# synscan_detector.py
# -*- coding: utf-8 -*-
#! /usr/bin/env python3

"""
SynScanDetector - process that detects SYN-only stealth scans (nmap -sS)
Outputs:
- debug prints for each SYN seen with a running port-count
- custom [ALERT] lines when threshold exceeded
- writes alerts to logs/synscan.log
- saves small sample pcap in alerts/ when available
"""

import os
import time
from collections import defaultdict, deque
from multiprocessing import Process
from typing import Deque, Dict, Set, Tuple, List
from scapy.all import Ether, IP, TCP, wrpcap

# Top-level helper factories so they are picklable on Windows
def _default_set():
    return set()

def _default_dd_set():
    # returns defaultdict(set)
    return defaultdict(_default_set)

class SynScanDetector(object):
    def __init__(self, task_queue, stop_event, log_file: str = "logs/synscan.log"):
        super().__init__()
        self.daemon = True
        self.task_queue = task_queue
        self.stop_event = stop_event
        self.log_file = log_file

        # ports_by_src_dst[src][dst] -> set(dports)
        # use top-level factory to remain picklable on Windows
        self.ports_by_src_dst: Dict[str, Dict[str, Set[int]]] = defaultdict(_default_dd_set)

        # timestamps per src -> deque of (timestamp, dst, dport) for sliding-window checks
        self.ports_timestamps: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(deque)

        # small packet samples buffered per src to save pcap on alert
        self.sample_pkts_by_src: Dict[str, List] = defaultdict(list)

        # last alert time to implement cooldown per (src, dst) or src-distributed
        self.last_alert_time: Dict[Tuple[str, str], float] = {}

        # Tunable parameters (adjust as needed)
        self.WINDOW_SEC = 10                   # sliding window seconds
        self.PORTS_THRESHOLD = 5               # distinct dst ports to same dst => alert
        self.UNIQUE_COMBOS_THRESHOLD = 12      # distinct (dst,port) combos => distributed scan
        self.COOLDOWN_SEC = 30                 # cooldown before re-alerting same src/dst
        self.SAMPLE_PCAP_COUNT = 8             # saved sample packets per src for pcap

        # Ensure log directories exist
        log_dir = os.path.dirname(self.log_file) or "."
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception:
            pass
        try:
            os.makedirs("alerts", exist_ok=True)
        except Exception:
            pass

    def _write_log(self, msg: str):
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception as e:
            print(f"[!] Failed to write synscan log: {e}")

    def _save_sample_pcap(self, src: str, scan_type: str):
        pkts = self.sample_pkts_by_src.get(src, [])
        if not pkts:
            return
        try:
            pcap_path = os.path.join("alerts", f"synscan_{scan_type}_{int(time.time())}.pcap")
            # wrpcap expects scapy packets; we stored packets themselves
            wrpcap(pcap_path, pkts)
        except Exception as e:
            print(f"[!] Failed to save synscan pcap: {e}")


    def _emit_alert(self, src: str, dst: str, scan_type: str, count: int, ts: float):
        """
        Emit alert exactly as requested:
        [ALERT] SYN-SCAN Detected (custom detector) src=SRC -> DST ports=COUNT window=XXs priority=HIGH type=TYPE
        """
        priority = "HIGH"
        msg = (
            f"[ALERT] SYN-SCAN Detected (custom detector) "
            f"src={src} -> {dst} ports={count} window={self.WINDOW_SEC}s "
            f"priority={priority} type={scan_type}"
        )

        # اطبع التنبيه على الكونسول
        print(msg)

        # اكتب التنبيه في ملف السجل مع طابع زمني
        try:
            ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"{ts_str} {msg}\n")
        except Exception as e:
            print(f"[!] Failed to write synscan log: {e}")

        # احفظ عينة pcap صغيرة (اختياري)
        try:
            from scapy.all import wrpcap
            pkts = self.sample_pkts_by_src.get(src, [])
            if pkts:
                pcap_path = os.path.join("alerts", f"synscan_{scan_type}_{int(time.time())}.pcap")
                wrpcap(pcap_path, pkts)
        except Exception as e:
            print(f"[!] Failed to save synscan pcap: {e}")



    
    def run(self):
        print("[*] SynScanDetector started.")
        try:
            while not self.stop_event.is_set():
                try:
                    pkt_bytes = self.task_queue.get(timeout=1)
                except Exception:
                    # timeout or queue closed or interrupted; check stop_event again
                    continue

                try:
                    pkt = Ether(pkt_bytes)
                except Exception:
                    # unparsable packet bytes
                    continue

                # require IP + TCP
                if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                    continue

                ip_layer = pkt[IP]
                tcp_layer = pkt[TCP]
                flags = int(tcp_layer.flags)
                src = ip_layer.src
                dst = ip_layer.dst
                try:
                    dport = int(tcp_layer.dport)
                except Exception:
                    dport = None

                # detect SYN-only (SYN set, ACK not set)
                is_syn_only = (flags & 0x02) and not (flags & 0x10)
                if not is_syn_only:
                    continue

                now = time.time()

                # buffer sample packet for potential pcap (limit size)
                samples = self.sample_pkts_by_src[src]
                if len(samples) < self.SAMPLE_PCAP_COUNT:
                    try:
                        samples.append(pkt)  # store scapy packet object
                    except Exception:
                        pass

                # record port and timestamp
                if dport is not None:
                    # add to per-src->dst set for distinct port counting
                    self.ports_by_src_dst[src][dst].add(dport)
                    # append to timestamp deque for src
                    self.ports_timestamps[src].append((now, dst, dport))

                    # trim old events for this src (global window)
                    cutoff = now - self.WINDOW_SEC
                    dq = self.ports_timestamps[src]
                    while dq and dq[0][0] < cutoff:
                        dq.popleft()
                    # compute distinct combos in current window for distributed detection
                    unique_combos = set((dst2, port2) for _, dst2, port2 in dq)

                    # compute ports_count for this src->dst in current window
                    ports_set = self.ports_by_src_dst[src][dst]
                    # It's possible ports_set contains ports older than window; compute current distinct ports from dq
                    current_ports = {port2 for _, dst2, port2 in dq if dst2 == dst}
                    ports_count = len(current_ports)

                    # Debug printing - show running potential count
                    potential_count = ports_count
                    # print(f"[DEBUG] SYN seen: {src} -> {dst}:{dport} (ports_count~{potential_count})")

                    # Per-target detection
                    if ports_count >= self.PORTS_THRESHOLD:
                        last = self.last_alert_time.get((src, dst), 0)
                        if now - last > self.COOLDOWN_SEC:
                            self._emit_alert(src, dst, "syn_scan_per_target", ports_count, now)
                            # clear state for this src->dst to avoid immediate re-alerting
                            self.ports_by_src_dst[src][dst].clear()
                            self.ports_timestamps[src].clear()
                            self.sample_pkts_by_src[src].clear()
                            self.last_alert_time[(src, dst)] = now
                            continue

                    # Distributed detection across many targets/ports
                    if len(unique_combos) >= self.UNIQUE_COMBOS_THRESHOLD:
                        last = self.last_alert_time.get((src, "distributed"), 0)
                        if now - last > self.COOLDOWN_SEC:
                            self._emit_alert(src, "multiple_targets", "syn_scan_distributed", len(unique_combos), now)
                            # reset tracking for this src
                            self.ports_by_src_dst[src].clear()
                            self.ports_timestamps[src].clear()
                            self.sample_pkts_by_src[src].clear()
                            self.last_alert_time[(src, "distributed")] = now
                            continue

        except KeyboardInterrupt:
            # Graceful stop if user interrupts process directly
            pass
        except Exception as e:
            print(f"[ERROR] SynScanDetector encountered unexpected error: {e}")
        finally:
            print("[*] SynScanDetector stopped.")
