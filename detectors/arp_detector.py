# -----------------------------------------------------------------------------
# File: arp_detector.py
# ARP Spoofing / Poisoning Detector
# Compatible with Windows + Scapy + Multiprocessing queues
# -----------------------------------------------------------------------------

import os
import time
from multiprocessing import Process
from scapy.all import Ether, ARP, wrpcap

class ArpSpoofDetector(object):
    def __init__(self, task_queue, stop_event,
                log_file="logs/arp_spoof.log",
                window_sec=10,
                max_changes=2,
                flood_threshold=25):
        super().__init__()
        self.daemon = True
        self.task_queue = task_queue
        self.stop_event = stop_event
        self.log_file = log_file

        # tracking
        self.arp_table = {}            # ip -> mac
        self.arp_conflicts = {}        # ip -> set(macs)
        self.arp_timestamps = []       # (ts, ip, mac)
        self.samples = []              # ARP packet samples for pcap

        # parameters
        self.WINDOW_SEC = window_sec
        self.MAX_CHANGES = max_changes       # how many mac changes for same IP allowed
        self.FLOOD_THRESHOLD = flood_threshold

        # folders
        os.makedirs("logs", exist_ok=True)
        os.makedirs("alerts", exist_ok=True)

    # -------------------------------------------------------------------------
    def _write_log(self, msg: str):
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except:
            pass

    # -------------------------------------------------------------------------
    def _alert(self, msg: str, pkt_list=None):
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = f"{ts_str} {msg}"
        print(line)
        self._write_log(line)

        # save sample pcap
        if pkt_list:
            try:
                pcap_path = os.path.join("alerts", f"arp_alert_{int(time.time())}.pcap")
                wrpcap(pcap_path, pkt_list)
            except:
                pass

    # -------------------------------------------------------------------------
    def _check_flood(self):
        """Detect ARP flood based on number of packets in the sliding window."""
        now = time.time()
        cutoff = now - self.WINDOW_SEC

        # remove old entries
        self.arp_timestamps = [(ts, ip, mac) for (ts, ip, mac) in self.arp_timestamps if ts >= cutoff]

        if len(self.arp_timestamps) >= self.FLOOD_THRESHOLD:
            self._alert(
                f"[ALERT] ARP-FLOOD Detected count={len(self.arp_timestamps)} "
                f"window={self.WINDOW_SEC}s priority=HIGH",
                pkt_list=self.samples[:10]
            )
            self.arp_timestamps.clear()
            self.samples.clear()

    # -------------------------------------------------------------------------
    def _check_conflict(self, ip, mac):
        """Detect ARP Poisoning: multiple MACs for one IP."""
        if ip not in self.arp_table:
            self.arp_table[ip] = mac
            self.arp_conflicts[ip] = {mac}
            return

        if mac != self.arp_table[ip]:
            # IP has multiple MACs → suspicious
            self.arp_conflicts[ip].add(mac)

            if len(self.arp_conflicts[ip]) >= self.MAX_CHANGES:
                self._alert(
                    f"[ALERT] ARP-SPOOFING / POISONING Detected "
                    f"IP={ip} old_mac={self.arp_table[ip]} new_mac={mac} "
                    f"conflicts={len(self.arp_conflicts[ip])} priority=HIGH",
                    pkt_list=self.samples[:10]
                )
                # update table and clear samples
                self.arp_table[ip] = mac
                self.arp_conflicts[ip] = {mac}
                self.samples.clear()
            else:
                # minor mismatch (suspicious but not alert level yet)
                pass

    # -------------------------------------------------------------------------
    def _check_gratuitous(self, arp_pkt):
        """Detect gratuitous ARP replies."""
        if arp_pkt.op == 2:  # ARP reply
            if arp_pkt.psrc == arp_pkt.pdst:
                # Gratuitous ARP → could be legit or attacker
                self._alert(
                    f"[ALERT] Suspicious Gratuitous ARP Detected "
                    f"IP={arp_pkt.psrc} MAC={arp_pkt.hwsrc} priority=MEDIUM",
                    pkt_list=self.samples[:10]
                )
                self.samples.clear()

    # -------------------------------------------------------------------------
    def run(self):
        print("[*] ArpSpoofDetector started.")
        try:
            while not self.stop_event.is_set():
                try:
                    pkt_bytes = self.task_queue.get(timeout=1)
                except:
                    continue

                try:
                    pkt = Ether(pkt_bytes)
                except:
                    continue

                if not pkt.haslayer(ARP):
                    continue

                arp = pkt[ARP]
                ip = arp.psrc
                mac = arp.hwsrc
                now = time.time()

                # Save samples for pcap
                if len(self.samples) < 20:
                    self.samples.append(pkt)

                # Track sliding window
                self.arp_timestamps.append((now, ip, mac))

                # Flood detection
                self._check_flood()

                # Conflict detection
                self._check_conflict(ip, mac)

                # Gratuitous ARP
                self._check_gratuitous(arp)

        except Exception as e:
            print(f"[ERROR] ArpSpoofDetector crashed: {e}")

        finally:
            print("[*] ArpSpoofDetector stopped.")
