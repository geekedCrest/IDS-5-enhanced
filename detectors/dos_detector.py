# -*- coding: utf-8 -*-
"""DoS/Scan Detector Module

Sliding-window detections for:
 - FLOOD any (SID 1000004)
 - SYN scan (1000001)
 - UDP flood (1000002)
 - ICMP flood (1000003)
 - Port scan (many distinct dst ports) (1000010)
 - Horizontal scan (many dst IPs) (1000012)
 - SYN-only distinct ports (1000013)
 - UDP distinct ports (1000014)

Enabled only when analyzer is launched with -dos / --dos flag.
"""
from collections import defaultdict, deque, Counter
from typing import Callable
import time
import ipaddress
from scapy.all import IP, TCP, UDP

class DosDetector:
    def __init__(self, emit_alert: Callable[[str,str,int,str,object], None], debug: bool=False, ack_warmup_until: float=0.0):
        self.emit_alert = emit_alert
        self.debug = debug
        self._ack_warmup_until = ack_warmup_until
        # State windows
        self._dos_windows = defaultdict(deque)          # (type, src, dst[, port]) -> deque ts
        self._port_scan_state = {}                      # src -> {'dq': deque((dst,port,ts)), 'by_dst': {dst: Counter}}
        self._syn_port_state = {}                       # src -> {'dq': deque, 'by_dst': {}}
        self._udp_port_state = {}                       # src -> {'dq': deque, 'by_dst': {}}
        self._hscan_state = {}                          # src -> {'dq': deque, 'counter': Counter}
        self._flag_windows = defaultdict(deque)         # (flagname, src) -> deque ts
        self._tcp_syn_seen = {}
        self._tcp_established = {}
        self._tcp_handshakes = {}
        self._tcp_state_ttl = {'handshake': 180.0, 'established': 600.0}
        # Thresholds (copied from previous analyzer config)
        self.cfg = {
            'syn': {'window': 5.0, 'threshold': 20},
            'udp': {'window': 5.0, 'threshold': 100},
            'icmp': {'window': 5.0, 'threshold': 20},
            'any': {'window': 10.0, 'threshold': 500},
            'port_scan': {'window': 30.0, 'threshold': 20},
            'syn_port_scan': {'window': 30.0, 'threshold': 8},
            'udp_port_scan': {'window': 30.0, 'threshold': 15},
            'hscan': {'window': 30.0, 'threshold': 10},
            'flags': {'window': 30.0, 'threshold': 15},
        }

    def _is_multicast_or_broadcast(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except Exception:
            return False
        if ip_str == '255.255.255.255':
            return True
        try:
            return ip in ipaddress.ip_network('224.0.0.0/4')
        except Exception:
            return False

    def process(self, pkt) -> None:
        if not pkt:
            return
        now = time.time()
        src = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "unknown"

        def add_ts(key: tuple, window_sec: float):
            dq = self._dos_windows.setdefault(key, deque())
            dq.append(now)
            cutoff = now - window_sec
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)

        # Any flood (ignore established TCP)
        any_cfg = self.cfg['any']
        is_established_tcp = False
        if pkt.haslayer(TCP):
            try:
                tcp = pkt[TCP]
                sport = int(tcp.sport)
                dport = int(tcp.dport)
                flow = (src, sport, dst, dport)
                is_established_tcp = flow in self._tcp_established
            except Exception:
                is_established_tcp = False
        if not is_established_tcp:
            cnt = add_ts(('any', src, dst), any_cfg['window'])
            if cnt >= any_cfg['threshold']:
                self.emit_alert(src, dst, 1000004, "FLOOD - high packet rate (any)", pkt)

        # TCP handshake & SYN scan
        if pkt.haslayer(TCP):
            try:
                tcp = pkt[TCP]
                flags = int(tcp.flags)
                syn = bool(flags & 0x02)
                ack = bool(flags & 0x10)
                rst = bool(flags & 0x04)
                fin = bool(flags & 0x01)
                psh = bool(flags & 0x08)
                sport = int(tcp.sport) if hasattr(tcp,'sport') else None
                dport = int(tcp.dport) if hasattr(tcp,'dport') else None

                flow = (src, sport, dst, dport)
                cutoff_flow = now - 120.0
                if self._tcp_syn_seen:
                    self._tcp_syn_seen = {k:t for k,t in self._tcp_syn_seen.items() if t >= cutoff_flow}
                if self._tcp_established:
                    self._tcp_established = {k:t for k,t in self._tcp_established.items() if t >= cutoff_flow}
                if self._tcp_handshakes:
                    new_hs = {}
                    for k, st in self._tcp_handshakes.items():
                        ttl = self._tcp_state_ttl['established'] if st.get('established') else self._tcp_state_ttl['handshake']
                        if st.get('last_seen',0) >= now - ttl:
                            new_hs[k] = st
                    self._tcp_handshakes = new_hs

                if sport is not None and dport is not None:
                    hs_key = (src, sport, dst, dport)
                    rev_hs_key = (dst, dport, src, sport)
                    if syn and not ack:
                        st = self._tcp_handshakes.get(hs_key, {'established': False})
                        st['syn'] = now
                        st['last_seen'] = now
                        self._tcp_handshakes[hs_key] = st
                        self._tcp_syn_seen[flow] = now
                    elif syn and ack:
                        st = self._tcp_handshakes.get(rev_hs_key)
                        if st and st.get('syn'):
                            st['synack'] = now
                            st['last_seen'] = now
                            self._tcp_handshakes[rev_hs_key] = st
                        self._tcp_established[(dst, dport, src, sport)] = now
                    elif ack and not syn:
                        has_payload = False
                        try:
                            has_payload = len(tcp.payload) > 0
                        except Exception:
                            has_payload = False
                        st = self._tcp_handshakes.get(hs_key)
                        if st and st.get('synack') and not st.get('established'):
                            st['ack'] = now
                            st['established'] = True
                            st['last_seen'] = now
                            self._tcp_handshakes[hs_key] = st
                            self._tcp_established[(src, sport, dst, dport)] = now
                            self._tcp_established[(dst, dport, src, sport)] = now
                        if has_payload or psh:
                            self._tcp_established[(src, sport, dst, dport)] = now
                    if rst or fin:
                        try:
                            if (src, sport, dst, dport) in self._tcp_established:
                                del self._tcp_established[(src, sport, dst, dport)]
                            if (dst, dport, src, sport) in self._tcp_established:
                                del self._tcp_established[(dst, dport, src, sport)]
                        except Exception:
                            pass

                # SYN-only scan
                if syn and not ack and not rst and not fin:
                    cfg = self.cfg['syn']
                    count = add_ts(('syn', src, dst), cfg['window'])
                    if self.debug:
                        try:
                            print(f"[DEBUG] SYN-only {src}->{dst} count={count}/{cfg['threshold']}")
                        except Exception:
                            pass
                    if count >= cfg['threshold']:
                        self.emit_alert(src, dst, 1000001, "SCAN - TCP SYN scan detected", pkt)

                # SYN port-scan (distinct ports per dst)
                sps = self.cfg.get('syn_port_scan')
                if sps and dport is not None and syn and not ack:
                    if src not in self._syn_port_state:
                        self._syn_port_state[src] = {'dq': deque(), 'by_dst': {}}
                    state = self._syn_port_state[src]
                    state['dq'].append((dst, dport, now))
                    state['by_dst'].setdefault(dst, Counter())
                    state['by_dst'][dst][dport] += 1
                    cut = now - sps['window']
                    while state['dq'] and state['dq'][0][2] < cut:
                        d, p, t = state['dq'].popleft()
                        state['by_dst'][d][p] -= 1
                        if state['by_dst'][d][p] <= 0:
                            del state['by_dst'][d][p]
                        if not state['by_dst'][d]:
                            del state['by_dst'][d]
                    if dst in state['by_dst'] and len(state['by_dst'][dst]) >= sps['threshold']:
                        self.emit_alert(src, dst, 1000013, "SCAN - SYN port scan detected (many SYN dst ports)", pkt)
            except Exception as e:
                print(f"[!] SYN scan detection error: {e}")

        # UDP flood + UDP port scan
        if pkt.haslayer(UDP):
            try:
                cfg = self.cfg['udp']
                try:
                    dport = int(pkt[UDP].dport)
                except Exception:
                    dport = None
                key = ('udp', src, dst, dport) if dport is not None else ('udp', src, dst)
                count = add_ts(key, cfg['window'])
                if count >= cfg['threshold']:
                    self.emit_alert(src, dst, 1000002, "DOS - UDP flood detected", pkt)
                ups = self.cfg.get('udp_port_scan')
                if ups and dport is not None:
                    if src not in self._udp_port_state:
                        self._udp_port_state[src] = {'dq': deque(), 'by_dst': {}}
                    st = self._udp_port_state[src]
                    st['dq'].append((dst, dport, now))
                    st['by_dst'].setdefault(dst, Counter())
                    st['by_dst'][dst][dport] += 1
                    cut = now - ups['window']
                    while st['dq'] and st['dq'][0][2] < cut:
                        d, p, t = st['dq'].popleft()
                        st['by_dst'][d][p] -= 1
                        if st['by_dst'][d][p] <= 0:
                            del st['by_dst'][d][p]
                        if not st['by_dst'][d]:
                            del st['by_dst'][d]
                    if dst in st['by_dst'] and len(st['by_dst'][dst]) >= ups['threshold']:
                        self.emit_alert(src, dst, 1000014, "SCAN - UDP port scan detected (many UDP dst ports)", pkt)
            except Exception:
                pass

        # ICMP flood
        if pkt.haslayer('ICMP') or pkt.haslayer('icmp'):
            try:
                cfg = self.cfg['icmp']
                count = add_ts(('icmp', src, dst), cfg['window'])
                if count >= cfg['threshold']:
                    self.emit_alert(src, dst, 1000003, "DOS - ICMP flood detected", pkt)
            except Exception:
                pass

        # Generic port-scan (many dst ports)
        try:
            dst_port = None
            if pkt.haslayer('TCP') or pkt.haslayer('tcp'):
                try: dst_port = int(pkt['TCP'].dport)
                except Exception: dst_port = None
            elif pkt.haslayer('UDP') or pkt.haslayer('udp'):
                try: dst_port = int(pkt['UDP'].dport)
                except Exception: dst_port = None
            if dst_port is not None:
                cfg_ps = self.cfg['port_scan']
                if src not in self._port_scan_state:
                    self._port_scan_state[src] = {'dq': deque(), 'by_dst': {}}
                state = self._port_scan_state[src]
                state['dq'].append((dst, dst_port, now))
                state['by_dst'].setdefault(dst, Counter())
                state['by_dst'][dst][dst_port] += 1
                cut = now - cfg_ps['window']
                while state['dq'] and state['dq'][0][2] < cut:
                    d, p, t = state['dq'].popleft()
                    state['by_dst'][d][p] -= 1
                    if state['by_dst'][d][p] <= 0:
                        del state['by_dst'][d][p]
                    if not state['by_dst'][d]:
                        del state['by_dst'][d]
                if dst in state['by_dst'] and len(state['by_dst'][dst]) >= cfg_ps['threshold']:
                    self.emit_alert(src, dst, 1000010, "SCAN - port scan detected (many dst ports)", pkt)
        except Exception:
            pass

        # Horizontal scan
        try:
            cfg_h = self.cfg['hscan']
            if src not in self._hscan_state:
                self._hscan_state[src] = {'dq': deque(), 'counter': Counter()}
            state = self._hscan_state[src]
            add_dst = False
            if not self._is_multicast_or_broadcast(dst):
                if pkt.haslayer(TCP):
                    try:
                        fl = int(pkt[TCP].flags)
                        syn = bool(fl & 0x02); ack = bool(fl & 0x10)
                    except Exception:
                        syn = False; ack = False
                    if syn and not ack and (dst not in state['counter']):
                        add_dst = True
                elif pkt.haslayer(UDP):
                    if dst not in state['counter']:
                        add_dst = True
            if add_dst:
                state['dq'].append((dst, now))
                state['counter'][dst] += 1
            cut = now - cfg_h['window']
            while state['dq'] and state['dq'][0][1] < cut:
                ipaddr, t = state['dq'].popleft()
                state['counter'][ipaddr] -= 1
                if state['counter'][ipaddr] <= 0:
                    del state['counter'][ipaddr]
            if len(state['counter']) >= cfg_h['threshold']:
                self.emit_alert(src, dst, 1000012, "SCAN - horizontal scan detected (many dst IPs)", pkt)
        except Exception:
            pass

        # Flag-based stealth scans (NULL/FIN/XMAS/ACK)
        if pkt.haslayer('TCP') or pkt.haslayer('tcp'):
            try:
                tcp = pkt['TCP']
                flags = int(tcp.flags)
                flagname = None
                if flags == 0: flagname = 'NULL'
                elif flags == 0x01: flagname = 'FIN'
                elif flags == 0x29: flagname = 'XMAS'
                elif flags == 0x10:
                    if time.time() >= self._ack_warmup_until:
                        try:
                            sport = int(tcp.sport)
                        except Exception:
                            sport = None
                        try:
                            dport = int(tcp.dport)
                        except Exception:
                            dport = None
                        flow = (src, sport, dst, dport)
                        if (sport is not None and dport is not None) and (flow not in self._tcp_established):
                            flagname = 'ACK'
                    else:
                        if self.debug:
                            print("[DEBUG] ACK-only suppressed during warmup window")
                if flagname:
                    cfg_f = self.cfg['flags']
                    key = (flagname, src)
                    dq = self._flag_windows.setdefault(key, deque())
                    dq.append(now)
                    cut = now - cfg_f['window']
                    while dq and dq[0] < cut:
                        dq.popleft()
                    if len(dq) >= cfg_f['threshold']:
                        self.emit_alert(src, dst, 1000011, f"SCAN - {flagname} flag scan detected", pkt)
            except Exception:
                pass
