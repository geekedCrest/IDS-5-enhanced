# -*- coding: utf-8 -*-
"""Brute Force Detector Module

Provides protocol-aware brute-force detection with deep packet inspection.
Enabled only when analyzer is launched with -brute / --brute flag.

Synthetic SIDs emitted:
  1000020 SSH authentication failures
  1000021 RDP authentication failures
  1000022 FTP login failures
  1000023 HTTP authentication failures
  1000024 SMTP authentication failures
  1000025 Multi-service credential stuffing
  +100  Username enumeration per protocol
  +200  Slow brute-force per protocol
"""
from collections import defaultdict, deque, Counter
from typing import Optional, Dict, Callable
import re
import time
from scapy.all import IP, TCP, Raw
import os

class BruteForceDetector:
    def __init__(self, emit_alert: Callable[[str,str,int,str,object], None], debug: bool = False):
        self.emit_alert = emit_alert  # callback to analyzer (src,dst,sid,msg,pkt)
        self.debug = debug
        # Configurable FTP ports (default: 21 and 2121). Override with env var IDS_FTP_PORTS e.g. "21,2121,2122"
        env_ports = os.getenv('IDS_FTP_PORTS')
        if env_ports:
            try:
                self.ftp_ports = {int(p.strip()) for p in env_ports.split(',') if p.strip()}
                print(f"[BRUTE-FORCE] Using custom FTP ports from environment: {self.ftp_ports}")
            except Exception:
                self.ftp_ports = {21, 2121}
        else:
            self.ftp_ports = {21, 2121}
        
        if self.debug:
            print(f"[BRUTE-FORCE] Initialized with FTP ports: {self.ftp_ports}")
            print(f"[BRUTE-FORCE] FTP threshold: {5} failures in {120}s window")
        # Per-protocol failure trackers: client_ip -> deque[timestamps]
        self._ssh = defaultdict(deque)
        self._rdp = defaultdict(deque)
        self._ftp = defaultdict(deque)
        self._http = defaultdict(deque)
        self._smtp = defaultdict(deque)
        # Multi-service: client_ip -> {service: deque[timestamps]}
        self._multi_service = {}
        # Username enumeration: (client_ip, service) -> {'usernames': set(), 'attempts': deque}
        self._enum = {}
        # Slow brute-force: client_ip -> {'first': ts, 'services': set(), 'total': int}
        self._slow = {}

        # Threshold config (mirrors previous analyzer inline config)
        self.cfg = {
            'ssh': {'window': 120.0, 'threshold': 5, 'sid': 1000020, 'severity': 'high'},
            'rdp': {'window': 120.0, 'threshold': 4, 'sid': 1000021, 'severity': 'critical'},
            'ftp': {'window': 120.0, 'threshold': 5, 'sid': 1000022, 'severity': 'medium'},
            'http': {'window': 180.0, 'threshold': 10, 'sid': 1000023, 'severity': 'medium'},
            'smtp': {'window': 120.0, 'threshold': 5, 'sid': 1000024, 'severity': 'high'},
            'multi': {'window': 300.0, 'threshold': 3, 'sid': 1000025},
            'enum': {'window': 300.0, 'threshold': 10},
            'slow': {'window': 3600.0, 'threshold': 30},
        }

    # ---------- Protocol-specific failure helpers ----------
    def _detect_ssh(self, payload: bytes) -> Optional[Dict[str,str]]:
        try:
            if len(payload) < 10:
                return None
            if b'\x33' in payload[:100]:
                m = re.search(b'[\x20-\x7e]{3,32}', payload[10:60])
                user = m.group(0).decode('ascii','ignore') if m else 'unknown'
                return {'username': user}
            if b'SSH-' in payload and (b'Protocol' in payload or b'mismatch' in payload):
                return {'username': 'protocol_negotiation'}
        except Exception:
            pass
        return None

    def _detect_rdp(self, payload: bytes) -> Optional[Dict[str,str]]:
        try:
            if len(payload) < 10:
                return None
            if payload[0] == 0x15 and len(payload) >= 7:
                alert_desc = payload[6] if len(payload) > 6 else 0
                if alert_desc in [40,49,42,45]:
                    return {'type':'tls_alert','alert_desc': str(alert_desc)}
            if b'\x30\x82' in payload[:20] and b'\x02\x01' in payload:
                if any(p in payload for p in [b'\x02\x01\x05', b'\x02\x01\x07', b'\x02\x01\x09']):
                    return {'type':'credssp_failure'}
            if payload[0:2]==b'\x03\x00' and len(payload)>=11 and b'\x0e\xd0' in payload[7:11]:
                return {'type':'rdp_protocol_error'}
        except Exception:
            pass
        return None

    def _detect_ftp(self, payload: bytes) -> Optional[Dict[str,str]]:
        try:
            s = payload.decode('ascii','ignore')
            if s.startswith('530'):
                um = re.search(r'530[- ].*?(\w+@?\w*)', s)
                user = um.group(1) if um else 'unknown'
                return {'username': user, 'code': '530'}
            if s.startswith('421'):
                return {'code': '421'}
            if len(s)>=3 and s[0]=='5':
                cm = re.match(r'^(\d{3})', s)
                if cm and int(cm.group(1)) in [500,501,502,503,504,530,532,550]:
                    return {'code': cm.group(1)}
        except Exception:
            pass
        return None

    def _detect_http(self, payload: bytes) -> Optional[Dict[str,str]]:
        try:
            s = payload.decode('utf-8','ignore')
            if 'HTTP/' in s and ' 401 ' in s:
                auth='unknown'
                am = re.search(r'WWW-Authenticate:\s*(\w+)', s, re.IGNORECASE)
                if am: auth = am.group(1).lower()
                pm = re.search(r'(GET|POST|PUT|DELETE)\s+([^\s]+)', s)
                path = pm.group(2) if pm else 'unknown'
                return {'code':'401','auth_method':auth,'path': path}
            if 'HTTP/' in s and ' 403 ' in s:
                pm = re.search(r'(GET|POST|PUT|DELETE)\s+([^\s]+)', s)
                path = pm.group(2) if pm else 'unknown'
                return {'code':'403','path': path}
            if 'HTTP/' in s and ' 200 ' in s:
                lower = payload.lower()
                for pat in [b'login failed', b'invalid credentials', b'authentication failed', b'incorrect password', b'username or password', b'login error']:
                    if pat in lower:
                        return {'code':'200','type':'login_failure_message'}
        except Exception:
            pass
        return None

    def _detect_smtp(self, payload: bytes) -> Optional[Dict[str,str]]:
        try:
            s = payload.decode('ascii','ignore')
            if s.startswith('535'):
                mm = re.search(r'(PLAIN|LOGIN|CRAM-MD5|DIGEST-MD5|NTLM)', s, re.IGNORECASE)
                mech = mm.group(1) if mm else 'unknown'
                return {'code':'535','mechanism': mech}
            if s.startswith('534'): return {'code':'534'}
            if s.startswith('538'): return {'code':'538'}
            if s.startswith('454'): return {'code':'454'}
        except Exception:
            pass
        return None

    # ---------- Public processing entry ----------
    def process(self, pkt, ts: float):
        if not pkt or not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        payload = bytes(pkt[Raw])
        if len(payload) < 5:
            return
        tcp = pkt[TCP]
        sport = int(tcp.sport)
        dport = int(tcp.dport)
        src = pkt[IP].src
        dst = pkt[IP].dst

        # Debug: show all TCP packets with payload on configured FTP ports
        if self.debug and (sport in self.ftp_ports or dport in self.ftp_ports):
            print(f"[BRUTE-DEBUG] FTP packet: {src}:{sport} -> {dst}:{dport}, payload_len={len(payload)}")
            print(f"[BRUTE-DEBUG] Payload preview: {payload[:100]!r}")
            try:
                payload_str = payload.decode('ascii', 'ignore')
                print(f"[BRUTE-DEBUG] Payload decoded: {payload_str[:100]!r}")
            except:
                pass

        failure = None
        protocol = None
        username = None

        if dport == 22 or sport == 22:
            failure = self._detect_ssh(payload)
            if failure:
                protocol = 'ssh'
                username = failure.get('username')
                client = src if dport == 22 else dst
                server = dst if dport == 22 else src
                self._track(client, server, protocol, ts, pkt, username)
        elif dport == 3389 or sport == 3389:
            failure = self._detect_rdp(payload)
            if failure:
                protocol = 'rdp'
                client = src if dport == 3389 else dst
                server = dst if dport == 3389 else src
                self._track(client, server, protocol, ts, pkt, None)
        elif sport in self.ftp_ports or dport in self.ftp_ports:  # FTP (standard and configured ports)
            failure = self._detect_ftp(payload)
            if self.debug:
                print(f"[BRUTE-DEBUG] FTP check: sport={sport}, dport={dport}, failure={failure}")
            if failure:
                protocol = 'ftp'
                username = failure.get('username')
                # FTP responses come FROM server (sport), requests TO server (dport)
                # Detect by response codes, so we look at sport primarily
                if sport in self.ftp_ports:
                    client = dst
                    server = src
                else:
                    client = src
                    server = dst
                if self.debug:
                    print(f"[BRUTE-DEBUG] FTP failure detected! client={client}, server={server}")
                self._track(client, server, protocol, ts, pkt, username)
        elif sport in [80,443,8080,8443] or dport in [80,443,8080,8443]:
            failure = self._detect_http(payload)
            if failure:
                protocol = 'http'
                client = dst if sport in [80,443,8080,8443] else src
                server = src if sport in [80,443,8080,8443] else dst
                self._track(client, server, protocol, ts, pkt, None)
        elif sport in [25,587,465] or dport in [25,587,465]:
            failure = self._detect_smtp(payload)
            if failure:
                protocol = 'smtp'
                client = dst if sport in [25,587,465] else src
                server = src if sport in [25,587,465] else dst
                self._track(client, server, protocol, ts, pkt, None)

    def _track(self, client_ip: str, server_ip: str, protocol: str, ts: float, pkt, username: Optional[str]):
        mmap = {
            'ssh': (self._ssh, self.cfg['ssh'], "SSH authentication failures"),
            'rdp': (self._rdp, self.cfg['rdp'], "RDP authentication failures (CRITICAL)"),
            'ftp': (self._ftp, self.cfg['ftp'], "FTP login failures"),
            'http': (self._http, self.cfg['http'], "HTTP authentication failures"),
            'smtp': (self._smtp, self.cfg['smtp'], "SMTP authentication failures"),
        }
        if protocol not in mmap:
            return
        deq_map, cfg, human = mmap[protocol]
        dq = deq_map[client_ip]
        dq.append(ts)
        cutoff = ts - cfg['window']
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= cfg['threshold']:
            msg = f"BRUTEFORCE - {human} [Severity: {cfg['severity'].upper()}] - {len(dq)} failures in {cfg['window']}s"
            self.emit_alert(client_ip, server_ip, cfg['sid'], msg, pkt)

        # Username enumeration
        if username and username != 'unknown':
            key = (client_ip, protocol)
            if key not in self._enum:
                self._enum[key] = {'usernames': set(), 'attempts': deque()}
            data = self._enum[key]
            data['usernames'].add(username)
            data['attempts'].append(ts)
            e_cfg = self.cfg['enum']
            e_cut = ts - e_cfg['window']
            while data['attempts'] and data['attempts'][0] < e_cut:
                data['attempts'].popleft()
            if len(data['usernames']) >= e_cfg['threshold']:
                msg = f"BRUTEFORCE - Username enumeration detected on {protocol.upper()} ({len(data['usernames'])} usernames attempted)"
                self.emit_alert(client_ip, server_ip, mmap[protocol][1]['sid'] + 100, msg, pkt)
                data['usernames'].clear()

        # Multi-service credential stuffing
        if client_ip not in self._multi_service:
            self._multi_service[client_ip] = {}
        svc_map = self._multi_service[client_ip]
        if protocol not in svc_map:
            svc_map[protocol] = deque()
        svc_map[protocol].append(ts)
        m_cfg = self.cfg['multi']
        m_cut = ts - m_cfg['window']
        for svc in list(svc_map.keys()):
            q = svc_map[svc]
            while q and q[0] < m_cut:
                q.popleft()
        active = [svc for svc, q in svc_map.items() if q]
        if len(active) >= m_cfg['threshold']:
            msg = f"BRUTEFORCE - Multi-service credential stuffing detected (targeting {', '.join(active)})"
            self.emit_alert(client_ip, server_ip, m_cfg['sid'], msg, pkt)

        # Slow brute-force
        if client_ip not in self._slow:
            self._slow[client_ip] = {'first': None, 'services': set(), 'total': 0}
        slow = self._slow[client_ip]
        if slow['first'] is None:
            slow['first'] = ts
        slow['services'].add(protocol)
        slow['total'] += 1
        s_cfg = self.cfg['slow']
        span = ts - slow['first']
        if span >= s_cfg['window'] and slow['total'] >= s_cfg['threshold']:
            msg = f"BRUTEFORCE - Slow brute-force attack detected ({slow['total']} attempts over {span/60:.1f} minutes)"
            self.emit_alert(client_ip, server_ip, mmap[protocol][1]['sid'] + 200, msg, pkt)
            slow['first'] = ts
            slow['total'] = 0
