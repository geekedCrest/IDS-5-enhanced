# -*- coding: utf-8 -*-
import random
import time
import json
import os
import sys
import subprocess
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory, send_file
from flask_socketio import SocketIO, emit
import netifaces
from rules import load_rules, verify_rules
from signature import Signature
from classifier import (get_model, get_feature_info, get_model_metadata, predict_single,
                        feature_info_from_csv, generate_security_report, predict_batch,
                        dataset_report_from_csv)
from detector_manager import DetectorManager
from flow_features import FlowTracker

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-dashboard-secret'
# set logger to False to prevent console flooding
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading', logger=False, engineio_logger=False)

# ─── Capture mode ─────────────────────────────────────────────────────────────
# LIVE_CAPTURE=1 → use scapy to capture real packets from the chosen network
#                  interface. Requires root/sudo and a real NIC. Real alerts.
# LIVE_CAPTURE unset → simulation mode. No real packets, no real alerts
#                      (the dashboard still works as a visual demo).
LIVE_CAPTURE = os.environ.get('LIVE_CAPTURE', '').lower() in ('1', 'true', 'yes', 'on')

# ─── State ────────────────────────────────────────────────────────────────────

state = {
    'running': False,
    'paused': False,
    'packet_count': 0,
    'alert_count': 0,
    'filtered_count': 0,
    'interface': 'eth0',
    'start_time': None,
    'rules': [],
    'packets': [],
    'alerts': [],
    'protocol_stats': {
        'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0,
        'HTTP': 0, 'DNS': 0, 'TLS': 0, 'SSH': 0, 'FTP': 0, 'SMTP': 0,
        'OTHER': 0,
    },
    'traffic_history': [],
    'active_filter': '',
    'selected_rules_file': 'default.rules',
    'live_capture_mode': LIVE_CAPTURE,
    'total_bytes': 0,
    'threat_stats': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
    # When a .pcap is opened we freeze the background simulation so the loaded
    # packets stay pristine. Start/Restart clears this and resumes live traffic.
    'file_mode': False,
    # Dataset-composition report for the Statistics panel; set when a CSV is
    # uploaded so the panel reflects the user's file instead of the static default.
    'dataset_report': None,
}

# Reassembles packets into bidirectional flows and computes CICFlowMeter features so
# the ML classifier can analyse the real dashboard traffic (live / simulated / pcap).
flow_tracker = FlowTracker()

# Synthetic alerts are off by default in simulation mode (they're fake).
SIMULATE_ALERTS = False

PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS', 'ARP', 'TLS', 'SSH', 'FTP', 'SMTP']
THREAT_LEVELS = ['LOW', 'LOW', 'LOW', 'LOW', 'MEDIUM', 'MEDIUM', 'HIGH', 'CRITICAL']

SAMPLE_IPS = [
    '192.168.0.1', '192.168.0.2', '192.168.0.3', '192.168.178.22',
    '10.0.0.1', '10.0.0.5', '172.16.0.1', '1.1.1.1', '8.8.8.8',
    '127.0.0.1', '0.0.0.0', '255.255.255.255', '192.0.0.1',
    '185.220.101.5', '45.33.32.156', '198.51.100.1', '203.0.113.50',
]

COMMON_PORTS = [80, 443, 22, 21, 25, 53, 8080, 8443, 3306, 5432,
                1234, 12345, 501, 8000, 65535, 1235]

ATTACK_TYPES = ['Port Scan', 'DoS Attack', 'Brute Force', 'SQL Injection',
                'XSS Attempt', 'ARP Spoofing', 'DNS Poisoning', 'MITM']

INFO_TEMPLATES = {
    'TCP': ['SYN', 'ACK', 'FIN', 'RST', 'PSH,ACK', 'SYN,ACK', 'Seq={seq} Ack={ack} Win={win}'],
    'UDP': ['Src Port: {sport} Dst Port: {dport}', 'DNS Standard query', 'DHCP Discover'],
    'ICMP': ['Echo (ping) request  id={id}, seq={seq}', 'Echo (ping) reply id={id}, seq={seq}', 'Destination unreachable'],
    'HTTP': ['GET / HTTP/1.1', 'POST /api/data HTTP/1.1', 'HTTP/1.1 200 OK', 'HTTP/1.1 404 Not Found'],
    'DNS': ['Standard query 0x{id:04x} A {domain}', 'Standard query response A {ip}'],
    'ARP': ['Who has {ip}? Tell {src}', 'Reply {ip} is-at {mac}'],
    'TLS': ['Client Hello', 'Server Hello', 'Application Data', 'Certificate'],
    'SSH': ['Client: Protocol exchange', 'Server: Key Exchange Init', 'New Keys'],
    'FTP': ['Request: USER anonymous', 'Response: 220 FTP server ready', 'Request: RETR file.txt'],
    'SMTP': ['EHLO mail.example.com', 'MAIL FROM:<sender@example.com>', 'DATA'],
}

DOMAINS = ['google.com', 'example.com', 'cloudflare.com', 'github.com',
           'evil-domain.ru', 'malware-c2.net', 'suspicious-host.xyz']
MACS = ['aa:bb:cc:dd:ee:ff', '00:11:22:33:44:55', 'de:ad:be:ef:00:01']

# ─── Load rules ────────────────────────────────────────────────────────────────

def load_ids_rules(path='default.rules'):
    try:
        rules = load_rules(path)
        state['rules'] = [str(r) for r in rules]
        return rules
    except ValueError as e:
        print(f'[WARN] Could not load rules from {path}: {e}')
        return []

ids_rules = load_ids_rules('default.rules')

# ─── Detector Manager & Simulated to Scapy conversion ─────────────────────────

def handle_detector_alert(detector_name, alert_dict):
    alert = {
        'id': state['alert_count'] + 1,
        'ts': datetime.now().strftime('%H:%M:%S.%f')[:-3],
        'type': alert_dict['msg'].split(' - ')[0] if ' - ' in alert_dict['msg'] else detector_name,
        'threat': alert_dict['threat'],
        'src': alert_dict['src_ip'],
        'dst': alert_dict['dst_ip'],
        'rule': f"[{detector_name}] {alert_dict['msg']}",
        'info': alert_dict['msg'],
        'proto': 'IP',
    }
    state['alert_count'] += 1
    state['alerts'].append(alert)
    if len(state['alerts']) > 500:
        state['alerts'] = state['alerts'][-500:]
        
    if state['running'] and not state['paused']:
        socketio.emit('alert', alert)

detector_manager = DetectorManager(
    detectors_dir=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'detectors'),
    alert_callback=handle_detector_alert
)
detector_manager.start_all_enabled()

def simulated_to_scapy(pkt_dict):
    try:
        from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, Raw, DNS, DNSQR
        
        p = Ether()
        proto = pkt_dict.get('proto', 'TCP')
        src_ip = pkt_dict.get('src_ip', '192.168.0.1')
        dst_ip = pkt_dict.get('dst_ip', '192.168.0.2')
        
        if proto == 'ARP':
            p = p / ARP(psrc=src_ip, pdst=dst_ip, op=1)
        else:
            p = p / IP(src=src_ip, dst=dst_ip)
            sport = pkt_dict.get('src_port', 12345)
            dport = pkt_dict.get('dst_port', 80)
            info = pkt_dict.get('info', '')
            
            if proto in ('TCP', 'HTTP', 'TLS', 'SSH', 'FTP', 'SMTP'):
                p = p / TCP(sport=sport, dport=dport, flags="S")
                if proto in ('HTTP', 'FTP', 'SMTP', 'SSH', 'TLS'):
                    p = p / Raw(load=info.encode('utf-8', errors='ignore'))
            elif proto in ('UDP', 'DNS'):
                p = p / UDP(sport=sport, dport=dport)
                if proto == 'DNS':
                    p = p / DNS(rd=1, qd=DNSQR(qname="evil-domain.ru"))
            elif proto == 'ICMP':
                p = p / ICMP()
        return p
    except Exception as e:
        print(f"[WARN] Error converting simulated packet to Scapy: {e}")
        return None


# ─── Rule matching helpers ─────────────────────────────────────────────────────

def _ip_match(rule_ip, actual_ip):
    if rule_ip == 'any':
        return True
    if rule_ip.startswith('!'):
        return rule_ip[1:] != actual_ip
    return rule_ip == actual_ip


def _port_match(rule_port, actual_port):
    if rule_port == 'any':
        return True
    actual = str(actual_port)
    rp = rule_port
    negate = False
    if rp.startswith('!'):
        negate = True
        rp = rp[1:]
    if rp.startswith('[') and rp.endswith(']'):
        try:
            lo, hi = rp[1:-1].split('-')
            in_range = int(lo) <= int(actual) <= int(hi)
            return not in_range if negate else in_range
        except (ValueError, IndexError):
            return False
    matches = (rp == actual)
    return not matches if negate else matches


def _proto_match(rule_proto, actual_proto):
    if rule_proto in ('any', 'IP'):
        return True
    return rule_proto == actual_proto


def _packet_matches_rule(rule, src_ip, dst_ip, proto, src_port, dst_port):
    """Strict rule match: proto + both IPs + both ports must all match."""
    if not _proto_match(rule.proto, proto):
        return False
    if not _ip_match(rule.src_ip, src_ip):
        return False
    if not _ip_match(rule.dst_ip, dst_ip):
        return False
    if not _port_match(rule.src_port, src_port):
        return False
    if not _port_match(rule.dst_port, dst_port):
        return False
    return True


# ─── Packet simulation ─────────────────────────────────────────────────────────

def _fmt_info(proto):
    tpl = random.choice(INFO_TEMPLATES.get(proto, ['Data transfer']))
    return tpl.format(
        seq=random.randint(1000, 9999999),
        ack=random.randint(1000, 9999999),
        win=random.choice([65535, 8192, 29200, 1024]),
        sport=random.choice(COMMON_PORTS),
        dport=random.choice(COMMON_PORTS),
        id=random.randint(0, 0xFFFF),
        ip=random.choice(SAMPLE_IPS),
        src=random.choice(SAMPLE_IPS),
        mac=random.choice(MACS),
        domain=random.choice(DOMAINS),
    )

def _generate_packet():
    proto = random.choices(
        PROTOCOLS,
        weights=[30, 20, 10, 15, 10, 3, 5, 3, 2, 2]
    )[0]

    src_ip = random.choice(SAMPLE_IPS)
    dst_ip = random.choice(SAMPLE_IPS)
    src_port = random.choice(COMMON_PORTS)
    dst_port = random.choice(COMMON_PORTS)

    length = random.randint(40, 1500)
    state['packet_count'] += 1
    pkt_id = state['packet_count']
    ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]

    # Check against rules — strict match on proto + IPs + ports.
    # Skipped entirely when SIMULATE_ALERTS is False so the dashboard
    # never produces synthetic intrusion alerts on simulated traffic.
    is_alert = False
    matched_rule = None
    if SIMULATE_ALERTS:
        for rule in ids_rules:
            if _packet_matches_rule(rule, src_ip, dst_ip, proto, src_port, dst_port):
                is_alert = True
                matched_rule = str(rule)
                break

    threat = 'CRITICAL' if is_alert else random.choices(
        ['LOW', 'LOW', 'LOW', 'MEDIUM', 'HIGH'],
        weights=[60, 10, 10, 15, 5]
    )[0]

    hex_bytes = ' '.join(f'{random.randint(0,255):02x}' for _ in range(min(length, 64)))
    hex_lines = []
    raw = bytes(random.randint(0, 255) for _ in range(min(length, 64)))
    for i in range(0, len(raw), 16):
        chunk = raw[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk).ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        hex_lines.append({'offset': f'{i:04x}', 'hex': hex_part, 'ascii': ascii_part})

    layers = _build_layers(proto, src_ip, dst_ip, str(src_port), str(dst_port), length)

    pkt = {
        'id': pkt_id,
        'ts': ts,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'proto': proto,
        'length': length,
        'info': _fmt_info(proto),
        'threat': threat,
        'is_alert': is_alert,
        'matched_rule': matched_rule,
        'hex': hex_lines,
        'layers': layers,
        'src_port': src_port,
        'dst_port': dst_port,
    }

    # Update protocol stats + byte / threat tracking
    proto_key = proto if proto in state['protocol_stats'] else 'OTHER'
    state['protocol_stats'][proto_key] = state['protocol_stats'].get(proto_key, 0) + 1
    state['total_bytes'] += length
    state['threat_stats'][threat] = state['threat_stats'].get(threat, 0) + 1

    return pkt

def _build_layers(proto, src_ip, dst_ip, src_port, dst_port, length):
    layers = [
        {
            'name': f'Frame {state["packet_count"]}: {length} bytes on wire',
            'fields': [
                {'key': 'Encapsulation type', 'value': 'Ethernet (1)'},
                {'key': 'Frame Length', 'value': f'{length} bytes'},
                {'key': 'Capture Length', 'value': f'{length} bytes'},
            ],
        },
        {
            'name': f'Ethernet II, Src: {random.choice(MACS)}, Dst: {random.choice(MACS)}',
            'fields': [
                {'key': 'Destination', 'value': random.choice(MACS)},
                {'key': 'Source', 'value': random.choice(MACS)},
                {'key': 'Type', 'value': '0x0800 (IPv4)' if proto != 'ARP' else '0x0806 (ARP)'},
            ],
        },
        {
            'name': f'Internet Protocol Version 4, Src: {src_ip}, Dst: {dst_ip}',
            'fields': [
                {'key': 'Version', 'value': '4'},
                {'key': 'Header Length', 'value': '20 bytes'},
                {'key': 'Total Length', 'value': str(length)},
                {'key': 'TTL', 'value': str(random.choice([64, 128, 255]))},
                {'key': 'Source Address', 'value': src_ip},
                {'key': 'Destination Address', 'value': dst_ip},
            ],
        },
    ]

    if proto in ('TCP', 'HTTP', 'TLS', 'SSH', 'FTP', 'SMTP'):
        layers.append({
            'name': f'Transmission Control Protocol, Src Port: {src_port}, Dst Port: {dst_port}',
            'fields': [
                {'key': 'Source Port', 'value': src_port},
                {'key': 'Destination Port', 'value': dst_port},
                {'key': 'Sequence Number', 'value': str(random.randint(0, 4294967295))},
                {'key': 'Acknowledgment Number', 'value': str(random.randint(0, 4294967295))},
                {'key': 'Flags', 'value': random.choice(['0x002 (SYN)', '0x010 (ACK)', '0x018 (PSH,ACK)', '0x001 (FIN)'])},
                {'key': 'Window Size', 'value': str(random.choice([65535, 8192, 29200]))},
            ],
        })
    elif proto in ('UDP', 'DNS'):
        layers.append({
            'name': f'User Datagram Protocol, Src Port: {src_port}, Dst Port: {dst_port}',
            'fields': [
                {'key': 'Source Port', 'value': src_port},
                {'key': 'Destination Port', 'value': dst_port},
                {'key': 'Length', 'value': str(length - 20)},
                {'key': 'Checksum', 'value': f'0x{random.randint(0, 0xFFFF):04x}'},
            ],
        })
    elif proto == 'ICMP':
        layers.append({
            'name': 'Internet Control Message Protocol',
            'fields': [
                {'key': 'Type', 'value': random.choice(['8 (Echo request)', '0 (Echo reply)', '3 (Destination unreachable)'])},
                {'key': 'Code', 'value': '0'},
                {'key': 'Checksum', 'value': f'0x{random.randint(0, 0xFFFF):04x}'},
                {'key': 'Identifier', 'value': str(random.randint(1, 65535))},
                {'key': 'Sequence Number', 'value': str(random.randint(1, 1000))},
            ],
        })

    if proto in ('HTTP',):
        layers.append({
            'name': 'Hypertext Transfer Protocol',
            'fields': [
                {'key': 'Method', 'value': random.choice(['GET', 'POST', 'PUT', 'DELETE'])},
                {'key': 'URI', 'value': random.choice(['/', '/api/data', '/login', '/admin'])},
                {'key': 'Host', 'value': random.choice(DOMAINS)},
                {'key': 'User-Agent', 'value': 'Mozilla/5.0 (compatible; Scanner/1.0)'},
            ],
        })

    return layers


def _check_for_attacks(packets_window):
    """Detect simple attack patterns in a window of recent packets."""
    alerts = []
    src_count = {}
    dst_count = {}
    dst_port_count = {}

    for p in packets_window:
        src = p['src_ip']
        dst = p['dst_ip']
        dport = p.get('dst_port', 0)
        src_count[src] = src_count.get(src, 0) + 1
        dst_count[dst] = dst_count.get(dst, 0) + 1
        key = f'{src}->{dst}'
        dst_port_count[key] = dst_port_count.get(key, 0) + 1

    # DoS only triggers when one source dominates the recent window
    # (>60% of last 100 packets) — avoids false positives from uniform
    # random traffic across a small IP pool.
    total = len(packets_window) or 1
    threshold = max(60, int(total * 0.6))
    for src, cnt in src_count.items():
        if cnt > threshold:
            alerts.append({
                'type': 'DoS Attack',
                'threat': 'CRITICAL',
                'src': src,
                'dst': 'multiple',
                'ts': datetime.now().strftime('%H:%M:%S'),
                'detail': f'{cnt}/{total} packets from {src} in last window',
            })
    return alerts


# ─── Live packet capture (scapy) ───────────────────────────────────────────────

def _scapy_proto(spkt):
    """Identify high-level protocol + ports from a scapy packet."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP
    sport = dport = None
    if spkt.haslayer(ARP):
        return 'ARP', None, None
    if spkt.haslayer(TCP):
        sport, dport = spkt[TCP].sport, spkt[TCP].dport
        for p in (dport, sport):
            if p == 80: return 'HTTP', sport, dport
            if p == 443: return 'TLS', sport, dport
            if p == 22: return 'SSH', sport, dport
            if p in (20, 21): return 'FTP', sport, dport
            if p in (25, 587): return 'SMTP', sport, dport
        return 'TCP', sport, dport
    if spkt.haslayer(UDP):
        sport, dport = spkt[UDP].sport, spkt[UDP].dport
        if 53 in (sport, dport): return 'DNS', sport, dport
        return 'UDP', sport, dport
    if spkt.haslayer(ICMP):
        return 'ICMP', None, None
    return 'OTHER', None, None


def _scapy_to_packet(spkt):
    """Convert a scapy packet into the dashboard's packet dict."""
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP
    from scapy.packet import NoPayload

    state['packet_count'] += 1
    pkt_id = state['packet_count']
    ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    length = len(spkt)
    proto, sport, dport = _scapy_proto(spkt)

    src_ip = dst_ip = ''
    if spkt.haslayer(IP):
        src_ip, dst_ip = spkt[IP].src, spkt[IP].dst
    elif spkt.haslayer(IPv6):
        src_ip, dst_ip = spkt[IPv6].src, spkt[IPv6].dst
    elif spkt.haslayer(ARP):
        src_ip, dst_ip = spkt[ARP].psrc, spkt[ARP].pdst

    # Real rule matching against captured traffic
    is_alert = False
    matched_rule = None
    sp = str(sport) if sport is not None else 'any'
    dp = str(dport) if dport is not None else 'any'
    for rule in ids_rules:
        if _packet_matches_rule(rule, src_ip, dst_ip, proto, sp, dp):
            is_alert = True
            matched_rule = str(rule)
            break

    threat = 'CRITICAL' if is_alert else 'LOW'

    # Hex view (cap at 256 bytes for the panel)
    raw = bytes(spkt)[:256]
    hex_lines = []
    for i in range(0, len(raw), 16):
        chunk = raw[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk).ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        hex_lines.append({'offset': f'{i:04x}', 'hex': hex_part, 'ascii': ascii_part})

    # Walk scapy layer chain → dashboard layer tree
    layers = []
    cur = spkt
    while cur is not None and not isinstance(cur, NoPayload):
        fields = []
        for f in cur.fields_desc:
            try:
                val = cur.getfieldval(f.name)
                fields.append({'key': f.name, 'value': str(val)[:200]})
            except Exception:
                pass
        layers.append({'name': cur.name, 'fields': fields})
        cur = cur.payload

    return {
        'id': pkt_id,
        'ts': ts,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'proto': proto,
        'length': length,
        'info': spkt.summary(),
        'threat': threat,
        'is_alert': is_alert,
        'matched_rule': matched_rule,
        'hex': hex_lines,
        'layers': layers,
        'src_port': sport,
        'dst_port': dport,
    }


def _process_live_packet(spkt):
    """Per-packet callback for scapy.sniff in live mode."""
    if not state['live_capture_mode']:
        return
    try:
        pkt = _scapy_to_packet(spkt)
    except Exception as e:
        print(f'[LIVE] Packet processing error: {e}')
        return

    state['packets'].append(pkt)
    if len(state['packets']) > 2000:
        state['packets'] = state['packets'][-2000:]

    proto_key = pkt['proto'] if pkt['proto'] in state['protocol_stats'] else 'OTHER'
    state['protocol_stats'][proto_key] = state['protocol_stats'].get(proto_key, 0) + 1
    state['total_bytes'] += pkt.get('length', 0)
    state['threat_stats'][pkt.get('threat', 'LOW')] = state['threat_stats'].get(pkt.get('threat', 'LOW'), 0) + 1

    # Feed packet to Detector Manager
    detector_manager.process_packet(spkt)
    # Feed the flow tracker so the ML classifier can analyse real traffic
    try:
        flow_tracker.add_packet(spkt, time.time())
    except Exception:
        pass

    if state['running'] and not state['paused']:
        socketio.emit('packet', pkt)

    # Real alert from a real rule match on a real packet
    if pkt['is_alert']:
        alert = {
            'id': state['alert_count'] + 1,
            'ts': pkt['ts'],
            'type': 'Rule Match',
            'threat': pkt['threat'],
            'src': pkt['src_ip'],
            'dst': pkt['dst_ip'],
            'rule': pkt['matched_rule'],
            'info': pkt['info'],
            'proto': pkt['proto'],
        }
        state['alert_count'] += 1
        state['alerts'].append(alert)
        if len(state['alerts']) > 500:
            state['alerts'] = state['alerts'][-500:]
        if state['running'] and not state['paused']:
            socketio.emit('alert', alert)


def live_capture_thread():
    """Run scapy.sniff continuously in the background."""
    from scapy.all import sniff
    print('[LIVE] Live capture thread started (Continuous background monitoring)')
    while True:
        iface = state['interface']
        # On Windows, Scapy's Npcap driver requires the '\\Device\\NPF_' prefix before the GUID
        if os.name == 'nt' and iface.startswith('{') and iface.endswith('}'):
            iface = f"\\Device\\NPF_{iface}"
            
        try:
            sniff(iface=iface, prn=_process_live_packet,
                  timeout=1, store=False)
        except PermissionError:
            msg = f'Permission denied on {iface}. Re-run with sudo for live capture.'
            print(f'[LIVE] {msg}')
            if state['running'] and not state['paused']:
                socketio.emit('capture_error', {'error': msg})
            socketio.sleep(2)
        except OSError:
            socketio.sleep(1)
        except Exception as e:
            print(f'[LIVE] sniff error: {e}')
            socketio.sleep(1)


def live_stats_thread():
    """Emit periodic traffic-rate updates while live capture is running."""
    last_count = 0
    last_bytes = 0
    last_time = time.time()
    while True:
        socketio.sleep(1.0)
        if not state['running'] or state['paused']:
            last_count = state['packet_count']
            last_bytes = state['total_bytes']
            last_time = time.time()
            continue
        now = time.time()
        cur = state['packet_count']
        cur_bytes = state['total_bytes']
        elapsed = max(now - last_time, 0.001)
        pps = round((cur - last_count) / elapsed, 1)
        bps = round((cur_bytes - last_bytes) / elapsed)
        last_count, last_bytes, last_time = cur, cur_bytes, now

        traffic_point = {
            'ts': datetime.now().strftime('%H:%M:%S'),
            'pps': pps,
            'bps': bps,
            'total': cur,
        }
        state['traffic_history'].append(traffic_point)
        if len(state['traffic_history']) > 60:
            state['traffic_history'] = state['traffic_history'][-60:]
        socketio.emit('traffic_update', {
            'traffic': traffic_point,
            'protocol_stats': state['protocol_stats'],
            'total_bytes': state['total_bytes'],
            'threat_stats': state['threat_stats'],
            'status': _status(),
        })


# ─── Background simulation thread ──────────────────────────────────────────────

def simulation_thread():
    recent_packets = []
    traffic_tick = 0
    while True:
        # Run continuously in background
        delay = random.uniform(0.12, 0.28)
        socketio.sleep(delay)
        if state['live_capture_mode'] or state['file_mode']:
            continue

        pkt = _generate_packet()
        state['packets'].append(pkt)
        if len(state['packets']) > 2000:
            state['packets'] = state['packets'][-2000:]
        recent_packets.append(pkt)
        if len(recent_packets) > 100:
            recent_packets = recent_packets[-100:]

        # Feed to Detector Manager
        scapy_pkt = simulated_to_scapy(pkt)
        if scapy_pkt:
            detector_manager.process_packet(scapy_pkt)
            try:
                flow_tracker.add_packet(scapy_pkt, time.time())
            except Exception:
                pass

        if state['running'] and not state['paused']:
            socketio.emit('packet', pkt)

        # Inline rule checks for simulated alerts
        if SIMULATE_ALERTS and pkt['is_alert']:
            alert = {
                'id': state['alert_count'] + 1,
                'ts': pkt['ts'],
                'type': random.choice(ATTACK_TYPES),
                'threat': pkt['threat'],
                'src': pkt['src_ip'],
                'dst': pkt['dst_ip'],
                'rule': pkt['matched_rule'],
                'info': pkt['info'],
                'proto': pkt['proto'],
            }
            state['alert_count'] += 1
            state['alerts'].append(alert)
            if len(state['alerts']) > 500:
                state['alerts'] = state['alerts'][-500:]
            if state['running'] and not state['paused']:
                socketio.emit('alert', alert)

        traffic_tick += 1
        if traffic_tick % 20 == 0:
            if SIMULATE_ALERTS:
                attack_alerts = _check_for_attacks(recent_packets)
                for al in attack_alerts:
                    state['alert_count'] += 1
                    al['id'] = state['alert_count']
                    state['alerts'].append(al)
                    if state['running'] and not state['paused']:
                        socketio.emit('alert', al)

            traffic_point = {
                'ts': datetime.now().strftime('%H:%M:%S'),
                'pps': round(1 / delay, 1),
                'bps': round(state['total_bytes'] / max(time.time() - (state['start_time'] or time.time()), 1)),
                'total': state['packet_count'],
            }
            state['traffic_history'].append(traffic_point)
            if len(state['traffic_history']) > 60:
                state['traffic_history'] = state['traffic_history'][-60:]
            
            if state['running'] and not state['paused']:
                socketio.emit('traffic_update', {
                    'traffic': traffic_point,
                    'protocol_stats': state['protocol_stats'],
                    'total_bytes': state['total_bytes'],
                    'threat_stats': state['threat_stats'],
                    'status': _status(),
                })


def _status():
    active_count = sum(1 for d in detector_manager.get_detectors_metadata() if d['enabled'])
    return {
        'packet_count': state['packet_count'],
        'alert_count': state['alert_count'],
        'filtered_count': state['filtered_count'],
        'interface': state['interface'],
        'running': state['running'],
        'paused': state['paused'],
        'uptime': _uptime(),
        'active_detectors_count': active_count,
        'selected_rules_file': state['selected_rules_file'],
        'live_capture_mode': state['live_capture_mode']
    }


def _uptime():
    if state['start_time']:
        elapsed = int(time.time() - state['start_time'])
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        return f'{h:02d}:{m:02d}:{s:02d}'
    return '00:00:00'


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    return jsonify(_status())


@app.route('/api/packets')
def api_packets():
    limit = int(request.args.get('limit', 200))
    return jsonify(state['packets'][-limit:])


@app.route('/api/alerts')
def api_alerts():
    return jsonify(state['alerts'][-100:])


@app.route('/api/rules')
def api_rules():
    rules = []
    rule_files = [f for f in os.listdir('.') if f.endswith('.rules')]
    for path in rule_files:
        if os.path.exists(path):
            with open(path, encoding='utf-8') as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    rules.append({
                        'line': i,
                        'file': path,
                        'text': line,
                        'is_comment': line.startswith('#'),
                        'is_empty': line == '',
                    })
    return jsonify(rules)


@app.route('/api/rules/validate', methods=['POST'])
def api_validate_rule():
    data = request.json or {}
    rule_text = data.get('rule', '').strip()
    if not rule_text:
        return jsonify({'valid': False, 'error': 'Empty rule'})
    try:
        sigs = verify_rules([rule_text])
        return jsonify({'valid': True, 'parsed': str(sigs[0])})
    except ValueError as e:
        return jsonify({'valid': False, 'error': str(e)})


@app.route('/api/rules/upload', methods=['POST'])
def api_rules_upload():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        f = request.files['file']
        if not f.filename:
            return jsonify({'success': False, 'error': 'Empty filename'})
        if not f.filename.lower().endswith('.rules'):
            return jsonify({'success': False, 'error': 'Only .rules files are supported'})
        
        import string
        safe_chars = "-_.() " + string.ascii_letters + string.digits
        filename = ''.join(c for c in f.filename if c in safe_chars)
        if not filename or not filename.endswith('.rules'):
            filename = "uploaded.rules"
            
        dest_path = os.path.join('.', filename)
        f.save(dest_path)
        
        # Load rules
        global ids_rules
        state['selected_rules_file'] = filename
        ids_rules = load_ids_rules(filename)
        
        # Emit rules_loaded with rules_files to all clients
        socketio.emit('rules_loaded', {
            'rules': state['rules'],
            'count': len(ids_rules),
            'selected_rules_file': filename,
            'rules_files': [file for file in os.listdir('.') if file.endswith('.rules')]
        })
        
        return jsonify({'success': True, 'filename': filename, 'rules_count': len(ids_rules)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


def get_friendly_name(iface_name):
    if os.name == 'nt':
        try:
            import winreg
            import re
            m = re.search(r'\{[a-fA-F0-9\-]+\}', iface_name)
            if m:
                guid = m.group(0)
                reg_path = f"SYSTEM\\CurrentControlSet\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{guid}\\Connection"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                    friendly_name, _ = winreg.QueryValueEx(key, "Name")
                    return friendly_name
        except Exception:
            pass
    return iface_name


@app.route('/api/interfaces')
def api_interfaces():
    ifaces = []
    for name in netifaces.interfaces():
        addrs = netifaces.ifaddresses(name)
        ipv4_list = [a.get('addr', '') for a in addrs.get(netifaces.AF_INET, []) if a.get('addr')]
        ipv6_list = [a.get('addr', '').split('%')[0] for a in addrs.get(netifaces.AF_INET6, []) if a.get('addr')]
        mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', '') if hasattr(netifaces, 'AF_LINK') else ''
        is_loopback = name in ('lo', 'lo0') or any(ip.startswith('127.') for ip in ipv4_list) or '::1' in ipv6_list
        friendly = get_friendly_name(name)
        ifaces.append({
            'name': name,
            'friendly_name': friendly,
            'ip': ipv4_list[0] if ipv4_list else '',
            'ipv4': ipv4_list,
            'ipv6': ipv6_list,
            'mac': mac,
            'loopback': is_loopback,
            'active': name == state['interface'],
        })
    return jsonify(ifaces)


@app.route('/api/stats')
def api_stats():
    return jsonify({
        'protocol_stats': state['protocol_stats'],
        'traffic_history': state['traffic_history'][-30:],
        'status': _status(),
        'total_bytes': state['total_bytes'],
        'threat_stats': state['threat_stats'],
    })


@app.route('/api/dataset-report')
def api_dataset_report():
    # If the user uploaded a CSV, show ITS composition instead of the static default.
    if state.get('dataset_report'):
        return jsonify(state['dataset_report'])
    return jsonify({
        'success': True,
        'source': 'default',
        'dataset': 'CICIDS 2017 / 2018 Unified Balanced',
        'total_samples': 916666,
        'n_features': 78,
        'n_classes': 27,
        'benign_count': 366666,
        'benign_pct': 40.0,
        'attack_count': 550000,
        'attack_pct': 60.0,
        'algorithm': 'Random Forest',
        'estimators': 200,
        'classes': [
            {'name': 'Benign',                      'count': 366666, 'pct': 40.0000, 'is_benign': True},
            {'name': 'DDOS attack-HOIC',            'count': 105407, 'pct': 11.5000, 'is_benign': False},
            {'name': 'DDoS attacks-LOIC-HTTP',      'count':  87830, 'pct':  9.5815, 'is_benign': False},
            {'name': 'DoS attacks-Hulk',            'count':  70467, 'pct':  7.6873, 'is_benign': False},
            {'name': 'Bot',                         'count':  44219, 'pct':  4.8239, 'is_benign': False},
            {'name': 'DoS Hulk',                    'count':  35455, 'pct':  3.8678, 'is_benign': False},
            {'name': 'FTP-BruteForce',              'count':  29369, 'pct':  3.2039, 'is_benign': False},
            {'name': 'SSH-Bruteforce',              'count':  28706, 'pct':  3.1316, 'is_benign': False},
            {'name': 'Infilteration',               'count':  24747, 'pct':  2.7000, 'is_benign': False},
            {'name': 'PortScan',                    'count':  24136, 'pct':  2.6330, 'is_benign': False},
            {'name': 'DoS attacks-SlowHTTPTest',    'count':  21512, 'pct':  2.3468, 'is_benign': False},
            {'name': 'DDoS',                        'count':  19601, 'pct':  2.1383, 'is_benign': False},
            {'name': 'DoS attacks-GoldenEye',       'count':   6488, 'pct':  0.7078, 'is_benign': False},
            {'name': 'DoS attacks-Slowloris',       'count':   1673, 'pct':  0.1825, 'is_benign': False},
            {'name': 'DoS GoldenEye',               'count':   1553, 'pct':  0.1694, 'is_benign': False},
            {'name': 'FTP-Patator',                 'count':   1241, 'pct':  0.1354, 'is_benign': False},
            {'name': 'DoS slowloris',               'count':    897, 'pct':  0.0979, 'is_benign': False},
            {'name': 'SSH-Patator',                 'count':    895, 'pct':  0.0976, 'is_benign': False},
            {'name': 'DoS Slowhttptest',            'count':    862, 'pct':  0.0940, 'is_benign': False},
            {'name': 'DDOS attack-LOIC-UDP',        'count':    275, 'pct':  0.0300, 'is_benign': False},
            {'name': 'Web Attack - Brute Force',    'count':    218, 'pct':  0.0238, 'is_benign': False},
            {'name': 'Web Attack - XSS',            'count':    102, 'pct':  0.0111, 'is_benign': False},
            {'name': 'Brute Force -Web',            'count':     84, 'pct':  0.0092, 'is_benign': False},
            {'name': 'Brute Force -XSS',            'count':     37, 'pct':  0.0040, 'is_benign': False},
            {'name': 'SQL Injection',               'count':      7, 'pct':  0.0008, 'is_benign': False},
            {'name': 'Web Attack - SQL Injection',  'count':      4, 'pct':  0.0004, 'is_benign': False},
            {'name': 'Infiltration',                'count':      2, 'pct':  0.0002, 'is_benign': False},
        ],
    })


# ─── Classifier API ───────────────────────────────────────────────────────────

@app.route('/api/classifier/features')
def api_classifier_features():
    try:
        info = get_feature_info()
        meta = get_model_metadata()
        return jsonify({'success': True, 'features': info, 'model_meta': meta})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/classifier/predict', methods=['POST'])
def api_classifier_predict():
    try:
        data = request.json or {}
        result = predict_single(data)
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/classifier/upload-csv', methods=['POST'])
def api_classifier_upload_csv():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        f = request.files['file']
        if not f.filename.lower().endswith('.csv'):
            return jsonify({'success': False, 'error': 'Only CSV files are supported'})
        info = feature_info_from_csv(f.stream)
        # Also compute the dataset-composition report from the CSV's labels so the
        # Statistics panel reflects the uploaded file instead of the static defaults.
        report = None
        try:
            report = dataset_report_from_csv(f.stream, filename=f.filename)
            state['dataset_report'] = report
        except Exception as e:
            print(f'[WARN] dataset report from CSV failed: {e}')
        return jsonify({'success': True, 'features': info, 'filename': f.filename,
                        'count': len(info), 'dataset_report': report})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


def _native_dialog(mode, kind, suggested=''):
    """Pop a native OS file dialog (in a subprocess) and return the chosen path or None.

    Runs the dialog in a separate process so the web server's threads never touch
    Tcl/Tk (which is not thread-safe). mode='open'|'save', kind='pcap'|'docx'.
    """
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'file_dialog.py')
    try:
        proc = subprocess.run(
            [sys.executable, script, mode, kind, suggested],
            capture_output=True, text=True, timeout=600,
        )
        path = (proc.stdout or '').strip()
        return path or None
    except Exception:
        return None


def prompt_save_path(suggested_name):
    """Native "Save As" dialog for the Word report (.docx)."""
    return _native_dialog('save', 'docx', suggested_name)


def prompt_open_pcap():
    """Native "Open" dialog for a packet capture (.pcap/.pcapng/.cap)."""
    return _native_dialog('open', 'pcap')


def prompt_save_pcap(suggested_name):
    """Native "Save As" dialog for a packet capture (.pcap)."""
    return _native_dialog('save', 'pcap', suggested_name)


def _reset_capture_view():
    """Clear packets / alerts / counters / stats (used when opening a pcap)."""
    state['packet_count'] = 0
    state['alert_count'] = 0
    state['filtered_count'] = 0
    state['packets'] = []
    state['alerts'] = []
    state['protocol_stats'] = {
        'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0,
        'HTTP': 0, 'DNS': 0, 'TLS': 0, 'SSH': 0, 'FTP': 0, 'SMTP': 0,
        'OTHER': 0,
    }
    state['traffic_history'] = []
    state['total_bytes'] = 0
    state['threat_stats'] = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    flow_tracker.reset()


@app.route('/api/capture/open-pcap', methods=['POST'])
def api_open_pcap():
    """Open a native file dialog, read a .pcap, classify every packet against the
    loaded rules, and load the results into the dashboard view (freezing the
    background simulation)."""
    try:
        path = prompt_open_pcap()
        if not path:
            return jsonify({'success': False, 'cancelled': True,
                            'error': 'Open cancelled by user.'}), 200
        if not os.path.exists(path):
            return jsonify({'success': False, 'error': 'File not found: ' + path}), 400

        try:
            from scapy.utils import rdpcap
            packets = rdpcap(path)
        except Exception as e:
            return jsonify({'success': False,
                            'error': 'Could not read capture file: ' + str(e)}), 400

        MAX_PKTS = 2000
        total_in_file = len(packets)
        truncated = total_in_file > MAX_PKTS
        selected = packets[:MAX_PKTS]

        # Enter file mode: freeze the simulation and reset the current view.
        state['file_mode'] = True
        state['running'] = False
        state['paused'] = False
        _reset_capture_view()

        alerts_added = 0
        for spkt in selected:
            try:
                pkt = _scapy_to_packet(spkt)
            except Exception:
                continue
            # Feed the flow tracker with the packet's real capture time
            try:
                pkt_ts = float(spkt.time)
            except Exception:
                pkt_ts = time.time()
            try:
                flow_tracker.add_packet(spkt, pkt_ts)
            except Exception:
                pass
            state['packets'].append(pkt)
            proto_key = pkt['proto'] if pkt['proto'] in state['protocol_stats'] else 'OTHER'
            state['protocol_stats'][proto_key] = state['protocol_stats'].get(proto_key, 0) + 1
            state['total_bytes'] += pkt.get('length', 0)
            state['threat_stats'][pkt.get('threat', 'LOW')] = \
                state['threat_stats'].get(pkt.get('threat', 'LOW'), 0) + 1
            try:
                detector_manager.process_packet(spkt)
            except Exception:
                pass
            if pkt['is_alert']:
                state['alert_count'] += 1
                state['alerts'].append({
                    'id': state['alert_count'],
                    'ts': pkt['ts'],
                    'type': 'Rule Match',
                    'threat': pkt['threat'],
                    'src': pkt['src_ip'],
                    'dst': pkt['dst_ip'],
                    'rule': pkt['matched_rule'],
                    'info': pkt['info'],
                    'proto': pkt['proto'],
                })
                alerts_added += 1

        # Thread-based detectors (ARP, SYN-scan) drain their queues asynchronously —
        # give them a moment so their alerts land in state before the client refetches.
        socketio.sleep(1.2)

        loaded = len(state['packets'])
        socketio.emit('pcap_loaded', {
            'filename': os.path.basename(path),
            'count': loaded,
            'alerts': alerts_added,
            'truncated': truncated,
            'total_in_file': total_in_file,
        })
        socketio.emit('status_update', _status())

        return jsonify({'success': True, 'filename': os.path.basename(path),
                        'count': loaded, 'alerts': alerts_added,
                        'truncated': truncated, 'total_in_file': total_in_file})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/capture/save-pcap', methods=['POST'])
def api_save_pcap():
    """Open a native Save dialog and write the current packets to a .pcap file."""
    try:
        pkts = list(state['packets'])
        if not pkts:
            return jsonify({'success': False,
                            'error': 'No packets to save — capture or open something first.'}), 200

        suggested = 'capture_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '.pcap'
        save_path = prompt_save_pcap(suggested)
        if not save_path:
            return jsonify({'success': False, 'cancelled': True,
                            'error': 'Save cancelled by user.'}), 200
        low = save_path.lower()
        if not (low.endswith('.pcap') or low.endswith('.pcapng') or low.endswith('.cap')):
            save_path += '.pcap'

        scapy_pkts = []
        for pd in pkts:
            sp = simulated_to_scapy(pd)
            if sp is not None:
                scapy_pkts.append(sp)
        if not scapy_pkts:
            return jsonify({'success': False,
                            'error': 'Could not reconstruct any packets for export.'}), 200

        from scapy.utils import wrpcap
        wrpcap(save_path, scapy_pkts)

        return jsonify({'success': True, 'saved_path': save_path,
                        'filename': os.path.basename(save_path), 'count': len(scapy_pkts)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/classifier/analyze-traffic', methods=['POST'])
def api_classifier_analyze_traffic():
    """Run the ML classifier over the REAL dashboard traffic: reassemble the captured
    packets into bidirectional flows, compute CICFlowMeter features, and classify each
    flow with the Random Forest model."""
    try:
        snapshot = flow_tracker.snapshot()
        if not snapshot:
            return jsonify({'success': False,
                            'error': 'No traffic captured yet. Start capture, run the '
                                     'simulation, or open a .pcap first.'}), 200

        metas = [m for m, _f in snapshot]
        feats = [f for _m, f in snapshot]
        preds = predict_batch(feats)

        class_counts = {}
        flows_out = []
        benign = 0
        for meta, pred in zip(metas, preds):
            label = pred['prediction']
            class_counts[label] = class_counts.get(label, 0) + 1
            is_benign = label.strip().lower() in ('benign', 'normal')
            if is_benign:
                benign += 1
            flows_out.append({
                'src': meta['src'],
                'src_port': meta['sport'],
                'dst_port': meta['dst_port'],
                'proto': {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(meta['proto'], str(meta['proto'])),
                'packets': meta['pkts'],
                'prediction': label,
                'confidence': pred.get('confidence'),
                'is_attack': not is_benign,
            })

        total = len(flows_out)
        attacks = total - benign
        # Sort: attacks first (highest confidence), then benign
        flows_out.sort(key=lambda x: (not x['is_attack'], -(x['confidence'] or 0)))
        distribution = sorted(class_counts.items(), key=lambda kv: kv[1], reverse=True)

        return jsonify({
            'success': True,
            'total_flows': total,
            'benign_flows': benign,
            'attack_flows': attacks,
            'distribution': [{'class': c, 'count': n,
                              'pct': round(n / total * 100, 1)} for c, n in distribution],
            'flows': flows_out[:200],
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def _classify_captured_flows(defaults=None):
    """Classify the captured flows. Returns (breakdown_dict, stats_text) or (None, None)."""
    snapshot = flow_tracker.snapshot()
    if not snapshot:
        return None, None
    metas = [m for m, _f in snapshot]
    feats = [f for _m, f in snapshot]
    preds = predict_batch(feats, defaults=defaults)

    class_counts = {}
    flows_out = []
    benign = 0
    for meta, pred in zip(metas, preds):
        label = pred['prediction']
        class_counts[label] = class_counts.get(label, 0) + 1
        is_benign = label.strip().lower() in ('benign', 'normal')
        if is_benign:
            benign += 1
        flows_out.append({
            'src': meta['src'], 'src_port': meta['sport'], 'dst_port': meta['dst_port'],
            'proto': {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(meta['proto'], str(meta['proto'])),
            'packets': meta['pkts'], 'prediction': label,
            'confidence': pred.get('confidence'), 'is_attack': not is_benign,
        })
    total = len(flows_out)
    attacks = total - benign
    flows_out.sort(key=lambda x: (not x['is_attack'], -(x['confidence'] or 0)))
    distribution = sorted(class_counts.items(), key=lambda kv: kv[1], reverse=True)

    # Extra statistics
    total_packets = sum(f['packets'] for f in flows_out)
    proto_counts = {}
    port_counts = {}
    talker_counts = {}
    conf_sum = 0.0
    conf_n = 0
    for f in flows_out:
        proto_counts[f['proto']] = proto_counts.get(f['proto'], 0) + 1
        port_counts[f['dst_port']] = port_counts.get(f['dst_port'], 0) + 1
        talker_counts[f['src']] = talker_counts.get(f['src'], 0) + 1
        if f['confidence'] is not None:
            conf_sum += f['confidence']
            conf_n += 1
    top_ports = sorted(port_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    top_talkers = sorted(talker_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    avg_conf = round(conf_sum / conf_n, 1) if conf_n else 0.0

    breakdown = {
        'total_flows': total, 'benign_flows': benign, 'attack_flows': attacks,
        'total_packets': total_packets,
        'unique_sources': len(talker_counts),
        'unique_dst_ports': len(port_counts),
        'avg_confidence': avg_conf,
        'attack_pct': round(attacks / total * 100, 1) if total else 0,
        'protocols': sorted(proto_counts.items(), key=lambda kv: kv[1], reverse=True),
        'top_ports': top_ports,
        'top_talkers': top_talkers,
        'distribution': [{'class': c, 'count': n, 'pct': round(n / total * 100, 1)}
                         for c, n in distribution],
        'flows': flows_out[:200],
    }

    # Plain-text statistics fed to Gemini
    lines = [
        '=' * 60,
        'CAPTURED NETWORK TRAFFIC ANALYSIS',
        'Random Forest classification of live / simulated / pcap flows',
        '=' * 60, '',
        f'Total flows analyzed: {total}',
        f'Benign flows: {benign} ({benign / total * 100:.1f}%)',
        f'Attack flows: {attacks} ({attacks / total * 100:.1f}%)',
        '', 'Class distribution:',
    ]
    for c, n in distribution:
        lines.append(f'  {c}: {n} ({n / total * 100:.1f}%)')
    lines += ['', 'Top flagged (attack) flows:']
    listed = [f for f in flows_out if f['is_attack']][:40]
    if listed:
        for f in listed:
            lines.append(f"  {f['src']}:{f['src_port']} -> :{f['dst_port']} {f['proto']} | "
                         f"{f['packets']} pkts | {f['prediction']} ({f['confidence']}%)")
    else:
        lines.append('  None — all captured flows classified as benign.')
    lines.append('')
    return breakdown, '\n'.join(lines)


@app.route('/api/classifier/traffic-report', methods=['POST'])
def api_traffic_report():
    """Classify the CAPTURED traffic (live/simulated/pcap flows) using the model
    (optionally with CSV-median feature defaults), then save a Gemini-authored Word
    report on that captured-traffic classification via a native Save dialog."""
    def progress(pct, message, done=False):
        socketio.emit('report_progress', {'pct': pct, 'message': message, 'done': done})

    try:
        body = request.get_json(silent=True) or {}
        defaults = body.get('defaults') if isinstance(body.get('defaults'), dict) else None

        progress(12, 'Reassembling flows & classifying captured traffic…')
        breakdown, stats_text = _classify_captured_flows(defaults=defaults)
        if breakdown is None:
            progress(100, 'No traffic captured', done=True)
            return jsonify({'success': False,
                            'error': 'No traffic captured yet. Start capture, run the '
                                     'simulation, or open a .pcap first.'}), 200

        progress(35, 'Choose where to save the report…')
        suggested = 'Traffic_Report_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '.docx'
        save_path = prompt_save_path(suggested)
        if not save_path:
            progress(100, 'Report save cancelled', done=True)
            return jsonify({'success': True, 'report_saved': False,
                            'cancelled_report': True, **breakdown})
        if not save_path.lower().endswith('.docx'):
            save_path += '.docx'

        from classifier import call_gemini_api, markdown_to_docx
        progress(58, 'Generating AI security report (Gemini)…')
        md = call_gemini_api(stats_text)
        progress(88, 'Writing Word document…')
        markdown_to_docx(md, save_path)
        progress(100, 'Report saved', done=True)

        return jsonify({'success': True, 'report_saved': True, 'saved_path': save_path,
                        'filename': os.path.basename(save_path), **breakdown})
    except Exception as e:
        progress(100, 'Error', done=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/classifier/report', methods=['POST'])
def api_classifier_report():
    """Bulk-classify an uploaded CSV, then save a Gemini-authored Word (.docx) report
    to a location chosen by the user via a native Save dialog."""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        f = request.files['file']
        if not f.filename.lower().endswith('.csv'):
            return jsonify({'success': False, 'error': 'Only CSV files are supported'}), 400

        # Ask WHERE to save first, so a cancel avoids the expensive Gemini call.
        base = os.path.splitext(os.path.basename(f.filename))[0]
        suggested = f'Security_Report_{base}.docx'
        save_path = prompt_save_path(suggested)
        if not save_path:
            return jsonify({'success': False, 'cancelled': True,
                            'error': 'Save cancelled by user.'}), 200
        if not save_path.lower().endswith('.docx'):
            save_path += '.docx'

        docx_io, stats = generate_security_report(f.stream)
        with open(save_path, 'wb') as out:
            out.write(docx_io.getbuffer())

        return jsonify({
            'success': True,
            'saved_path': save_path,
            'filename': os.path.basename(save_path),
            'stats': stats,
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ─── WebSocket events ─────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    emit('init', {
        'status': _status(),
        'protocol_stats': state['protocol_stats'],
        'rules': state['rules'],
        'recent_packets': state['packets'][-50:],
        'recent_alerts': state['alerts'][-20:],
        'traffic_history': state['traffic_history'][-30:],
        'detectors': detector_manager.get_detectors_metadata(),
        'rules_files': [f for f in os.listdir('.') if f.endswith('.rules')],
        'selected_rules_file': state['selected_rules_file']
    })


@socketio.on('toggle_detector')
def on_toggle_detector(data):
    class_name = data.get('id')
    enabled = data.get('enabled', True)
    success = detector_manager.toggle_detector(class_name, enabled)
    # Broadcast status change to all clients
    emit('detector_status_changed', {
        'id': class_name,
        'enabled': enabled,
        'success': success,
        'detectors': detector_manager.get_detectors_metadata(),
        'status': _status()
    }, broadcast=True)


@socketio.on('toggle_capture_mode')
def on_toggle_capture_mode(data):
    live_mode = data.get('live', False)
    state['live_capture_mode'] = live_mode
    print(f"[*] Capture mode switched dynamically to: {'LIVE CAPTURE' if live_mode else 'SIMULATION'}")
    emit('status_update', _status(), broadcast=True)


@socketio.on('start_capture')
def on_start():
    state['running'] = True
    state['paused'] = False
    state['file_mode'] = False   # resume live/simulated traffic
    if not state['start_time']:
        state['start_time'] = time.time()
    emit('status_update', _status(), broadcast=True)


@socketio.on('stop_capture')
def on_stop():
    state['running'] = False
    state['paused'] = False
    emit('status_update', _status(), broadcast=True)


@socketio.on('pause_capture')
def on_pause():
    state['paused'] = not state['paused']
    emit('status_update', _status(), broadcast=True)


@socketio.on('restart_capture')
def on_restart():
    state['running'] = False
    state['paused'] = False
    state['file_mode'] = False   # resume live/simulated traffic
    state['packet_count'] = 0
    state['alert_count'] = 0
    state['filtered_count'] = 0
    state['packets'] = []
    state['alerts'] = []
    state['protocol_stats'] = {
        'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0,
        'HTTP': 0, 'DNS': 0, 'TLS': 0, 'SSH': 0, 'FTP': 0, 'SMTP': 0,
        'OTHER': 0,
    }
    state['traffic_history'] = []
    state['total_bytes'] = 0
    state['threat_stats'] = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    state['start_time'] = None
    flow_tracker.reset()
    emit('cleared', {}, broadcast=True)
    time.sleep(0.3)
    state['running'] = True
    state['start_time'] = time.time()
    emit('status_update', _status(), broadcast=True)


@socketio.on('set_interface')
def on_set_interface(data):
    iface = data.get('interface', 'eth0')
    state['interface'] = iface
    emit('status_update', _status(), broadcast=True)


@socketio.on('set_filter')
def on_set_filter(data):
    state['active_filter'] = data.get('filter', '')
    emit('filter_applied', {'filter': state['active_filter']}, broadcast=True)


@socketio.on('load_rules')
def on_load_rules(data):
    global ids_rules
    path = data.get('path', 'default.rules')
    
    # Store currently selected rules file in state
    state['selected_rules_file'] = path
    
    # Reload rules
    ids_rules = load_ids_rules(path)
    
    # Emit event to notify frontend
    emit('rules_loaded', {
        'rules': state['rules'],
        'count': len(ids_rules),
        'selected_rules_file': path,
        'rules_files': [f for f in os.listdir('.') if f.endswith('.rules')]
    }, broadcast=True)


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print('[*] Initializing background capture & simulation engines (ready for dynamic toggle)...')
    socketio.start_background_task(live_capture_thread)
    socketio.start_background_task(live_stats_thread)
    socketio.start_background_task(simulation_thread)
    port_start = int(os.environ.get('PORT', 5000))
    for port in range(port_start, port_start + 100):
        try:
            print(f'[*] Attempting to start server on port {port}...')
            socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
            break
        except OSError as e:
            print(f'[WARN] Port {port} is in use: {e}')
            continue
