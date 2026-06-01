# -*- coding: utf-8 -*-
"""Reassemble packets into bidirectional flows and compute CICFlowMeter-style
features so the CICIDS Random Forest classifier can analyse real dashboard traffic
(live capture, simulation, or an opened .pcap).

This is an approximation of CICFlowMeter: ~64 of the model's 78 features are computed
directly from packets; the rest (bulk-transfer and active/idle timing features) are
left for the classifier to fill with training means. Durations/IATs are expressed in
microseconds to match the training scale.
"""
import math
import threading


def _proto_num(spkt):
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6
        if spkt.haslayer(TCP):
            return 6
        if spkt.haslayer(UDP):
            return 17
        if spkt.haslayer(ICMP):
            return 1
        if spkt.haslayer(IP):
            return int(spkt[IP].proto)
        if spkt.haslayer(IPv6):
            return int(spkt[IPv6].nh)
    except Exception:
        pass
    return 0


def _packet_view(spkt):
    """Extract the fields we need from a scapy packet. Returns a dict or None."""
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
    except Exception:
        return None

    if spkt.haslayer(IP):
        ip = spkt[IP]
        src, dst = ip.src, ip.dst
        ip_hdr_len = ip.ihl * 4 if ip.ihl else 20
        ip_total = ip.len if ip.len else len(ip)
    elif spkt.haslayer(IPv6):
        ip6 = spkt[IPv6]
        src, dst = ip6.src, ip6.dst
        ip_hdr_len = 40
        ip_total = len(ip6)
    else:
        return None

    proto = _proto_num(spkt)
    sport = dport = 0
    tcp_hdr_len = 0
    win = 0
    flags = {'F': 0, 'S': 0, 'R': 0, 'P': 0, 'A': 0, 'U': 0, 'E': 0, 'C': 0}
    payload_len = 0

    if spkt.haslayer(TCP):
        tcp = spkt[TCP]
        sport, dport = int(tcp.sport), int(tcp.dport)
        tcp_hdr_len = tcp.dataofs * 4 if tcp.dataofs else 20
        win = int(tcp.window)
        f = tcp.flags
        flags['F'] = 1 if f & 0x01 else 0
        flags['S'] = 1 if f & 0x02 else 0
        flags['R'] = 1 if f & 0x04 else 0
        flags['P'] = 1 if f & 0x08 else 0
        flags['A'] = 1 if f & 0x10 else 0
        flags['U'] = 1 if f & 0x20 else 0
        flags['E'] = 1 if f & 0x40 else 0
        flags['C'] = 1 if f & 0x80 else 0
        payload_len = max(0, ip_total - ip_hdr_len - tcp_hdr_len)
    elif spkt.haslayer(UDP):
        udp = spkt[UDP]
        sport, dport = int(udp.sport), int(udp.dport)
        tcp_hdr_len = 8
        payload_len = max(0, ip_total - ip_hdr_len - 8)
    else:
        payload_len = max(0, ip_total - ip_hdr_len)

    header_len = ip_hdr_len + tcp_hdr_len
    return {
        'src': src, 'dst': dst, 'sport': sport, 'dport': dport, 'proto': proto,
        'length': int(ip_total), 'header_len': int(header_len),
        'payload_len': int(payload_len), 'win': int(win), 'flags': flags,
    }


class _DirStats:
    """Per-direction accumulators (O(1) memory via running sums)."""
    __slots__ = ('pkts', 'bytes', 'len_min', 'len_max', 'len_sum', 'len_sqsum',
                 'last_ts', 'iat_sum', 'iat_sqsum', 'iat_min', 'iat_max', 'iat_cnt',
                 'header_len', 'psh', 'urg', 'win_init', 'act_data_pkts',
                 'seg_min', 'seg_sum')

    def __init__(self):
        self.pkts = 0
        self.bytes = 0
        self.len_min = None
        self.len_max = 0
        self.len_sum = 0
        self.len_sqsum = 0
        self.last_ts = None
        self.iat_sum = 0.0
        self.iat_sqsum = 0.0
        self.iat_min = None
        self.iat_max = 0.0
        self.iat_cnt = 0
        self.header_len = 0
        self.psh = 0
        self.urg = 0
        self.win_init = None
        self.act_data_pkts = 0
        self.seg_min = None
        self.seg_sum = 0

    def add(self, pv, ts):
        ln = pv['length']
        self.pkts += 1
        self.bytes += ln
        self.len_min = ln if self.len_min is None else min(self.len_min, ln)
        self.len_max = max(self.len_max, ln)
        self.len_sum += ln
        self.len_sqsum += ln * ln
        self.header_len += pv['header_len']
        self.psh += pv['flags']['P']
        self.urg += pv['flags']['U']
        if self.win_init is None:
            self.win_init = pv['win']
        if pv['payload_len'] > 0:
            self.act_data_pkts += 1
        seg = pv['payload_len']
        self.seg_sum += seg
        self.seg_min = seg if self.seg_min is None else min(self.seg_min, seg)
        if self.last_ts is not None:
            iat = (ts - self.last_ts) * 1e6  # microseconds
            if iat < 0:
                iat = 0.0
            self.iat_sum += iat
            self.iat_sqsum += iat * iat
            self.iat_min = iat if self.iat_min is None else min(self.iat_min, iat)
            self.iat_max = max(self.iat_max, iat)
            self.iat_cnt += 1
        self.last_ts = ts


def _std(n, s, sq):
    if n <= 0:
        return 0.0
    mean = s / n
    var = max(0.0, sq / n - mean * mean)
    return math.sqrt(var)


class _Flow:
    __slots__ = ('proto', 'init_src', 'init_sport', 'dst_port', 'first_ts', 'last_ts',
                 'fwd', 'bwd', 'flow_iat_last', 'flow_iat_sum', 'flow_iat_sqsum',
                 'flow_iat_min', 'flow_iat_max', 'flow_iat_cnt',
                 'fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwe',
                 'all_len_min', 'all_len_max', 'all_len_sum', 'all_len_sqsum', 'all_cnt')

    def __init__(self, pv, ts):
        self.proto = pv['proto']
        self.init_src = pv['src']
        self.init_sport = pv['sport']
        self.dst_port = pv['dport']
        self.first_ts = ts
        self.last_ts = ts
        self.fwd = _DirStats()
        self.bwd = _DirStats()
        self.flow_iat_last = None
        self.flow_iat_sum = 0.0
        self.flow_iat_sqsum = 0.0
        self.flow_iat_min = None
        self.flow_iat_max = 0.0
        self.flow_iat_cnt = 0
        self.fin = self.syn = self.rst = self.psh = 0
        self.ack = self.urg = self.ece = self.cwe = 0
        self.all_len_min = None
        self.all_len_max = 0
        self.all_len_sum = 0
        self.all_len_sqsum = 0
        self.all_cnt = 0

    def add(self, pv, ts):
        self.last_ts = ts
        is_fwd = (pv['src'] == self.init_src and pv['sport'] == self.init_sport)
        (self.fwd if is_fwd else self.bwd).add(pv, ts)

        ln = pv['length']
        self.all_cnt += 1
        self.all_len_min = ln if self.all_len_min is None else min(self.all_len_min, ln)
        self.all_len_max = max(self.all_len_max, ln)
        self.all_len_sum += ln
        self.all_len_sqsum += ln * ln

        f = pv['flags']
        self.fin += f['F']; self.syn += f['S']; self.rst += f['R']; self.psh += f['P']
        self.ack += f['A']; self.urg += f['U']; self.ece += f['E']; self.cwe += f['C']

        if self.flow_iat_last is not None:
            iat = (ts - self.flow_iat_last) * 1e6
            if iat < 0:
                iat = 0.0
            self.flow_iat_sum += iat
            self.flow_iat_sqsum += iat * iat
            self.flow_iat_min = iat if self.flow_iat_min is None else min(self.flow_iat_min, iat)
            self.flow_iat_max = max(self.flow_iat_max, iat)
            self.flow_iat_cnt += 1
        self.flow_iat_last = ts

    def meta(self):
        a = 'fwd'
        return {
            'src': self.init_src, 'sport': self.init_sport,
            'proto': self.proto, 'dst_port': self.dst_port,
            'pkts': self.fwd.pkts + self.bwd.pkts,
        }

    def features(self):
        fwd, bwd = self.fwd, self.bwd
        dur_s = max(0.0, self.last_ts - self.first_ts)
        dur_us = dur_s * 1e6
        tot_pkts = fwd.pkts + bwd.pkts
        tot_bytes = fwd.bytes + bwd.bytes
        denom_s = dur_s if dur_s > 0 else 1e-6

        feats = {
            'dst_port': self.dst_port,
            'protocol': self.proto,
            'flow_duration': dur_us,
            'tot_fwd_pkts': fwd.pkts,
            'tot_bwd_pkts': bwd.pkts,
            'tot_len_fwd_pkts': fwd.bytes,
            'tot_len_bwd_pkts': bwd.bytes,
            'fwd_pkt_len_max': fwd.len_max,
            'fwd_pkt_len_min': fwd.len_min or 0,
            'fwd_pkt_len_mean': (fwd.len_sum / fwd.pkts) if fwd.pkts else 0,
            'fwd_pkt_len_std': _std(fwd.pkts, fwd.len_sum, fwd.len_sqsum),
            'bwd_pkt_len_max': bwd.len_max,
            'bwd_pkt_len_min': bwd.len_min or 0,
            'bwd_pkt_len_mean': (bwd.len_sum / bwd.pkts) if bwd.pkts else 0,
            'bwd_pkt_len_std': _std(bwd.pkts, bwd.len_sum, bwd.len_sqsum),
            'flow_byts_s': tot_bytes / denom_s,
            'flow_pkts_s': tot_pkts / denom_s,
            'flow_iat_mean': (self.flow_iat_sum / self.flow_iat_cnt) if self.flow_iat_cnt else 0,
            'flow_iat_std': _std(self.flow_iat_cnt, self.flow_iat_sum, self.flow_iat_sqsum),
            'flow_iat_max': self.flow_iat_max,
            'flow_iat_min': self.flow_iat_min or 0,
            'fwd_iat_tot': fwd.iat_sum,
            'fwd_iat_mean': (fwd.iat_sum / fwd.iat_cnt) if fwd.iat_cnt else 0,
            'fwd_iat_std': _std(fwd.iat_cnt, fwd.iat_sum, fwd.iat_sqsum),
            'fwd_iat_max': fwd.iat_max,
            'fwd_iat_min': fwd.iat_min or 0,
            'bwd_iat_tot': bwd.iat_sum,
            'bwd_iat_mean': (bwd.iat_sum / bwd.iat_cnt) if bwd.iat_cnt else 0,
            'bwd_iat_std': _std(bwd.iat_cnt, bwd.iat_sum, bwd.iat_sqsum),
            'bwd_iat_max': bwd.iat_max,
            'bwd_iat_min': bwd.iat_min or 0,
            'fwd_psh_flags': fwd.psh,
            'bwd_psh_flags': bwd.psh,
            'fwd_urg_flags': fwd.urg,
            'bwd_urg_flags': bwd.urg,
            'fwd_header_len': fwd.header_len,
            'bwd_header_len': bwd.header_len,
            'fwd_pkts_s': fwd.pkts / denom_s,
            'bwd_pkts_s': bwd.pkts / denom_s,
            'pkt_len_min': self.all_len_min or 0,
            'pkt_len_max': self.all_len_max,
            'pkt_len_mean': (self.all_len_sum / self.all_cnt) if self.all_cnt else 0,
            'pkt_len_std': _std(self.all_cnt, self.all_len_sum, self.all_len_sqsum),
            'pkt_len_var': _std(self.all_cnt, self.all_len_sum, self.all_len_sqsum) ** 2,
            'fin_flag_cnt': self.fin,
            'syn_flag_cnt': self.syn,
            'rst_flag_cnt': self.rst,
            'psh_flag_cnt': self.psh,
            'ack_flag_cnt': self.ack,
            'urg_flag_cnt': self.urg,
            'cwe_flag_cnt': self.cwe,
            'ece_flag_cnt': self.ece,
            'down_up_ratio': (bwd.bytes / fwd.bytes) if fwd.bytes else 0,
            'pkt_size_avg': (tot_bytes / tot_pkts) if tot_pkts else 0,
            'fwd_seg_size_avg': (fwd.seg_sum / fwd.pkts) if fwd.pkts else 0,
            'bwd_seg_size_avg': (bwd.seg_sum / bwd.pkts) if bwd.pkts else 0,
            'subflow_fwd_pkts': fwd.pkts,
            'subflow_fwd_byts': fwd.bytes,
            'subflow_bwd_pkts': bwd.pkts,
            'subflow_bwd_byts': bwd.bytes,
            'init_fwd_win_byts': fwd.win_init if fwd.win_init is not None else 0,
            'init_bwd_win_byts': bwd.win_init if bwd.win_init is not None else 0,
            'fwd_act_data_pkts': fwd.act_data_pkts,
            'fwd_seg_size_min': fwd.seg_min if fwd.seg_min is not None else 0,
        }
        return feats


class FlowTracker:
    """Thread-safe accumulator of bidirectional flows."""

    def __init__(self, max_flows=8000):
        self._flows = {}
        self._order = []
        self._max = max_flows
        self._lock = threading.Lock()

    def reset(self):
        with self._lock:
            self._flows.clear()
            self._order.clear()

    def add_packet(self, spkt, ts):
        pv = _packet_view(spkt)
        if pv is None:
            return
        a = (pv['src'], pv['sport'])
        b = (pv['dst'], pv['dport'])
        lo, hi = (a, b) if a <= b else (b, a)
        key = (pv['proto'], lo, hi)
        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                if len(self._order) >= self._max:
                    old = self._order.pop(0)
                    self._flows.pop(old, None)
                flow = _Flow(pv, ts)
                self._flows[key] = flow
                self._order.append(key)
            flow.add(pv, ts)

    def flow_count(self):
        with self._lock:
            return len(self._flows)

    def snapshot(self):
        """Return [(meta, feature_dict), ...] for all current flows."""
        with self._lock:
            flows = list(self._flows.values())
        out = []
        for fl in flows:
            try:
                out.append((fl.meta(), fl.features()))
            except Exception:
                continue
        return out
