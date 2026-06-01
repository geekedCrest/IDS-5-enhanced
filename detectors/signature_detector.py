# -*- coding: utf-8 -*-
"""Signature Detector Module

Handles Snort3-style signature matching and detection_filter aggregation.
Always enabled. Emits alerts via provided log callback.
"""
from collections import deque
import time
from scapy.all import IP
from typing import Deque, Dict, Callable, Any
from rules import match_rule
from signature import Signature

class SignatureDetector:
    def __init__(
        self,
        rules: list,
        seen_alerts: Dict[Any, float],
        rule_windows: Dict[Any, Deque[float]],
        log_callback: Callable[[Any, Signature], None],
        cooldown_seconds: float = 60.0,
        parent_analyzer=None,
    ):
        self.rules = rules
        self.seen_alerts = seen_alerts
        self.rule_windows = rule_windows
        self.log_callback = log_callback
        self.cooldown_seconds = cooldown_seconds
        self.parent_analyzer = parent_analyzer

    def process(self, pkt, ts: float):
        if pkt is None or not pkt.haslayer(IP):
            return
        for rule in self.rules:
            try:
                if match_rule(pkt, rule):
                    # detection_filter handling
                    df = getattr(rule, 'detection_filter', None)
                    if df and 'count' in df and 'seconds' in df:
                        track = df.get('track', 'by_src')
                        src_ip = pkt[IP].src if pkt.haslayer(IP) else 'unknown'
                        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else 'unknown'
                        if track == 'by_src':
                            track_key = src_ip
                        elif track == 'by_dst':
                            track_key = dst_ip
                        elif track == 'by_src_dst':
                            track_key = f"{src_ip}->{dst_ip}"
                        else:
                            track_key = getattr(rule, 'sid', 'rule')
                        now = time.time()
                        win_key = (rule.sid, track_key)
                        dq = self.rule_windows.setdefault(win_key, deque())
                        dq.append(now)
                        cutoff = now - df['seconds']
                        while dq and dq[0] < cutoff:
                            dq.popleft()
                        if len(dq) < df['count']:
                            continue
                    src_ip = pkt[IP].src if pkt.haslayer(IP) else 'unknown'
                    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else 'unknown'
                    if dst_ip.endswith('.255'):
                        continue  # ignore broadcast
                    key = (rule.sid, src_ip, dst_ip)
                    now_rule = time.time()
                    last = self.seen_alerts.get(key)
                    if last is None or (now_rule - last) >= self.cooldown_seconds:
                        self.seen_alerts[key] = now_rule
                        if self.parent_analyzer:
                            self.parent_analyzer.alert_count += 1
                        self.log_callback(pkt, rule)
            except Exception as e:
                print(f"[!] Rule match error (SID {getattr(rule,'sid','unknown')}): {e}")
