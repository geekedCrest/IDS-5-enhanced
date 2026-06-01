# detectors/dns_tunnel_detector.py
# -*- coding: utf-8 -*-
#! /usr/bin/env python3
"""
DNS Tunnel Detection
Detects data exfiltration and command & control (C2) through DNS tunneling.

Detection Categories:
- Long domain names (data encoding)
- High entropy subdomains (compressed/encrypted data)
- Rapid repeated queries to same domain (C2 heartbeat)
- Suspicious query patterns (low-and-slow data transfer)
- Large TXT record responses (data exfiltration)

SID Range: 1000090-1000099
"""

import math
import time
from collections import defaultdict, deque
from typing import Tuple, List, Dict, Deque
from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR


class DNSTunnelDetector:
    """Detects DNS tunneling attacks and data exfiltration."""
    
    # SID assignments
    SID_DNS_LONG_DOMAIN = 1000090           # Long domain name (data encoding)
    SID_DNS_HIGH_ENTROPY = 1000091          # High entropy subdomain (compressed/encrypted)
    SID_DNS_RAPID_QUERIES = 1000092         # Rapid repeated queries to domain (C2 heartbeat)
    SID_DNS_SUSPICIOUS_PATTERN = 1000093    # Suspicious query pattern
    SID_DNS_LARGE_TXT = 1000094             # Large TXT record response (data exfiltration)
    SID_DNS_MANY_SUBDOMAINS = 1000095       # Many different subdomains under same domain
    SID_DNS_QUERY_RATE_FLOOD = 1000096      # DNS query rate flood
    SID_DNS_NULL_BYTE = 1000097              # Null bytes in DNS query (obfuscation)
    SID_DNS_UNUSUAL_PORTS = 1000098         # DNS on non-standard port
    SID_DNS_TUNNEL_ANOMALY = 1000099        # General DNS tunnel anomaly
    
    def __init__(self, emit_alert, sensitivity='moderate'):
        """
        Initialize DNS tunnel detector.
        
        Args:
            emit_alert: Callback function to emit alerts (src, dst, sid, msg)
            sensitivity: Detection sensitivity ('strict', 'moderate', 'loose')
        """
        self.emit_alert = emit_alert
        self.sensitivity = sensitivity
        
        # Domain timestamp tracking for query rate detection
        # {(src_ip, base_domain): deque([timestamp1, timestamp2, ...])}
        self.domain_queries = defaultdict(deque)
        
        # Subdomain tracking per domain
        # {base_domain: set([subdomain1, subdomain2, ...])}
        self.domain_subdomains = defaultdict(set)
        
        # Alert cooldown tracking
        # {(src_ip, sid): last_alert_time}
        self.alert_cooldown = {}
        self.COOLDOWN_SEC = 30
        
        # Configuration based on sensitivity
        self._configure_thresholds()
        
        # Cleanup tracking
        self.last_cleanup = time.time()
        self.CLEANUP_INTERVAL = 300  # 5 minutes
    
    def _configure_thresholds(self):
        """Configure detection thresholds based on sensitivity."""
        if self.sensitivity == 'strict':
            self.DOMAIN_LENGTH_THRESHOLD = 50
            self.DOMAIN_LENGTH_HIGH = 100
            self.ENTROPY_THRESHOLD = 4.0
            self.ENTROPY_HIGH = 4.5
            self.QUERY_RATE_THRESHOLD = 10      # queries per 10 seconds
            self.QUERY_RATE_WINDOW = 10
            self.SUBDOMAIN_COUNT_THRESHOLD = 20
            self.TXT_SIZE_THRESHOLD = 100
        elif self.sensitivity == 'moderate':
            self.DOMAIN_LENGTH_THRESHOLD = 80
            self.DOMAIN_LENGTH_HIGH = 150
            self.ENTROPY_THRESHOLD = 3.8
            self.ENTROPY_HIGH = 4.5
            self.QUERY_RATE_THRESHOLD = 20      # queries per 10 seconds
            self.QUERY_RATE_WINDOW = 10
            self.SUBDOMAIN_COUNT_THRESHOLD = 50
            self.TXT_SIZE_THRESHOLD = 200
        else:  # loose
            self.DOMAIN_LENGTH_THRESHOLD = 120
            self.DOMAIN_LENGTH_HIGH = 200
            self.ENTROPY_THRESHOLD = 3.5
            self.ENTROPY_HIGH = 4.2
            self.QUERY_RATE_THRESHOLD = 50      # queries per 10 seconds
            self.QUERY_RATE_WINDOW = 10
            self.SUBDOMAIN_COUNT_THRESHOLD = 100
            self.TXT_SIZE_THRESHOLD = 500
    
    def _entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        
        # Filter to alphanumeric only
        filtered = [c for c in s.lower() if c.isalnum()]
        if not filtered:
            return 0.0
        
        length = len(filtered)
        freq = {}
        for c in filtered:
            freq[c] = freq.get(c, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _get_base_domain(self, qname: str) -> str:
        """Extract base domain (last 2 labels) from FQDN."""
        parts = qname.rstrip('.').split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return qname
    
    def _can_alert(self, src_ip: str, sid: int, timestamp: float) -> bool:
        """Check if enough time has passed since last alert for this src_ip + SID."""
        key = (src_ip, sid)
        last_time = self.alert_cooldown.get(key, 0)
        if timestamp - last_time > self.COOLDOWN_SEC:
            self.alert_cooldown[key] = timestamp
            return True
        return False
    
    def _cleanup_old_data(self, current_time: float):
        """Clean up old entries from tracking dictionaries."""
        if current_time - self.last_cleanup < self.CLEANUP_INTERVAL:
            return
        
        self.last_cleanup = current_time
        cutoff_time = current_time - (self.QUERY_RATE_WINDOW * 3)  # Keep 3x window
        
        # Remove old domain queries
        for key in list(self.domain_queries.keys()):
            dq = self.domain_queries[key]
            while dq and dq[0] < cutoff_time:
                dq.popleft()
            if not dq:
                del self.domain_queries[key]
    
    def process(self, pkt, timestamp: float):
        """
        Process a packet for DNS tunnel detection.
        
        Args:
            pkt: Scapy packet object
            timestamp: Packet timestamp
        """
        # Only process IP packets
        if not pkt.haslayer(IP):
            return
        
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Periodic cleanup
        self._cleanup_old_data(timestamp)
        
        # Check for DNS (port 53 on UDP/TCP)
        if pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            if udp_layer.dport != 53 and udp_layer.sport != 53:
                return
        elif pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            if tcp_layer.dport != 53 and tcp_layer.sport != 53:
                return
        else:
            return
        
        # Extract DNS layer
        if not pkt.haslayer(DNS):
            return
        
        dns = pkt[DNS]
        
        # Only analyze DNS queries (qr=0)
        if dns.qr != 0 or dns.qd is None:
            # Check DNS responses for large TXT records (data exfiltration)
            self._check_dns_response(pkt, dns, src_ip, dst_ip, timestamp)
            return
        
        # Extract query name
        try:
            qname_bytes = dns.qd.qname
            qname = qname_bytes.decode(errors='ignore') if isinstance(qname_bytes, bytes) else str(qname_bytes)
            qname = qname.rstrip('.')
        except Exception:
            return
        
        base_domain = self._get_base_domain(qname)
        labels = qname.split('.')
        
        # Check for various tunneling indicators
        self._check_domain_length(src_ip, dst_ip, qname, timestamp)
        self._check_entropy(src_ip, dst_ip, labels, qname, timestamp)
        self._check_query_rate(src_ip, dst_ip, base_domain, timestamp)
        self._check_subdomain_count(src_ip, dst_ip, base_domain, qname, timestamp)
        self._check_null_bytes(src_ip, dst_ip, qname, timestamp)
    
    def _check_domain_length(self, src_ip: str, dst_ip: str, qname: str, timestamp: float):
        """Check for suspiciously long domain names (data encoding)."""
        length = len(qname)
        
        if length >= self.DOMAIN_LENGTH_HIGH:
            if self._can_alert(src_ip, self.SID_DNS_LONG_DOMAIN, timestamp):
                msg = f"DNS Tunnel: Unusually long domain name ({length} chars): {qname[:50]}..."
                self.emit_alert(src_ip, dst_ip, self.SID_DNS_LONG_DOMAIN, msg)
        elif length >= self.DOMAIN_LENGTH_THRESHOLD:
            if self._can_alert(src_ip, self.SID_DNS_LONG_DOMAIN, timestamp):
                msg = f"DNS Tunnel: Long domain name ({length} chars): {qname[:60]}"
                self.emit_alert(src_ip, dst_ip, self.SID_DNS_LONG_DOMAIN, msg)
    
    def _check_entropy(self, src_ip: str, dst_ip: str, labels: List[str], qname: str, timestamp: float):
        """Check for high entropy in subdomains (compressed/encrypted data)."""
        if not labels:
            return
        
        # Check first label (most likely to contain encoded data)
        first_label = labels[0]
        ent = self._entropy(first_label)
        
        if ent >= self.ENTROPY_HIGH:
            if self._can_alert(src_ip, self.SID_DNS_HIGH_ENTROPY, timestamp):
                msg = f"DNS Tunnel: Very high entropy subdomain (entropy={ent:.2f}): {first_label}"
                self.emit_alert(src_ip, dst_ip, self.SID_DNS_HIGH_ENTROPY, msg)
        elif ent >= self.ENTROPY_THRESHOLD:
            if self._can_alert(src_ip, self.SID_DNS_HIGH_ENTROPY, timestamp):
                msg = f"DNS Tunnel: High entropy subdomain (entropy={ent:.2f}): {first_label}"
                self.emit_alert(src_ip, dst_ip, self.SID_DNS_HIGH_ENTROPY, msg)
    
    def _check_query_rate(self, src_ip: str, dst_ip: str, base_domain: str, timestamp: float):
        """Check for rapid repeated queries to same domain (C2 heartbeat)."""
        key = (src_ip, base_domain)
        dq = self.domain_queries[key]
        dq.append(timestamp)
        
        # Remove old timestamps outside window
        cutoff = timestamp - self.QUERY_RATE_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()
        
        # Check if rate exceeds threshold
        if len(dq) >= self.QUERY_RATE_THRESHOLD:
            if self._can_alert(src_ip, self.SID_DNS_RAPID_QUERIES, timestamp):
                msg = f"DNS Tunnel: Rapid repeated queries to {base_domain} ({len(dq)} in {self.QUERY_RATE_WINDOW}s)"
                self.emit_alert(src_ip, dst_ip, self.SID_DNS_RAPID_QUERIES, msg)
    
    def _check_subdomain_count(self, src_ip: str, dst_ip: str, base_domain: str, qname: str, timestamp: float):
        """Check for many different subdomains under same domain (data tunneling)."""
        self.domain_subdomains[base_domain].add(qname)
        
        count = len(self.domain_subdomains[base_domain])
        if count >= self.SUBDOMAIN_COUNT_THRESHOLD:
            if self._can_alert(src_ip, self.SID_DNS_MANY_SUBDOMAINS, timestamp):
                msg = f"DNS Tunnel: Many subdomains under {base_domain} ({count} unique subdomains)"
                self.emit_alert(src_ip, dst_ip, self.SID_DNS_MANY_SUBDOMAINS, msg)
    
    def _check_null_bytes(self, src_ip: str, dst_ip: str, qname: str, timestamp: float):
        """Check for null bytes in DNS queries (obfuscation technique)."""
        if '\x00' in qname:
            if self._can_alert(src_ip, self.SID_DNS_NULL_BYTE, timestamp):
                msg = f"DNS Tunnel: Null bytes detected in DNS query"
                self.emit_alert(src_ip, dst_ip, self.SID_DNS_NULL_BYTE, msg)
    
    def _check_dns_response(self, pkt, dns, src_ip: str, dst_ip: str, timestamp: float):
        """Check DNS responses for large TXT records (data exfiltration)."""
        try:
            if dns.an is None:
                return
            
            # Check answer records for TXT responses
            an = dns.an
            while an:
                if hasattr(an, 'type') and an.type == 16:  # TXT record type
                    # Check TXT record size
                    if hasattr(an, 'rdata'):
                        rdata_size = len(str(an.rdata)) if an.rdata else 0
                        if rdata_size >= self.TXT_SIZE_THRESHOLD:
                            if self._can_alert(src_ip, self.SID_DNS_LARGE_TXT, timestamp):
                                msg = f"DNS Tunnel: Large TXT record response ({rdata_size} bytes) from {dst_ip}"
                                self.emit_alert(src_ip, dst_ip, self.SID_DNS_LARGE_TXT, msg)
                
                an = an.payload if hasattr(an, 'payload') else None
        except Exception:
            pass
