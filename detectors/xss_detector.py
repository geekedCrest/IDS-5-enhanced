"""
XSS (Cross-Site Scripting) Detector
Detects XSS injection attempts in HTTP traffic.

Detection Categories:
- Script tag injection (<script>, <iframe>, <object>)
- Event handler injection (onerror, onload, onclick)
- JavaScript protocol (javascript:, data:text/html)
- DOM-based XSS patterns
- Encoded/obfuscated XSS
- SVG-based XSS
- Template injection patterns
- Polyglot XSS

SID Range: 1000070-1000079
"""

import re
import time
from collections import deque
from urllib.parse import unquote, unquote_plus
from scapy.all import TCP, Raw


class XSSDetector:
    """Detects Cross-Site Scripting (XSS) patterns in HTTP payloads."""
    
    # SID assignments
    SID_XSS_SCRIPT_TAG = 1000070
    SID_XSS_EVENT_HANDLER = 1000071
    SID_XSS_JAVASCRIPT_PROTOCOL = 1000072
    SID_XSS_DOM_BASED = 1000073
    SID_XSS_ENCODED = 1000074
    SID_XSS_SVG_BASED = 1000075
    SID_XSS_IFRAME_EMBED = 1000076
    SID_XSS_ATTRIBUTE_BREAK = 1000077
    SID_XSS_TEMPLATE_INJECTION = 1000078
    SID_XSS_POLYGLOT = 1000079
    
    def __init__(self, emit_alert, sensitivity='moderate'):
        """
        Initialize XSS detector.
        
        Args:
            emit_alert: Callback function to emit alerts
            sensitivity: Detection sensitivity ('strict', 'moderate', 'loose')
        """
        self.emit_alert = emit_alert
        self.sensitivity = sensitivity
        
        # Alert cooldown tracking (per source IP and SID)
        self.alert_cooldown = {}  # {(src_ip, sid): last_alert_time}
        self.COOLDOWN_SEC = 60  # seconds between same alert type
        
        # Compile regex patterns for performance
        self._compile_patterns()
        
    def _compile_patterns(self):
        """Compile regex patterns for XSS detection."""
        
        # Script tag patterns
        self.script_patterns = [
            re.compile(r"<script[^>]*>", re.IGNORECASE),
            re.compile(r"</script>", re.IGNORECASE),
            re.compile(r"<script[^>]*src\s*=", re.IGNORECASE),
            re.compile(r"<script>\s*alert\s*\(", re.IGNORECASE),
            re.compile(r"<script>\s*eval\s*\(", re.IGNORECASE),
        ]
        
        # Event handler patterns
        self.event_patterns = [
            re.compile(r"\bon\w+\s*=\s*[\"']?\s*(alert|eval|confirm|prompt|javascript:)", re.IGNORECASE),
            re.compile(r"onerror\s*=", re.IGNORECASE),
            re.compile(r"onload\s*=", re.IGNORECASE),
            re.compile(r"onclick\s*=", re.IGNORECASE),
            re.compile(r"onmouseover\s*=", re.IGNORECASE),
            re.compile(r"onfocus\s*=", re.IGNORECASE),
            re.compile(r"onanimationend\s*=", re.IGNORECASE),
        ]
        
        # JavaScript protocol patterns
        self.javascript_protocol_patterns = [
            re.compile(r"javascript:\s*(alert|eval|confirm|prompt|window\.)", re.IGNORECASE),
            re.compile(r"data:text/html[,;]", re.IGNORECASE),
            re.compile(r"data:text/html;base64,", re.IGNORECASE),
            re.compile(r"vbscript:", re.IGNORECASE),
        ]
        
        # DOM-based XSS patterns
        self.dom_patterns = [
            re.compile(r"(document\.|window\.|location\.|eval\()", re.IGNORECASE),
            re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
            re.compile(r"\.outerHTML\s*=", re.IGNORECASE),
            re.compile(r"document\.write\s*\(", re.IGNORECASE),
            re.compile(r"\.location\s*=\s*[\"']javascript:", re.IGNORECASE),
        ]
        
        # Encoded XSS patterns (HTML entities, Unicode, hex)
        self.encoded_patterns = [
            re.compile(r"&#x?\d+;.*&#x?\d+;.*&#x?\d+;", re.IGNORECASE),  # Multiple entities
            re.compile(r"\\u00[3-7][0-9a-f]", re.IGNORECASE),  # Unicode escape
            re.compile(r"\\x[0-9a-f]{2}", re.IGNORECASE),  # Hex escape
            re.compile(r"%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}", re.IGNORECASE),  # URL encoding chains
            re.compile(r"&#60;script", re.IGNORECASE),  # &lt;script
            re.compile(r"&lt;script", re.IGNORECASE),
        ]
        
        # SVG-based XSS
        self.svg_patterns = [
            re.compile(r"<svg[^>]*onload\s*=", re.IGNORECASE),
            re.compile(r"<svg[^>]*>.*<script", re.IGNORECASE),
            re.compile(r"<animatetransform[^>]*onbegin\s*=", re.IGNORECASE),
            re.compile(r"<set[^>]*onbegin\s*=", re.IGNORECASE),
        ]
        
        # iframe/embed/object patterns
        self.iframe_patterns = [
            re.compile(r"<iframe[^>]*src\s*=", re.IGNORECASE),
            re.compile(r"<embed[^>]*src\s*=", re.IGNORECASE),
            re.compile(r"<object[^>]*data\s*=", re.IGNORECASE),
            re.compile(r"<iframe[^>]*srcdoc\s*=", re.IGNORECASE),
        ]
        
        # Attribute breaking patterns
        self.attribute_break_patterns = [
            re.compile(r"[\"']\s*>\s*<script", re.IGNORECASE),
            re.compile(r"[\"']\s*onerror\s*=", re.IGNORECASE),
            re.compile(r">\s*<img[^>]*src\s*=\s*x\s+onerror", re.IGNORECASE),
            re.compile(r"[\"']\s*autofocus\s+onfocus\s*=", re.IGNORECASE),
        ]
        
        # Template injection (server-side XSS)
        self.template_patterns = [
            re.compile(r"\{\{.*constructor.*\}\}", re.IGNORECASE),
            re.compile(r"\{\{.*\[.*\].*\}\}"),  # {{7*7}}
            re.compile(r"\$\{.*\}", re.IGNORECASE),  # ${7*7}
            re.compile(r"<%.*%>"),  # ASP-style
        ]
        
        # Polyglot XSS patterns (works across multiple contexts)
        self.polyglot_patterns = [
            re.compile(r"javascript:.*alert.*\(.*\)", re.IGNORECASE),
            re.compile(r"<.*onerror.*=.*alert.*\(", re.IGNORECASE),
            re.compile(r"'\s*\+\s*alert\s*\(", re.IGNORECASE),  # '+alert(
            re.compile(r"\"\s*\+\s*alert\s*\(", re.IGNORECASE),  # "+alert(
        ]
        
    def _deep_decode(self, payload: str, max_iterations: int = 3) -> str:
        """
        Recursively decode URL-encoded payloads to catch multi-encoded attacks.
        
        Args:
            payload: The payload to decode
            max_iterations: Maximum decoding iterations
            
        Returns:
            Decoded payload string
        """
        decoded = payload
        for _ in range(max_iterations):
            try:
                prev = decoded
                decoded = unquote_plus(unquote(decoded))
                if decoded == prev:
                    break
            except Exception:
                break
        return decoded
    
    def _can_alert(self, src_ip: str, sid: int, timestamp: float) -> bool:
        """
        Check if enough time has passed since last alert for this src_ip + SID.
        
        Args:
            src_ip: Source IP address
            sid: Signature ID
            timestamp: Current timestamp
            
        Returns:
            True if alert is allowed, False if in cooldown
        """
        key = (src_ip, sid)
        last_time = self.alert_cooldown.get(key, 0)
        if timestamp - last_time > self.COOLDOWN_SEC:
            self.alert_cooldown[key] = timestamp
            return True
        return False
    
    def process(self, pkt, timestamp: float):
        """
        Process a packet for XSS detection.
        
        Args:
            pkt: Scapy packet object
            timestamp: Packet timestamp
        """
        # Only process TCP packets with payload
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
        except Exception:
            return
        
        # Only check HTTP traffic (common web ports)
        tcp = pkt[TCP]
        web_ports = {80, 8080, 8000, 443, 8443, 3000, 5000, 8888, 9090}
        if tcp.dport not in web_ports and tcp.sport not in web_ports:
            return
        
        # Focus on HTTP requests (GET/POST)
        if not (payload.startswith('GET ') or payload.startswith('POST ')):
            return
        
        # Get source and destination IPs
        if pkt.haslayer('IP'):
            from scapy.all import IP as IPLayer
            src_ip = pkt[IPLayer].src
            dst_ip = pkt[IPLayer].dst
        else:
            return
        
        # Deep decode the payload
        decoded_payload = self._deep_decode(payload)
        
        # Run all detection checks
        self._check_script_tags(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_event_handlers(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_javascript_protocol(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_dom_based(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_encoded_xss(src_ip, dst_ip, payload, timestamp)  # Check original too
        self._check_svg_xss(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_iframe_embed(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_attribute_break(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_template_injection(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_polyglot(src_ip, dst_ip, decoded_payload, timestamp)
    
    def _check_script_tags(self, src_ip: str, dst_ip: str, payload: str, timestamp: float):
        """Check for script tag injection."""
        for pattern in self.script_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_XSS_SCRIPT_TAG, timestamp):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_XSS_SCRIPT_TAG,
                        "XSS: Script tag injection detected"
                    )
                    return
    
    def _check_event_handlers(self, src_ip: str, dst_ip: str, payload: str, timestamp: float):
        """Check for event handler injection."""
        for pattern in self.event_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_XSS_EVENT_HANDLER, timestamp):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_XSS_EVENT_HANDLER,
                        "XSS: Event handler injection detected"
                    )
                    return
    
    def _check_javascript_protocol(self, src_ip: str, dst_ip: str, payload: str, timestamp: float):
        """Check for javascript: protocol usage."""
        for pattern in self.javascript_protocol_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_XSS_JAVASCRIPT_PROTOCOL, timestamp):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_XSS_JAVASCRIPT_PROTOCOL,
                        "XSS: JavaScript protocol injection detected"
                    )
                    return
    
    def _check_dom_based(self, src_ip: str, dst_ip: str, payload: str, timestamp: float):
        """Check for DOM-based XSS patterns."""
        for pattern in self.dom_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_XSS_DOM_BASED, timestamp):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_XSS_DOM_BASED,
                        "XSS: DOM-based XSS pattern detected"
                    )
                    return
    
    def _check_encoded_xss(self, src_ip: str, dst_ip: str, payload: str, timestamp: float):
        """Check for encoded XSS attempts."""
        for pattern in self.encoded_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_XSS_ENCODED, timestamp):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_XSS_ENCODED,
                        "XSS: Encoded/obfuscated XSS detected"
                    )
                    return
    
    def _check_svg_xss(self, src_ip: str, dst_ip: str, payload: str, timestamp: float):
        """Check for SVG-based XSS."""
        for pattern in self.svg_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_XSS_SVG_BASED, timestamp):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_XSS_SVG_BASED,
                        "XSS: SVG-based XSS detected"
                    )
                    return
    
    def _check_iframe_embed(self, src_ip: str, dst_ip: str, payload: str, timestamp: float):
        """Check for iframe/embed/object injection."""
        for pattern in self.iframe_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_XSS_IFRAME_EMBED, timestamp):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_XSS_IFRAME_EMBED,
                        "XSS: iframe/embed injection detected"
                    )
                    return
    
    def _check_attribute_break(self, src_ip: str, dst_ip: str, payload: str, timestamp: float):
        """Check for attribute breaking XSS."""
        for pattern in self.attribute_break_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_XSS_ATTRIBUTE_BREAK, timestamp):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_XSS_ATTRIBUTE_BREAK,
                        "XSS: Attribute breaking XSS detected"
                    )
                    return
    
    def _check_template_injection(self, src_ip: str, dst_ip: str, payload: str, timestamp: float):
        """Check for template injection patterns."""
        for pattern in self.template_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_XSS_TEMPLATE_INJECTION, timestamp):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_XSS_TEMPLATE_INJECTION,
                        "XSS: Template injection detected"
                    )
                    return
    
    def _check_polyglot(self, src_ip: str, dst_ip: str, payload: str, timestamp: float):
        """Check for polyglot XSS patterns."""
        for pattern in self.polyglot_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_XSS_POLYGLOT, timestamp):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_XSS_POLYGLOT,
                        "XSS: Polyglot XSS payload detected"
                    )
                    return
