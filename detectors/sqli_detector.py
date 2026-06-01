"""
SQL Injection Detector
Detects modern SQL injection attempts in HTTP traffic.

Detection Categories:
- Classic injection (UNION, OR 1=1, AND chains)
- Blind injection (time-based, boolean-based)
- Error-based injection
- Stacked queries
- NoSQL injection (MongoDB, CouchDB)
- Bypass techniques (comments, encoding, obfuscation)

SID Range: 1000040-1000049
"""

import re
import time
from urllib.parse import unquote, unquote_plus
from scapy.all import IP, TCP, Raw


class SQLiDetector:
    """Detects SQL injection patterns in HTTP payloads."""
    
    # SID assignments
    SID_SQLI_CLASSIC = 1000040
    SID_SQLI_UNION = 1000041
    SID_SQLI_BLIND_TIME = 1000042
    SID_SQLI_BLIND_BOOL = 1000043
    SID_SQLI_ERROR_BASED = 1000044
    SID_SQLI_STACKED = 1000045
    SID_SQLI_NOSQL = 1000046
    SID_SQLI_COMMENT_BYPASS = 1000047
    SID_SQLI_ENCODING_BYPASS = 1000048
    SID_SQLI_TAUTOLOGY = 1000049
    
    def __init__(self, emit_alert, sensitivity='moderate'):
        """
        Initialize SQL injection detector.
        
        Args:
            emit_alert: Callback function to emit alerts
            sensitivity: Detection sensitivity ('strict', 'moderate', 'loose')
        """
        self.emit_alert = emit_alert
        self.sensitivity = sensitivity
        
        # Alert cooldown tracking (per source IP)
        self.alert_cooldown = {}  # {(src_ip, sid): last_alert_time}
        self.COOLDOWN_SEC = 30
        self._current_pkt = None
        
        # Compile regex patterns for performance
        self._compile_patterns()
        
    def _compile_patterns(self):
        """Compile regex patterns for SQL injection detection."""
        
        # Classic SQLi patterns
        self.classic_patterns = [
            re.compile(r"(\bor\b|\|\|)\s*['\"]?\s*\d+\s*[=<>]+\s*\d+", re.IGNORECASE),  # OR 1=1
            re.compile(r"(\band\b|&&)\s*['\"]?\s*\d+\s*[=<>]+\s*\d+", re.IGNORECASE),  # AND 1=1
            re.compile(r"['\"]?\s*or\s*['\"]?\s*['\"]?\s*=\s*['\"]?", re.IGNORECASE),  # 'OR''='
            re.compile(r"admin['\"]?\s*(--|#|\/\*)", re.IGNORECASE),  # admin'--
        ]
        
        # UNION-based injection
        self.union_patterns = [
            re.compile(r"\bunion\b.*\bselect\b", re.IGNORECASE),
            re.compile(r"\/\*!?\d*union\*\/", re.IGNORECASE),  # /*!UNION*/
            re.compile(r"\bunion\b.*\ball\b.*\bselect\b", re.IGNORECASE),
        ]
        
        # Time-based blind SQLi
        self.time_blind_patterns = [
            re.compile(r"\b(sleep|benchmark|waitfor|pg_sleep)\s*\(", re.IGNORECASE),
            re.compile(r";\s*waitfor\s+delay\s+['\"]", re.IGNORECASE),
            re.compile(r"benchmark\s*\(\s*\d+", re.IGNORECASE),
        ]
        
        # Boolean-based blind SQLi
        self.bool_blind_patterns = [
            re.compile(r"\bif\s*\(\s*\d+\s*[=<>]", re.IGNORECASE),
            re.compile(r"\bcase\b.*\bwhen\b.*\bthen\b", re.IGNORECASE),
            re.compile(r"(ascii|ord|substring|substr)\s*\(.*\)\s*[=<>]", re.IGNORECASE),
        ]
        
        # Error-based SQLi
        self.error_patterns = [
            re.compile(r"(extractvalue|updatexml|exp)\s*\(", re.IGNORECASE),
            re.compile(r"convert\s*\(\s*int", re.IGNORECASE),
            re.compile(r"cast\s*\(.*\bas\b", re.IGNORECASE),
        ]
        
        # Stacked queries
        self.stacked_patterns = [
            re.compile(r";\s*(drop|insert|update|delete|create|alter)\b", re.IGNORECASE),
            re.compile(r";\s*exec\s*\(", re.IGNORECASE),
            re.compile(r";\s*declare\s+@", re.IGNORECASE),
        ]
        
        # NoSQL injection
        self.nosql_patterns = [
            re.compile(r"\$ne", re.IGNORECASE),
            re.compile(r"\$gt", re.IGNORECASE),
            re.compile(r"\$lt", re.IGNORECASE),
            re.compile(r"\$regex", re.IGNORECASE),
            re.compile(r"\$where", re.IGNORECASE),
            re.compile(r"\[\$", re.IGNORECASE),  # [$ne], [$gt], etc.
        ]
        
        # Comment-based bypass
        self.comment_patterns = [
            re.compile(r"\/\*!?\d*\w+\*\/", re.IGNORECASE),  # /*!50000SELECT*/
            re.compile(r"--[^\r\n]*", re.IGNORECASE),
            re.compile(r"#[^\r\n]*", re.IGNORECASE),
            re.compile(r"\/\*.*?\*\/", re.IGNORECASE),
        ]
        
        # Tautology-based
        self.tautology_patterns = [
            re.compile(r"['\"]?\s*or\s+['\"]?[a-z]+['\"]?\s*=\s*['\"]?[a-z]+", re.IGNORECASE),  # 'a'='a'
            re.compile(r"['\"]?\s*or\s+\d+\s*between\s+\d+\s*and\s*\d+", re.IGNORECASE),
        ]
        
        # SQL keywords for general detection
        self.sql_keywords = re.compile(
            r"\b(select|union|insert|update|delete|drop|create|alter|exec|execute|"
            r"declare|cast|convert|substring|ascii|char|concat|information_schema|"
            r"sys\.tables|sys\.columns|xp_cmdshell|sp_executesql)\b",
            re.IGNORECASE
        )
    
    def process(self, pkt, timestamp):
        """
        Process packet for SQL injection patterns.
        
        Args:
            pkt: Scapy packet object
            timestamp: Packet timestamp
        """
        # Only inspect HTTP traffic (TCP port 80, 8080, 443, etc.)
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        
        tcp = pkt[TCP]
        # Focus on common HTTP ports
        if tcp.dport not in [80, 8080, 8000, 443, 8443] and tcp.sport not in [80, 8080, 8000, 443, 8443]:
            return
        
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
        except:
            return
        
        # Only inspect HTTP requests (contains HTTP methods)
        if not self._is_http_request(payload):
            return
        
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"
        self._current_pkt = pkt
        
        # Decode URL encoding (multiple passes to catch double encoding)
        decoded_payload = self._deep_decode(payload)
        
        # Check for various SQLi patterns
        self._check_classic_sqli(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_union_sqli(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_time_blind(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_bool_blind(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_error_based(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_stacked_queries(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_nosql(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_comment_bypass(src_ip, dst_ip, decoded_payload, timestamp)
        self._check_encoding_bypass(src_ip, dst_ip, payload, decoded_payload, timestamp)
        self._check_tautology(src_ip, dst_ip, decoded_payload, timestamp)
    
    def _is_http_request(self, payload):
        """Check if payload is an HTTP request."""
        methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ']
        return any(payload.startswith(method) for method in methods)
    
    def _deep_decode(self, payload, max_depth=3):
        """Recursively decode URL encoding to detect bypass attempts."""
        decoded = payload
        for _ in range(max_depth):
            try:
                new_decoded = unquote_plus(unquote(decoded))
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            except:
                break
        return decoded
    
    def _can_alert(self, src_ip, sid):
        """Check if alert cooldown has expired."""
        key = (src_ip, sid)
        now = time.time()
        if key in self.alert_cooldown:
            if now - self.alert_cooldown[key] < self.COOLDOWN_SEC:
                return False
        self.alert_cooldown[key] = now
        return True
    
    def _check_classic_sqli(self, src_ip, dst_ip, payload, timestamp):
        """Detect classic SQL injection patterns."""
        for pattern in self.classic_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_SQLI_CLASSIC):
                    self.emit_alert(src_ip, dst_ip, self.SID_SQLI_CLASSIC, "SQL Injection - Classic pattern detected", self._current_pkt)
                break
    
    def _check_union_sqli(self, src_ip, dst_ip, payload, timestamp):
        """Detect UNION-based SQL injection."""
        for pattern in self.union_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_SQLI_UNION):
                    self.emit_alert(src_ip, dst_ip, self.SID_SQLI_UNION, "SQL Injection - UNION SELECT attack", self._current_pkt)
                break
    
    def _check_time_blind(self, src_ip, dst_ip, payload, timestamp):
        """Detect time-based blind SQL injection."""
        for pattern in self.time_blind_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_SQLI_BLIND_TIME):
                    self.emit_alert(src_ip, dst_ip, self.SID_SQLI_BLIND_TIME, "SQL Injection - Time-based blind attack", self._current_pkt)
                break
    
    def _check_bool_blind(self, src_ip, dst_ip, payload, timestamp):
        """Detect boolean-based blind SQL injection."""
        for pattern in self.bool_blind_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_SQLI_BLIND_BOOL):
                    self.emit_alert(src_ip, dst_ip, self.SID_SQLI_BLIND_BOOL, "SQL Injection - Boolean-based blind attack", self._current_pkt)
                break
    
    def _check_error_based(self, src_ip, dst_ip, payload, timestamp):
        """Detect error-based SQL injection."""
        for pattern in self.error_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_SQLI_ERROR_BASED):
                    self.emit_alert(src_ip, dst_ip, self.SID_SQLI_ERROR_BASED, "SQL Injection - Error-based attack", self._current_pkt)
                break
    
    def _check_stacked_queries(self, src_ip, dst_ip, payload, timestamp):
        """Detect stacked query injection."""
        for pattern in self.stacked_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_SQLI_STACKED):
                    self.emit_alert(src_ip, dst_ip, self.SID_SQLI_STACKED, "SQL Injection - Stacked queries attack", self._current_pkt)
                break
    
    def _check_nosql(self, src_ip, dst_ip, payload, timestamp):
        """Detect NoSQL injection patterns."""
        for pattern in self.nosql_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_SQLI_NOSQL):
                    self.emit_alert(src_ip, dst_ip, self.SID_SQLI_NOSQL, "NoSQL Injection - MongoDB/NoSQL attack", self._current_pkt)
                break
    
    def _check_comment_bypass(self, src_ip, dst_ip, payload, timestamp):
        """Detect SQL comment-based bypass techniques."""
        # Check for comments combined with SQL keywords
        if self.sql_keywords.search(payload):
            comment_count = sum(1 for p in self.comment_patterns if p.search(payload))
            if comment_count >= 2:  # Multiple comments suggest bypass attempt
                if self._can_alert(src_ip, self.SID_SQLI_COMMENT_BYPASS):
                    self.emit_alert(src_ip, dst_ip, self.SID_SQLI_COMMENT_BYPASS, "SQL Injection - Comment-based bypass", self._current_pkt)
    
    def _check_encoding_bypass(self, src_ip, dst_ip, original, decoded, timestamp):
        """Detect encoding-based bypass attempts."""
        # Skip if no difference between original and decoded
        if original == decoded:
            return
            
        # Check if decoding revealed classic SQLi patterns
        for pattern in self.classic_patterns:
            if pattern.search(decoded) and not pattern.search(original):
                if self._can_alert(src_ip, self.SID_SQLI_ENCODING_BYPASS):
                    self.emit_alert(src_ip, dst_ip, self.SID_SQLI_ENCODING_BYPASS, "SQL Injection - Encoding-based bypass (multiple encoding)", self._current_pkt)
                return
        
        # Check if decoded version has significantly more SQL keywords
        original_keywords = len(self.sql_keywords.findall(original))
        decoded_keywords = len(self.sql_keywords.findall(decoded))
        
        if decoded_keywords > original_keywords and decoded_keywords >= 2:
            if self._can_alert(src_ip, self.SID_SQLI_ENCODING_BYPASS):
                self.emit_alert(src_ip, dst_ip, self.SID_SQLI_ENCODING_BYPASS, "SQL Injection - Encoding-based bypass (multiple encoding)", self._current_pkt)
    
    def _check_tautology(self, src_ip, dst_ip, payload, timestamp):
        """Detect tautology-based SQL injection."""
        for pattern in self.tautology_patterns:
            if pattern.search(payload):
                if self._can_alert(src_ip, self.SID_SQLI_TAUTOLOGY):
                    self.emit_alert(src_ip, dst_ip, self.SID_SQLI_TAUTOLOGY, "SQL Injection - Tautology-based attack ('a'='a' pattern)", self._current_pkt)
                break
