"""
Remote Code Execution (RCE) and File Upload Attack Detector
Detects malicious file uploads and code execution attempts in HTTP traffic.

Detection Categories:
1. Malicious File Uploads (extensions, double extensions, null bytes)
2. Web Shell Uploads (PHP, JSP, ASP shells)
3. PHP Code Execution (eval, system, exec, shell_exec)
4. OS Command Injection (shell metacharacters, command chaining)
5. Python/Ruby/Perl/Node.js Code Execution
6. Deserialization Attacks (Java, PHP, Python pickle)
7. Template Injection (SSTI - Jinja2, Twig, Freemarker)
8. Expression Language Injection (EL, OGNL, SpEL)
9. XXE (XML External Entity) Injection
10. LDAP Injection

SID Range: 1000050-1000069
"""

import re
import time
from collections import deque
from urllib.parse import unquote, unquote_plus
from scapy.all import IP, TCP, Raw


class RCEDetector:
    """Detects remote code execution and file upload attacks in HTTP payloads."""
    
    # SID assignments (20 categories)
    SID_FILE_UPLOAD_MALICIOUS = 1000050
    SID_WEB_SHELL_UPLOAD = 1000051
    SID_PHP_CODE_EXEC = 1000052
    SID_COMMAND_INJECTION = 1000053
    SID_PYTHON_CODE_EXEC = 1000054
    SID_DESERIALIZATION = 1000055
    SID_TEMPLATE_INJECTION = 1000056
    SID_EXPRESSION_LANG = 1000057
    SID_XXE_INJECTION = 1000058
    SID_LDAP_INJECTION = 1000059
    SID_FILE_INCLUSION = 1000060
    SID_PATH_TRAVERSAL = 1000061
    SID_SHELL_SHOCK = 1000062
    SID_LOG4SHELL = 1000063
    SID_POLYGLOT_UPLOAD = 1000064
    SID_ASP_CODE_EXEC = 1000065
    SID_JSP_CODE_EXEC = 1000066
    SID_NODEJS_CODE_EXEC = 1000067
    SID_PERL_CODE_EXEC = 1000068
    SID_RUBY_CODE_EXEC = 1000069
    
    def __init__(self, emit_alert, sensitivity='moderate'):
        """
        Initialize RCE detector.
        
        Args:
            emit_alert: Callback function to emit alerts
            sensitivity: Detection sensitivity ('strict', 'moderate', 'loose')
        """
        self.emit_alert = emit_alert
        self.sensitivity = sensitivity
        
        # Alert cooldown tracking (per source IP, per SID)
        self.alert_cooldown = {}  # {(src_ip, sid): last_alert_time}
        
        # Compile detection patterns
        self._compile_patterns()
        
        # HTTP ports to monitor
        self.HTTP_PORTS = [80, 8080, 8000, 443, 8443, 3000, 5000, 8888, 9090]
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for performance."""
        
        # 1. Malicious file extensions
        self.malicious_extensions = re.compile(
            r'\.(php[3-7]?|phtml|jsp|jspx|aspx?|asa|cer|cdx|shtm|shtml|'
            r'exe|bat|cmd|sh|bash|zsh|ps1|vbs|dll|so|'
            r'py|rb|pl|cgi|war|ear|jar)\b',
            re.IGNORECASE
        )
        
        # Double extension bypass
        self.double_extension = re.compile(
            r'\.(php|jsp|asp|aspx|exe|sh)\.(?:jpg|jpeg|png|gif|txt|pdf)',
            re.IGNORECASE
        )
        
        # Null byte injection
        self.null_byte = re.compile(r'%00|\\x00|\x00')
        
        # 2. Web shell signatures
        self.webshell_patterns = [
            re.compile(r'<\?php.*(?:eval|system|exec|shell_exec|passthru|base64_decode)\s*\(', re.IGNORECASE | re.DOTALL),
            re.compile(r'(?:c99|r57|b374k|wso|shell|backdoor|webshell)', re.IGNORECASE),
            re.compile(r'FilesMan|WSO\s*Shell|C99Shell|R57Shell', re.IGNORECASE),
            re.compile(r'<%.*(?:eval|execute)\s*\(.*request', re.IGNORECASE | re.DOTALL),
        ]
        
        # 3. PHP code execution functions
        self.php_exec_patterns = [
            re.compile(r'\beval\s*\(', re.IGNORECASE),
            re.compile(r'\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(', re.IGNORECASE),
            re.compile(r'\b(?:assert|create_function|call_user_func(?:_array)?)\s*\(', re.IGNORECASE),
            re.compile(r'`[^`]*(?:ls|cat|whoami|id|pwd|wget|curl)', re.IGNORECASE),  # Backtick execution
            re.compile(r'\$_(?:GET|POST|REQUEST|COOKIE)\[.*\]\s*\(', re.IGNORECASE),  # Variable function
        ]
        
        # 4. OS Command injection
        self.command_injection_patterns = [
            re.compile(r'[;&|]\s*(?:ls|cat|whoami|id|pwd|uname|wget|curl|nc|netcat|bash|sh)\b', re.IGNORECASE),
            re.compile(r'(?:\||;|&&|\$\(|\`)\s*(?:cat|ls|rm|chmod|chown|kill|ps|ifconfig|netstat)', re.IGNORECASE),
            re.compile(r'/etc/passwd|/etc/shadow|/bin/bash|/bin/sh', re.IGNORECASE),
            re.compile(r'cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe', re.IGNORECASE),
        ]
        
        # 5. Python code execution
        self.python_exec_patterns = [
            re.compile(r'\b(?:__import__|eval|exec|compile|execfile|input)\s*\(', re.IGNORECASE),
            re.compile(r'os\.(?:system|popen|spawn|exec)', re.IGNORECASE),
            re.compile(r'subprocess\.(?:call|Popen|run|check_output)', re.IGNORECASE),
            re.compile(r'pickle\.loads?\(', re.IGNORECASE),
        ]
        
        # 6. Deserialization attacks
        self.deserialization_patterns = [
            re.compile(r'rO0AB|aced0005', re.IGNORECASE),  # Java serialization magic bytes (base64)
            re.compile(r'O:\d+:"', re.IGNORECASE),  # PHP object serialization
            re.compile(r'__reduce__|__setstate__', re.IGNORECASE),  # Python pickle
            re.compile(r'\.readObject\(|ObjectInputStream', re.IGNORECASE),
        ]
        
        # 7. Template injection (SSTI)
        self.template_injection_patterns = [
            re.compile(r'\{\{.*(?:config|self|request|lipsum|cycler|joiner|namespace)\b', re.IGNORECASE),
            re.compile(r'\{\{.*\.__(?:class|base|mro|subclasses|globals|init|import)__', re.IGNORECASE),
            re.compile(r'\$\{.*(?:Class|Runtime|ProcessBuilder)', re.IGNORECASE),
            re.compile(r'\{\{.*\|safe\}\}|\{\%.*\%\}', re.IGNORECASE),
        ]
        
        # 8. Expression Language injection
        self.expression_lang_patterns = [
            re.compile(r'\$\{(?:param|header|cookie|request)\.', re.IGNORECASE),
            re.compile(r'#(?:request|response|session|context)\[', re.IGNORECASE),
            re.compile(r'T\(java\.lang\.Runtime\)', re.IGNORECASE),
        ]
        
        # 9. XXE injection
        self.xxe_patterns = [
            re.compile(r'<!ENTITY\s+\w+\s+SYSTEM', re.IGNORECASE),
            re.compile(r'<!ENTITY.*file://', re.IGNORECASE),
            re.compile(r'<!DOCTYPE.*\[<!ENTITY', re.IGNORECASE),
        ]
        
        # 10. LDAP injection
        self.ldap_injection_patterns = [
            re.compile(r'\(\s*\|\s*\(', re.IGNORECASE),  # LDAP OR
            re.compile(r'\*\s*\)\s*\(', re.IGNORECASE),
            re.compile(r'\(\s*&\s*\(.*\)\s*\(.*objectClass=\*', re.IGNORECASE),
        ]
        
        # 11. File inclusion
        self.file_inclusion_patterns = [
            re.compile(r'(?:file|include|require|require_once|include_once)\s*\(\s*["\']?(?:http|ftp|php|data|expect|zip):', re.IGNORECASE),
            re.compile(r'(?:file|page|inc|module)=(?:http|ftp|php|data):', re.IGNORECASE),
            re.compile(r'php://(?:filter|input|stdin)', re.IGNORECASE),
            re.compile(r'data:text/plain;base64,', re.IGNORECASE),
        ]
        
        # 12. Path traversal
        self.path_traversal_patterns = [
            re.compile(r'\.\.[\\/]\.\.[\\/]', re.IGNORECASE),
            re.compile(r'(?:\.\.%2[fF]){2,}', re.IGNORECASE),
            re.compile(r'(?:\.\.%5[cC]){2,}', re.IGNORECASE),
            re.compile(r'%2e%2e[\\/]|\.\.%5c', re.IGNORECASE),
        ]
        
        # 13. ShellShock
        self.shellshock_patterns = [
            re.compile(r'\(\s*\)\s*\{\s*:;\s*\};', re.IGNORECASE),
            re.compile(r'\(\)\s*\{\s*ignored;\s*\}\s*;', re.IGNORECASE),
        ]
        
        # 14. Log4Shell
        self.log4shell_patterns = [
            re.compile(r'\$\{jndi:(?:ldap|rmi|dns)://', re.IGNORECASE),
            re.compile(r'\$\{jndi:\$\{lower:', re.IGNORECASE),
        ]
        
        # 15. Polyglot files (multiple formats in one)
        self.polyglot_patterns = [
            re.compile(rb'GIF89a.*<\?php', re.IGNORECASE | re.DOTALL),
            re.compile(rb'\xFF\xD8\xFF.*<\?php', re.IGNORECASE | re.DOTALL),  # JPEG + PHP
            re.compile(rb'%PDF.*<\?php', re.IGNORECASE | re.DOTALL),
        ]
        
        # 16. ASP/ASPX code execution
        self.asp_exec_patterns = [
            re.compile(r'<%.*(?:eval|execute|CreateObject|WScript\.Shell|Scripting\.FileSystemObject)', re.IGNORECASE | re.DOTALL),
            re.compile(r'Server\.(?:CreateObject|Execute|ScriptTimeout)', re.IGNORECASE),
        ]
        
        # 17. JSP code execution
        self.jsp_exec_patterns = [
            re.compile(r'<%.*(?:Runtime\.getRuntime|ProcessBuilder|exec)', re.IGNORECASE | re.DOTALL),
            re.compile(r'<jsp:(?:include|forward|plugin)', re.IGNORECASE),
        ]
        
        # 18. Node.js code execution
        self.nodejs_exec_patterns = [
            re.compile(r'require\s*\(\s*["\']child_process["\']\s*\)', re.IGNORECASE),
            re.compile(r'(?:spawn|exec|execSync|fork)\s*\(', re.IGNORECASE),
            re.compile(r'vm\.(?:runInNewContext|runInThisContext)', re.IGNORECASE),
        ]
        
        # 19. Perl code execution
        self.perl_exec_patterns = [
            re.compile(r'\beval\s*\{|system\s*\(|exec\s*\(|`', re.IGNORECASE),
            re.compile(r'open\s*\(.*\|', re.IGNORECASE),
        ]
        
        # 20. Ruby code execution
        self.ruby_exec_patterns = [
            re.compile(r'\beval\s*\(|system\s*\(|exec\s*\(|`', re.IGNORECASE),
            re.compile(r'IO\.popen|Open3\.|Kernel\.', re.IGNORECASE),
        ]
    
    def process(self, pkt, timestamp):
        """
        Process packet for RCE/file upload attack detection.
        
        Args:
            pkt: Scapy packet
            timestamp: Packet timestamp
        """
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        
        tcp = pkt[TCP]
        
        # Only inspect HTTP traffic
        if tcp.dport not in self.HTTP_PORTS and tcp.sport not in self.HTTP_PORTS:
            return
        
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
        except:
            return
        
        # Only check POST requests and multipart uploads (where attacks happen)
        if not payload.startswith('POST') and 'Content-Type' not in payload:
            return
        
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        
        # Deep decode URL/form data (up to 3 layers)
        decoded_payload = self._deep_decode(payload)
        
        # Run all detection checks
        self._check_malicious_file_upload(decoded_payload, payload, src_ip, pkt, timestamp)
        self._check_webshell_upload(decoded_payload, src_ip, pkt, timestamp)
        self._check_php_code_exec(decoded_payload, src_ip, pkt, timestamp)
        self._check_command_injection(decoded_payload, src_ip, pkt, timestamp)
        self._check_python_code_exec(decoded_payload, src_ip, pkt, timestamp)
        self._check_deserialization(decoded_payload, src_ip, pkt, timestamp)
        self._check_template_injection(decoded_payload, src_ip, pkt, timestamp)
        self._check_expression_lang(decoded_payload, src_ip, pkt, timestamp)
        self._check_xxe_injection(decoded_payload, src_ip, pkt, timestamp)
        self._check_ldap_injection(decoded_payload, src_ip, pkt, timestamp)
        self._check_file_inclusion(decoded_payload, src_ip, pkt, timestamp)
        self._check_path_traversal(decoded_payload, src_ip, pkt, timestamp)
        self._check_shellshock(decoded_payload, src_ip, pkt, timestamp)
        self._check_log4shell(decoded_payload, src_ip, pkt, timestamp)
        self._check_polyglot_upload(payload, src_ip, pkt, timestamp)
        self._check_asp_code_exec(decoded_payload, src_ip, pkt, timestamp)
        self._check_jsp_code_exec(decoded_payload, src_ip, pkt, timestamp)
        self._check_nodejs_code_exec(decoded_payload, src_ip, pkt, timestamp)
        self._check_perl_code_exec(decoded_payload, src_ip, pkt, timestamp)
        self._check_ruby_code_exec(decoded_payload, src_ip, pkt, timestamp)
    
    def _deep_decode(self, payload):
        """Recursively URL decode payload up to 3 times."""
        decoded = payload
        for _ in range(3):
            try:
                next_decode = unquote_plus(unquote(decoded))
                if next_decode == decoded:
                    break
                decoded = next_decode
            except:
                break
        return decoded
    
    def _can_alert(self, src_ip, sid):
        """Check if we can emit alert (cooldown enforcement)."""
        key = (src_ip, sid)
        now = time.time()
        
        # SID-specific cooldowns
        cooldown = 60  # Default 60 seconds
        if sid == self.SID_WEB_SHELL_UPLOAD:
            cooldown = 120  # Critical - longer cooldown
        elif sid in [self.SID_DESERIALIZATION, self.SID_LOG4SHELL, self.SID_SHELL_SHOCK]:
            cooldown = 90  # High-risk attacks
        
        if key in self.alert_cooldown:
            if now - self.alert_cooldown[key] < cooldown:
                return False
        
        self.alert_cooldown[key] = now
        return True

    def _emit_from_packet(self, pkt, sid, msg):
        """Emit an alert using the analyzer callback signature."""
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"
        self.emit_alert(src_ip, dst_ip, sid, msg, pkt)
    
    # Detection methods for each category
    
    def _check_malicious_file_upload(self, decoded, original, src_ip, pkt, timestamp):
        """Detect malicious file extensions."""
        if self.malicious_extensions.search(decoded) or self.double_extension.search(decoded) or self.null_byte.search(decoded):
            if self._can_alert(src_ip, self.SID_FILE_UPLOAD_MALICIOUS):
                self._emit_from_packet(pkt, self.SID_FILE_UPLOAD_MALICIOUS, "RCE - Malicious file upload detected")
    
    def _check_webshell_upload(self, decoded, src_ip, pkt, timestamp):
        """Detect web shell uploads."""
        for pattern in self.webshell_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_WEB_SHELL_UPLOAD):
                    self._emit_from_packet(pkt, self.SID_WEB_SHELL_UPLOAD, "RCE - Web shell upload detected")
                break
    
    def _check_php_code_exec(self, decoded, src_ip, pkt, timestamp):
        """Detect PHP code execution attempts."""
        for pattern in self.php_exec_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_PHP_CODE_EXEC):
                    self._emit_from_packet(pkt, self.SID_PHP_CODE_EXEC, "RCE - PHP code execution attempt")
                break
    
    def _check_command_injection(self, decoded, src_ip, pkt, timestamp):
        """Detect OS command injection."""
        for pattern in self.command_injection_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_COMMAND_INJECTION):
                    self._emit_from_packet(pkt, self.SID_COMMAND_INJECTION, "RCE - OS command injection detected")
                break
    
    def _check_python_code_exec(self, decoded, src_ip, pkt, timestamp):
        """Detect Python code execution."""
        for pattern in self.python_exec_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_PYTHON_CODE_EXEC):
                    self._emit_from_packet(pkt, self.SID_PYTHON_CODE_EXEC, "RCE - Python code execution attempt")
                break
    
    def _check_deserialization(self, decoded, src_ip, pkt, timestamp):
        """Detect deserialization attacks."""
        for pattern in self.deserialization_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_DESERIALIZATION):
                    self._emit_from_packet(pkt, self.SID_DESERIALIZATION, "RCE - Deserialization attack detected")
                break
    
    def _check_template_injection(self, decoded, src_ip, pkt, timestamp):
        """Detect SSTI attacks."""
        for pattern in self.template_injection_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_TEMPLATE_INJECTION):
                    self._emit_from_packet(pkt, self.SID_TEMPLATE_INJECTION, "RCE - Template injection (SSTI) detected")
                break
    
    def _check_expression_lang(self, decoded, src_ip, pkt, timestamp):
        """Detect Expression Language injection."""
        for pattern in self.expression_lang_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_EXPRESSION_LANG):
                    self._emit_from_packet(pkt, self.SID_EXPRESSION_LANG, "RCE - Expression Language injection")
                break
    
    def _check_xxe_injection(self, decoded, src_ip, pkt, timestamp):
        """Detect XXE attacks."""
        for pattern in self.xxe_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_XXE_INJECTION):
                    self._emit_from_packet(pkt, self.SID_XXE_INJECTION, "RCE - XXE injection detected")
                break
    
    def _check_ldap_injection(self, decoded, src_ip, pkt, timestamp):
        """Detect LDAP injection."""
        for pattern in self.ldap_injection_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_LDAP_INJECTION):
                    self._emit_from_packet(pkt, self.SID_LDAP_INJECTION, "RCE - LDAP injection detected")
                break
    
    def _check_file_inclusion(self, decoded, src_ip, pkt, timestamp):
        """Detect file inclusion (LFI/RFI)."""
        for pattern in self.file_inclusion_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_FILE_INCLUSION):
                    self._emit_from_packet(pkt, self.SID_FILE_INCLUSION, "RCE - File inclusion (LFI/RFI) detected")
                break
    
    def _check_path_traversal(self, decoded, src_ip, pkt, timestamp):
        """Detect path traversal attacks."""
        for pattern in self.path_traversal_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_PATH_TRAVERSAL):
                    self._emit_from_packet(pkt, self.SID_PATH_TRAVERSAL, "RCE - Path traversal detected")
                break
    
    def _check_shellshock(self, decoded, src_ip, pkt, timestamp):
        """Detect ShellShock attacks."""
        for pattern in self.shellshock_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_SHELL_SHOCK):
                    self._emit_from_packet(pkt, self.SID_SHELL_SHOCK, "RCE - ShellShock attack detected")
                break
    
    def _check_log4shell(self, decoded, src_ip, pkt, timestamp):
        """Detect Log4Shell attacks."""
        for pattern in self.log4shell_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_LOG4SHELL):
                    self._emit_from_packet(pkt, self.SID_LOG4SHELL, "RCE - Log4Shell (CVE-2021-44228) detected")
                break
    
    def _check_polyglot_upload(self, payload, src_ip, pkt, timestamp):
        """Detect polyglot file uploads (check raw bytes)."""
        # Convert string payload to bytes if needed
        if isinstance(payload, str):
            payload_bytes = payload.encode('latin1', errors='ignore')
        else:
            payload_bytes = payload
            
        for pattern in self.polyglot_patterns:
            if pattern.search(payload_bytes):
                if self._can_alert(src_ip, self.SID_POLYGLOT_UPLOAD):
                    self._emit_from_packet(pkt, self.SID_POLYGLOT_UPLOAD, "RCE - Polyglot file upload detected")
                break
    
    def _check_asp_code_exec(self, decoded, src_ip, pkt, timestamp):
        """Detect ASP/ASPX code execution."""
        for pattern in self.asp_exec_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_ASP_CODE_EXEC):
                    self._emit_from_packet(pkt, self.SID_ASP_CODE_EXEC, "RCE - ASP/ASPX code execution attempt")
                break
    
    def _check_jsp_code_exec(self, decoded, src_ip, pkt, timestamp):
        """Detect JSP code execution."""
        for pattern in self.jsp_exec_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_JSP_CODE_EXEC):
                    self._emit_from_packet(pkt, self.SID_JSP_CODE_EXEC, "RCE - JSP code execution attempt")
                break
    
    def _check_nodejs_code_exec(self, decoded, src_ip, pkt, timestamp):
        """Detect Node.js code execution."""
        for pattern in self.nodejs_exec_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_NODEJS_CODE_EXEC):
                    self._emit_from_packet(pkt, self.SID_NODEJS_CODE_EXEC, "RCE - Node.js code execution attempt")
                break
    
    def _check_perl_code_exec(self, decoded, src_ip, pkt, timestamp):
        """Detect Perl code execution."""
        for pattern in self.perl_exec_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_PERL_CODE_EXEC):
                    self._emit_from_packet(pkt, self.SID_PERL_CODE_EXEC, "RCE - Perl code execution attempt")
                break
    
    def _check_ruby_code_exec(self, decoded, src_ip, pkt, timestamp):
        """Detect Ruby code execution."""
        for pattern in self.ruby_exec_patterns:
            if pattern.search(decoded):
                if self._can_alert(src_ip, self.SID_RUBY_CODE_EXEC):
                    self._emit_from_packet(pkt, self.SID_RUBY_CODE_EXEC, "RCE - Ruby code execution attempt")
                break
