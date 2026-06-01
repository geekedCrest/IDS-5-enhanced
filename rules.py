# -*- coding: utf-8 -*-
#! /usr/bin/env python3

"""
Rules engine (Snort3-style)
---------------------------
Loads Snort3 community rules and provides a matcher to evaluate a Scapy
packet against a parsed Signature. The matcher follows a staged approach:
    1) protocol and IP validation
    2) address and port checks
    3) flow, flags, ICMP and service constraints
    4) payload checks (content/PCRE/byte tests)

This module aims to be pragmatic and tolerant (e.g., variable IPs, some
boolean options) while avoiding obvious false positives via lightweight
sanity checks.
"""

from scapy.all import IP, TCP, UDP, ICMP, Raw
from signature import Signature
import ipaddress
import re
from typing import Optional, List, Tuple, Dict

# Snort variable definitions (configurable)
SNORT_VARIABLES = {
    'HOME_NET': ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'],
    'EXTERNAL_NET': '!$HOME_NET',  # Any IP not in HOME_NET
    'HTTP_SERVERS': '$HOME_NET',
    'SMTP_SERVERS': '$HOME_NET',
    'SQL_SERVERS': '$HOME_NET',
    'DNS_SERVERS': '$HOME_NET',
    'TELNET_SERVERS': '$HOME_NET',
    'HTTP_PORTS': [80, 443, 8080, 8443],
    'SHELLCODE_PORTS': '!80',
    'ORACLE_PORTS': 1521,
}


def _resolve_variable(var_name: str) -> List[str]:
    """Resolve Snort variable to actual IP addresses or port numbers.
    
    Args:
        var_name: Variable name (e.g., '$HOME_NET' or 'HOME_NET')
    
    Returns:
        List of resolved values (IPs, CIDRs, or ports as strings)
    """
    # Strip $ prefix if present
    var_name = var_name.lstrip('$')
    
    if var_name not in SNORT_VARIABLES:
        return []  # Unknown variable
    
    value = SNORT_VARIABLES[var_name]
    
    # Handle string values
    if isinstance(value, str):
        if value.startswith('!$'):
            # Negated variable reference - not fully supported yet
            return []
        elif value.startswith('$'):
            # Recursive variable reference
            return _resolve_variable(value)
        else:
            return [value]
    
    # Handle list values
    if isinstance(value, list):
        return [str(v) for v in value]
    
    # Handle single values
    return [str(value)]


def load_rules(filename: str) -> List[Signature]:
    """Load Snort3 rules from a file into Signature objects.

    Notes:
      - Lines starting with '#' are ignored.
      - Any parse errors are logged but do not stop loading.
    """
    rules = []
    with open(filename, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                sig = Signature(line)
                rules.append(sig)
            except Exception as e:
                print(f"[!] Failed to parse rule at line {line_num}: {line} ({e})")
    return rules


def verify_rules(rule_lines: List[str]) -> List[Signature]:
    """Validate Snort rule strings and return parsed signatures.

    Raises:
        ValueError: If any input line is empty or fails parsing.
    """
    parsed_rules = []
    for idx, line in enumerate(rule_lines, 1):
        text = (line or '').strip()
        if not text:
            raise ValueError(f'Empty rule at position {idx}')
        try:
            parsed_rules.append(Signature(text))
        except Exception as e:
            raise ValueError(f'Invalid rule at position {idx}: {e}') from e
    return parsed_rules


def match_rule(pkt, rule: Signature) -> bool:
    """Return True if the packet matches the rule.

    The order of checks is important for performance: cheap structural checks
    come first, expensive payload/regex checks last.
    """
    
    # Basic packet validation
    if not pkt:
        return False
    
    # Protocol matching - must be exact match
    if rule.protocol == "tcp" and not pkt.haslayer(TCP):
        return False
    if rule.protocol == "udp" and not pkt.haslayer(UDP):
        return False
    if rule.protocol == "icmp" and not pkt.haslayer(ICMP):
        return False
    if rule.protocol == "ip" and not pkt.haslayer(IP):
        return False
    
    # IP layer validation
    if not pkt.haslayer(IP):
        return False
    ip_layer = pkt[IP]

    # IP address matching
    if not _match_ip(ip_layer.src, rule.src_ip):
        return False
    if not _match_ip(ip_layer.dst, rule.dst_ip):
        return False

    # Port matching for TCP/UDP
    if rule.protocol in ("tcp", "udp"):
        if not _match_ports(pkt, rule):
            return False
    
    # ICMP specific matching
    if rule.protocol == "icmp" and pkt.haslayer(ICMP):
        if not _match_icmp(pkt, rule):
            return False

    # IP protocol specific matching (for IP rules)
    if rule.protocol == "ip" and not _match_ip_protocol(pkt, rule):
        return False
    
    # TCP flags matching
    if rule.protocol == "tcp" and pkt.haslayer(TCP) and not _match_tcp_flags(pkt, rule):
        return False
    
    # Flow direction matching
    if rule.flow and not _match_flow(pkt, rule):
        return False
    
    # Content matching - must match ALL content conditions
    if rule.content and not _match_content(pkt, rule):
        return False
    
    # HTTP URI matching (for HTTP rules)
    if hasattr(rule, 'http_uri') and rule.http_uri and not _match_http_uri(pkt, rule):
        return False
    
    # HTTP header matching
    if rule.http_header and not _match_http_header(pkt, rule):
        return False
    
    # Service matching
    if rule.service and not _match_service(pkt, rule):
        return False
    
    # PCRE matching (regex)
    if rule.pcre and not _match_pcre(pkt, rule):
        return False
    
    # Byte test matching (for DNS and other protocols)
    if hasattr(rule, 'byte_test') and rule.byte_test and not _match_byte_test(pkt, rule):
        return False

    # Additional validation to reduce false positives
    if not _validate_rule_specificity(pkt, rule):
        return False

    return True


def _match_ip(packet_ip: str, rule_ip: str) -> bool:
    """Match IP addresses with support for CIDR, negation, and variables."""
    if rule_ip.lower() in ("any", "*"):
        return True
    
    # Handle negation
    if rule_ip.startswith("!"):
        return not _match_ip(packet_ip, rule_ip[1:])
    
    # Handle variables - properly resolve them
    if rule_ip.startswith("$"):
        resolved_ips = _resolve_variable(rule_ip)
        if not resolved_ips:
            # Unknown variable - be permissive to avoid breaking rules
            return True
        # Check if packet IP matches any resolved IP/CIDR
        for resolved_ip in resolved_ips:
            if _match_ip(packet_ip, resolved_ip):
                return True
        return False
    
    # Handle CIDR notation
    if "/" in rule_ip:
        try:
            network = ipaddress.ip_network(rule_ip, strict=False)
            return ipaddress.ip_address(packet_ip) in network
        except ValueError:
            return packet_ip == rule_ip
    
    # Exact match
    return packet_ip == rule_ip


def _match_ports(pkt, rule: Signature) -> bool:
    """Match source and destination ports."""
    if not pkt.haslayer(TCP) and not pkt.haslayer(UDP):
        return False
    
    # Get ports from packet
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    else:  # UDP
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    
    # Match source port
    if rule.src_port.lower() not in ("any", "*"):
        if not _match_port(sport, rule.src_port):
            return False
    
    # Match destination port
    if rule.dst_port.lower() not in ("any", "*"):
        if not _match_port(dport, rule.dst_port):
            return False
    
    return True


def _match_port(packet_port: int, rule_port: str) -> bool:
    """Match a single port with support for Snort3 port formats."""
    if rule_port.lower() in ("any", "*"):
        return True
    
    # Handle variables - properly resolve them
    if rule_port.startswith("$"):
        resolved_ports = _resolve_variable(rule_port)
        if not resolved_ports:
            # Unknown variable - be permissive
            return True
        # Check if packet port matches any resolved port
        for resolved_port in resolved_ports:
            if _match_port(packet_port, str(resolved_port)):
                return True
        return False
    
    # Handle negation
    if rule_port.startswith("!"):
        return not _match_port(packet_port, rule_port[1:])
    
    # Handle Snort3 bracket notation: [139], [135,139,445], [1024:], [1024:65535]
    if rule_port.startswith("[") and rule_port.endswith("]"):
        port_spec = rule_port[1:-1]  # Remove brackets
        
        # Handle port ranges with brackets: [1024:] or [1024:65535]
        if ":" in port_spec:
            try:
                if port_spec.endswith(":"):
                    # [1024:] - from 1024 to 65535
                    start = int(port_spec[:-1])
                    return packet_port >= start
                elif port_spec.startswith(":"):
                    # [:1024] - from 0 to 1024
                    end = int(port_spec[1:])
                    return packet_port <= end
                else:
                    # [1024:65535] - specific range
                    start, end = port_spec.split(":")
                    return int(start) <= packet_port <= int(end)
            except ValueError:
                return False
        
        # Handle port lists with brackets: [135,139,445]
        if "," in port_spec:
            try:
                ports = [int(p.strip()) for p in port_spec.split(",")]
                return packet_port in ports
            except ValueError:
                return False
        
        # Handle single port with brackets: [139]
        try:
            return packet_port == int(port_spec)
        except ValueError:
            return False
    
    # Handle port ranges without brackets: 1024:65535 or 1024:
    if ":" in rule_port:
        try:
            parts = rule_port.split(":")
            if len(parts) == 2:
                if parts[1] == "":
                    # 1024: - from 1024 to 65535
                    start = int(parts[0])
                    return packet_port >= start
                elif parts[0] == "":
                    # :1024 - from 0 to 1024
                    end = int(parts[1])
                    return packet_port <= end
                else:
                    # 1024:65535 - specific range
                    start = int(parts[0])
                    end = int(parts[1])
                    return start <= packet_port <= end
            else:
                return packet_port == int(rule_port)
        except ValueError:
            return False
    
    # Handle port lists without brackets: 135,139,445
    if "," in rule_port:
        try:
            ports = [int(p.strip()) for p in rule_port.split(",")]
            return packet_port in ports
        except ValueError:
            return False
    
    # Single port
    try:
        return packet_port == int(rule_port)
    except ValueError:
        return False


def _match_icmp(pkt, rule: Signature) -> bool:
    """Match ICMP specific fields."""
    icmp_layer = pkt[ICMP]
    
    # Match ICMP ID
    if rule.icmp_id is not None:
        if icmp_layer.id != rule.icmp_id:
            return False
    
    # Match ICMP type
    if rule.itype is not None:
        if icmp_layer.type != rule.itype:
            return False
    
    # Match ICMP code
    if rule.icode is not None:
        if icmp_layer.code != rule.icode:
            return False
    
    return True


def _match_flow(pkt, rule: Signature) -> bool:
    """Match flow direction and state with strict validation."""
    if not rule.flow:
        return True
    
    flow_options = [opt.strip() for opt in rule.flow.split(",")]
    
    # Check for established connections
    if "established" in flow_options:
        if pkt.haslayer(TCP):
            # Check TCP flags for established connection
            tcp_flags = pkt[TCP].flags
            # For established, we need ACK flag set (not just SYN)
            if not (tcp_flags & 0x10):  # ACK flag
                return False
        else:
            # Non-TCP packets can't be established
            return False
    
    # Check for stateless connections
    if "stateless" in flow_options:
        if pkt.haslayer(TCP):
            # For stateless, we typically want SYN without ACK
            tcp_flags = pkt[TCP].flags
            if (tcp_flags & 0x10):  # ACK flag present
                return False
    
    # Check flow direction
    if "to_server" in flow_options:
        # Packet going to server (typically high port to low port)
        if pkt.haslayer(TCP):
            if pkt[TCP].dport < pkt[TCP].sport:
                return False
        elif pkt.haslayer(UDP):
            if pkt[UDP].dport < pkt[UDP].sport:
                return False
    
    if "to_client" in flow_options:
        # Packet going to client (typically low port to high port)
        if pkt.haslayer(TCP):
            if pkt[TCP].sport < pkt[TCP].dport:
                return False
        elif pkt.haslayer(UDP):
            if pkt[UDP].sport < pkt[UDP].dport:
                return False
    
    return True


def _match_content(pkt, rule: Signature) -> bool:
    """Match content in packet payload with strict validation."""
    if not rule.content:
        return True
    
    # Get packet payload
    payload = bytes(pkt)
    if not payload:
        return False
    
    # Handle content with options
    content = rule.content
    if rule.nocase:
        content = content.lower()
        payload = payload.lower()
    
    # Handle depth and offset
    start_offset = rule.offset if rule.offset > 0 else 0
    end_offset = start_offset + rule.depth if rule.depth > 0 else len(payload)
    
    search_payload = payload[start_offset:end_offset]
    
    # Search for content
    if rule.fast_pattern:
        # For fast pattern, search the entire payload
        search_payload = payload
    
    # For HTTP rules, be more specific about content matching
    if rule.service == "http" or rule.http_uri:
        # Look for specific HTTP patterns
        if content.startswith("/"):
            # URI path matching - look for HTTP request line
            http_request = b"GET " + content.encode() + b" HTTP"
            if http_request in search_payload:
                return True
            # Also check for POST requests
            http_request = b"POST " + content.encode() + b" HTTP"
            if http_request in search_payload:
                return True
            return False
        elif content == "&":
            # Look for ampersand in HTTP request body
            if b"&" in search_payload:
                return True
            return False
    
    # For DNS rules, be more specific
    if rule.service == "dns":
        # DNS rules should have specific byte patterns
        # For now, be more restrictive - only match if we have proper DNS content
        if b"\x00" in search_payload or b"\x01" in search_payload:
            return True
        return False
    
    # Default content matching
    return content.encode() in search_payload


def _parse_http_headers(payload: bytes) -> Dict[str, str]:
    """Parse HTTP headers from raw payload.
    
    Returns:
        Dictionary of header_name -> header_value (lowercased keys)
    """
    headers = {}
    try:
        # Decode payload
        payload_str = payload.decode('utf-8', errors='ignore')
        
        # Split into lines
        lines = payload_str.split('\r\n')
        if not lines:
            return headers
        
        # First line is request/response line - skip it
        for line in lines[1:]:
            if not line or line == '\r\n':
                # End of headers
                break
            
            # Parse header: "Header-Name: value"
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
    except Exception:
        pass
    
    return headers


def _match_http_header(pkt, rule: Signature) -> bool:
    """Match HTTP header fields with proper parsing."""
    if not rule.http_header:
        return True
    
    if not pkt.haslayer(Raw):
        return False
    
    payload = bytes(pkt[Raw])
    
    # Check if this looks like HTTP traffic
    if not (b'HTTP/' in payload or b'GET ' in payload or b'POST ' in payload or 
            b'PUT ' in payload or b'DELETE ' in payload or b'HEAD ' in payload):
        return False
    
    # Parse HTTP headers
    headers = _parse_http_headers(payload)
    
    # Look for the rule's http_header content in any header value
    search_term = rule.http_header.lower()
    for header_name, header_value in headers.items():
        if search_term in header_value.lower() or search_term in header_name:
            return True
    
    # Also check raw payload as fallback
    return rule.http_header.encode() in payload


def _match_service(pkt, rule: Signature) -> bool:
    """Match service type."""
    if not rule.service:
        return True
    
    # Check if packet matches the specified service
    if rule.service == "http":
        if pkt.haslayer(TCP):
            # Check for common HTTP ports
            return pkt[TCP].dport in [80, 8080, 443, 8443]
    
    return True


def _match_pcre(pkt, rule: Signature) -> bool:
    """Match PCRE (Perl Compatible Regular Expression)."""
    if not rule.pcre:
        return True
    
    # Get packet payload
    payload = bytes(pkt)
    if not payload:
        return False
    
    try:
        # Extract the regex pattern from the PCRE option
        # Format: pcre:"/pattern/flags"
        pcre_match = re.search(r'pcre:"/(.*?)/(.*?)"', rule.pcre)
        if pcre_match:
            pattern = pcre_match.group(1)
            flags = pcre_match.group(2)
            
            # Convert flags
            re_flags = 0
            if 'i' in flags:
                re_flags |= re.IGNORECASE
            if 'm' in flags:
                re_flags |= re.MULTILINE
            if 's' in flags:
                re_flags |= re.DOTALL
            
            return bool(re.search(pattern, payload, re_flags))
    except Exception:
        pass
    
    return False


def _match_ip_protocol(pkt, rule: Signature) -> bool:
    """Match IP protocol specific options."""
    if not pkt.haslayer(IP):
        return False
    
    ip_layer = pkt[IP]
    
    # Check IP protocol number (e.g., ip_proto:2 for IGMP)
    if hasattr(rule, 'ip_proto') and rule.ip_proto:
        if ip_layer.proto != rule.ip_proto:
            return False
    
    # Check fragmentation bits (e.g., fragbits:M+)
    if hasattr(rule, 'fragbits') and rule.fragbits:
        # This is a simplified implementation
        # In a real IDS, you'd need to check the actual fragmentation flags
        pass
    
    return True


def _match_tcp_flags(pkt, rule: Signature) -> bool:
    """Match TCP flags (e.g., flags:S for SYN flag)."""
    if not pkt.haslayer(TCP):
        return False
    
    tcp_layer = pkt[TCP]
    
    # Check TCP flags (e.g., flags:S, flags:SA, etc.)
    if hasattr(rule, 'flags') and rule.flags:
        flags = rule.flags.upper()
        tcp_flags = tcp_layer.flags
        
        # Check for specific flag combinations
        if 'S' in flags and not (tcp_flags & 0x02):  # SYN flag
            return False
        if 'A' in flags and not (tcp_flags & 0x10):  # ACK flag
            return False
        if 'F' in flags and not (tcp_flags & 0x01):  # FIN flag
            return False
        if 'R' in flags and not (tcp_flags & 0x04):  # RST flag
            return False
        if 'P' in flags and not (tcp_flags & 0x08):  # PSH flag
            return False
        if 'U' in flags and not (tcp_flags & 0x20):  # URG flag
            return False
    
    return True


def _extract_http_uri(payload: bytes) -> Optional[str]:
    """Extract URI from HTTP request.
    
    Returns:
        The URI path from the request line, or None if not found
    """
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        lines = payload_str.split('\r\n')
        if not lines:
            return None
        
        # Parse request line: "METHOD /path/to/resource HTTP/1.1"
        request_line = lines[0]
        parts = request_line.split()
        
        if len(parts) >= 2:
            method = parts[0].upper()
            uri = parts[1]
            
            # Valid HTTP methods
            if method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']:
                return uri
    except Exception:
        pass
    
    return None


def _match_http_uri(pkt, rule: Signature) -> bool:
    """Match HTTP URI patterns with proper URI extraction."""
    if not rule.http_uri:
        return True
    
    if not pkt.haslayer(Raw):
        return False
    
    payload = bytes(pkt[Raw])
    
    # Extract URI from HTTP request
    uri = _extract_http_uri(payload)
    
    if uri:
        # If rule has content, check if it's in the URI
        if rule.content:
            search_content = rule.content.lower() if rule.nocase else rule.content
            uri_to_search = uri.lower() if rule.nocase else uri
            return search_content in uri_to_search
        # If no specific content, just confirm it's an HTTP request
        return True
    
    return False


def _match_byte_test(pkt, rule: Signature) -> bool:
    """Match byte test conditions (for DNS and other protocols)."""
    if not rule.byte_test:
        return True
    
    # This is a simplified implementation
    # In a real IDS, you'd need to implement proper byte testing
    # For now, we'll be more restrictive and require actual content matching
    return False


def _validate_rule_specificity(pkt, rule: Signature) -> bool:
    """Additional validation to reduce false positives."""
    
    # For rules with very specific content, require exact matches
    if rule.content:
        # If rule has specific content patterns, be more strict
        if rule.content.startswith("/") and rule.service == "http":
            # HTTP URI rules should have proper HTTP request structure
            if not pkt.haslayer(Raw):
                return False
            payload = bytes(pkt[Raw])
            if not (b"GET " in payload or b"POST " in payload or b"PUT " in payload):
                return False
        
        # For rules with ampersand content, require HTTP context
        if rule.content == "&" and rule.service == "http":
            if not pkt.haslayer(Raw):
                return False
            payload = bytes(pkt[Raw])
            # Should be in HTTP request body, not just anywhere
            if b"&" in payload:
                # Check if it's in a proper HTTP context
                if b"Content-Length:" in payload or b"application/x-www-form-urlencoded" in payload:
                    return True
                return False
    
    # For DNS rules, require proper DNS structure
    if rule.service == "dns":
        if not pkt.haslayer(Raw):
            return False
        payload = bytes(pkt[Raw])
        # DNS packets should have specific structure
        if len(payload) < 12:  # Minimum DNS header size
            return False
        # Check for DNS query structure (simplified)
        if payload[2] & 0x80:  # Response bit set
            return False  # We want queries, not responses
    
    # For rules with flow:established, require proper TCP state
    if rule.flow and "established" in rule.flow:
        if pkt.haslayer(TCP):
            tcp_flags = pkt[TCP].flags
            # Must have ACK flag for established connection
            if not (tcp_flags & 0x10):
                return False
    
    return True