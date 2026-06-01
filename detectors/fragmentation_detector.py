"""
IP Fragmentation Attack Detector
Detects malicious IP fragmentation patterns and attacks.

Detection Categories:
- Overlapping fragments (Teardrop attack)
- Ping of Death (oversized reassembled packets)
- Fragment flooding (DoS)
- Tiny fragments (firewall evasion)
- Missing fragments (incomplete reassembly)
- Fragment offset anomalies

SID Range: 1000080-1000089
"""

import time
from collections import defaultdict, deque
from scapy.all import IP, ICMP


class FragmentationDetector:
    """Detects IP fragmentation attacks and anomalies."""
    
    # SID assignments
    SID_FRAG_OVERLAPPING = 1000080      # Teardrop attack
    SID_FRAG_PING_OF_DEATH = 1000081    # Oversized reassembled packet
    SID_FRAG_FLOOD = 1000082             # Fragment flooding DoS
    SID_FRAG_TINY = 1000083              # Tiny fragments (evasion)
    SID_FRAG_INVALID_OFFSET = 1000084   # Invalid fragment offset
    SID_FRAG_EXCESSIVE = 1000085         # Too many fragments per packet
    SID_FRAG_TIMEOUT = 1000086           # Incomplete reassembly (missing fragments)
    SID_FRAG_ZERO_LENGTH = 1000087       # Zero-length fragments
    SID_FRAG_DUPLICATE = 1000088         # Duplicate fragment IDs
    SID_FRAG_ANOMALY = 1000089           # General fragmentation anomaly
    
    def __init__(self, emit_alert, sensitivity='moderate'):
        """
        Initialize fragmentation detector.
        
        Args:
            emit_alert: Callback function to emit alerts (src, dst, sid, msg, pkt)
            sensitivity: Detection sensitivity ('strict', 'moderate', 'loose')
        """
        self.emit_alert = emit_alert
        self.sensitivity = sensitivity
        
        # Fragment reassembly tracking
        # {(src_ip, dst_ip, ip_id): {'fragments': [pkt1, pkt2...], 'first_seen': timestamp, 'total_size': int}}
        self.reassembly_buffer = {}
        
        # Fragment flood detection (track fragment timestamps per source)
        # Use plain dict to avoid pickling issues with default factories on Windows
        # {src_ip: deque([...])}
        self.fragment_rate = {}
        
        # Alert cooldown tracking
        self.alert_cooldown = {}  # {(src_ip, sid): last_alert_time}
        self.COOLDOWN_SEC = 30
        
        # Configuration based on sensitivity
        self._configure_thresholds()
        
        # Cleanup old reassembly buffers periodically
        self.last_cleanup = time.time()
        self.CLEANUP_INTERVAL = 60  # seconds
        
    def _configure_thresholds(self):
        """Configure detection thresholds based on sensitivity."""
        if self.sensitivity == 'strict':
            self.TINY_FRAGMENT_SIZE = 100      # bytes
            self.FRAGMENT_FLOOD_THRESHOLD = 50 # fragments per second
            self.MAX_FRAGMENTS_PER_PACKET = 20
            self.REASSEMBLY_TIMEOUT = 10       # seconds
        elif self.sensitivity == 'moderate':
            self.TINY_FRAGMENT_SIZE = 64
            self.FRAGMENT_FLOOD_THRESHOLD = 100
            self.MAX_FRAGMENTS_PER_PACKET = 50
            self.REASSEMBLY_TIMEOUT = 30
        else:  # loose
            self.TINY_FRAGMENT_SIZE = 32
            self.FRAGMENT_FLOOD_THRESHOLD = 200
            self.MAX_FRAGMENTS_PER_PACKET = 100
            self.REASSEMBLY_TIMEOUT = 60
    
    def _can_alert(self, src_ip: str, sid: int, timestamp: float) -> bool:
        """Check if enough time has passed since last alert for this src_ip + SID."""
        key = (src_ip, sid)
        last_time = self.alert_cooldown.get(key, 0)
        if timestamp - last_time > self.COOLDOWN_SEC:
            self.alert_cooldown[key] = timestamp
            return True
        return False
    
    def _cleanup_old_reassembly_buffers(self, current_time: float):
        """Remove old incomplete fragments from reassembly buffer."""
        if current_time - self.last_cleanup < self.CLEANUP_INTERVAL:
            return
        
        self.last_cleanup = current_time
        expired_keys = []
        
        for key, data in self.reassembly_buffer.items():
            age = current_time - data['first_seen']
            if age > self.REASSEMBLY_TIMEOUT:
                # Alert for incomplete reassembly (possible evasion)
                src_ip, dst_ip, ip_id = key
                if self._can_alert(src_ip, self.SID_FRAG_TIMEOUT, current_time):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_FRAG_TIMEOUT,
                        f"Fragmentation: Incomplete reassembly timeout (ID:{ip_id})"
                    )
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.reassembly_buffer[key]
    
    def process(self, pkt, timestamp: float):
        """
        Process a packet for fragmentation attack detection.
        
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
        self._cleanup_old_reassembly_buffers(timestamp)
        
        # Check if packet is fragmented
        # MF (More Fragments) flag = 1, or fragment offset > 0
        is_fragmented = bool(ip_layer.flags & 0x1) or (ip_layer.frag > 0)
        
        if not is_fragmented:
            return
        
        # Track fragment rate for flood detection
        self._check_fragment_flood(src_ip, timestamp)
        
        # Get fragment details
        ip_id = ip_layer.id
        frag_offset = ip_layer.frag * 8  # Offset is in 8-byte units
        more_fragments = bool(ip_layer.flags & 0x1)
        payload_len = len(ip_layer.payload) if ip_layer.payload else 0
        total_len = ip_layer.len
        
        # Check for zero-length fragments
        if payload_len == 0 and more_fragments:
            if self._can_alert(src_ip, self.SID_FRAG_ZERO_LENGTH, timestamp):
                self.emit_alert(
                    src_ip,
                    dst_ip,
                    self.SID_FRAG_ZERO_LENGTH,
                    "Fragmentation: Zero-length fragment detected"
                )
        
        # Check for tiny fragments (evasion technique)
        if payload_len > 0 and payload_len < self.TINY_FRAGMENT_SIZE:
            if self._can_alert(src_ip, self.SID_FRAG_TINY, timestamp):
                self.emit_alert(
                    src_ip,
                    dst_ip,
                    self.SID_FRAG_TINY,
                    f"Fragmentation: Tiny fragment detected ({payload_len} bytes)"
                )
        
        # Check for invalid fragment offset
        if frag_offset > 65535:
            if self._can_alert(src_ip, self.SID_FRAG_INVALID_OFFSET, timestamp):
                self.emit_alert(
                    src_ip,
                    dst_ip,
                    self.SID_FRAG_INVALID_OFFSET,
                    f"Fragmentation: Invalid fragment offset ({frag_offset})"
                )
        
        # Reassembly tracking
        key = (src_ip, dst_ip, ip_id)
        
        if key not in self.reassembly_buffer:
            self.reassembly_buffer[key] = {
                'fragments': [],
                'first_seen': timestamp,
                'total_size': 0,
                'offsets': set()
            }
        
        buffer = self.reassembly_buffer[key]
        buffer['fragments'].append({
            'offset': frag_offset,
            'length': payload_len,
            'more_fragments': more_fragments,
            'timestamp': timestamp
        })
        buffer['total_size'] += payload_len
        
        # Check for overlapping fragments (Teardrop attack)
        for existing_frag in buffer['fragments'][:-1]:  # Check against previous fragments
            existing_start = existing_frag['offset']
            existing_end = existing_start + existing_frag['length']
            new_start = frag_offset
            new_end = new_start + payload_len
            
            # Check if ranges overlap
            if (new_start < existing_end and new_end > existing_start):
                if self._can_alert(src_ip, self.SID_FRAG_OVERLAPPING, timestamp):
                    self.emit_alert(
                        src_ip,
                        dst_ip,
                        self.SID_FRAG_OVERLAPPING,
                        f"Fragmentation: Overlapping fragments detected (Teardrop attack, ID:{ip_id})"
                    )
                return
        
        # Check for duplicate fragment offsets
        if frag_offset in buffer['offsets']:
            if self._can_alert(src_ip, self.SID_FRAG_DUPLICATE, timestamp):
                self.emit_alert(
                    src_ip,
                    dst_ip,
                    self.SID_FRAG_DUPLICATE,
                    f"Fragmentation: Duplicate fragment offset detected (ID:{ip_id})"
                )
        buffer['offsets'].add(frag_offset)
        
        # Check for too many fragments per packet
        if len(buffer['fragments']) > self.MAX_FRAGMENTS_PER_PACKET:
            if self._can_alert(src_ip, self.SID_FRAG_EXCESSIVE, timestamp):
                self.emit_alert(
                    src_ip,
                    dst_ip,
                    self.SID_FRAG_EXCESSIVE,
                    f"Fragmentation: Excessive fragments ({len(buffer['fragments'])}) for single packet"
                )
        
        # Check for Ping of Death (total reassembled size > 65535)
        if buffer['total_size'] > 65535:
            if self._can_alert(src_ip, self.SID_FRAG_PING_OF_DEATH, timestamp):
                self.emit_alert(
                    src_ip,
                    dst_ip,
                    self.SID_FRAG_PING_OF_DEATH,
                    f"Fragmentation: Ping of Death detected ({buffer['total_size']} bytes)"
                )
        
        # If this is the last fragment, clean up the buffer
        if not more_fragments:
            del self.reassembly_buffer[key]
    
    def _check_fragment_flood(self, src_ip: str, timestamp: float):
        """Check for fragment flooding DoS attack."""
        # Initialize deque if first time seeing this source
        if src_ip not in self.fragment_rate:
            self.fragment_rate[src_ip] = deque(maxlen=100)
        # Add current fragment timestamp
        self.fragment_rate[src_ip].append(timestamp)
        
        # Get fragments in last second
        recent_fragments = [ts for ts in self.fragment_rate[src_ip] if timestamp - ts <= 1.0]
        
        if len(recent_fragments) > self.FRAGMENT_FLOOD_THRESHOLD:
            if self._can_alert(src_ip, self.SID_FRAG_FLOOD, timestamp):
                self.emit_alert(
                    src_ip,
                    "multiple",
                    self.SID_FRAG_FLOOD,
                    f"Fragmentation: Fragment flood detected ({len(recent_fragments)} frags/sec)"
                )
