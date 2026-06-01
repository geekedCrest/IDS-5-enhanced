# -*- coding: utf-8 -*-
"""
Detector Manager and Plugin Registry
-------------------------------------
Handles dynamic discovery, metadata extraction, loading, execution,
and error isolation for all security detectors in the detectors/ directory.
Supports both callback-based and background thread-based detectors.
"""

import os
import sys
import time
import queue
import importlib
import inspect
import threading
import logging
from typing import Dict, Any, List, Callable
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, Raw

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DetectorManager")

class DetectorManager:
    # Default metadata fallback mapping for pre-existing detectors
    METADATA_FALLBACK = {
        'ArpSpoofDetector': {
            'name': 'ARP Spoof Detector',
            'description': 'Detects ARP flooding, spoofing, and poisoning anomalies.',
            'severity': 'HIGH',
            'enabled': False
        },
        'BruteForceDetector': {
            'name': 'Brute Force Detector',
            'description': 'Detects SSH, RDP, FTP, SMTP, and HTTP brute-force credential attacks.',
            'severity': 'HIGH',
            'enabled': False
        },
        'DNSTunnelDetector': {
            'name': 'DNS Tunnel Detector',
            'description': 'Detects data exfiltration and Command & Control heartbeats in DNS queries.',
            'severity': 'MEDIUM',
            'enabled': False
        },
        'DosDetector': {
            'name': 'DoS/Scan Detector',
            'description': 'Detects SYN, UDP, and ICMP flood attacks, as well as distinct port scanning.',
            'severity': 'HIGH',
            'enabled': False
        },
        'FragmentationDetector': {
            'name': 'Fragmentation Detector',
            'description': 'Detects IP fragmentation anomalies, overlapping fragments, and teardrop attacks.',
            'severity': 'MEDIUM',
            'enabled': False
        },
        'RCEDetector': {
            'name': 'RCE Detector',
            'description': 'Detects Remote Code Execution and malicious file upload patterns in HTTP payloads.',
            'severity': 'CRITICAL',
            'enabled': False
        },
        'SQLiDetector': {
            'name': 'SQL Injection Detector',
            'description': 'Detects SQL Injection (SQLi) patterns and query manipulations in HTTP requests.',
            'severity': 'CRITICAL',
            'enabled': False
        },
        'SynScanDetector': {
            'name': 'SYN Scan Detector',
            'description': 'Detects SYN-only stealth port scans (such as nmap -sS) and distributed sweeps.',
            'severity': 'HIGH',
            'enabled': False
        },
        'XSSDetector': {
            'name': 'XSS Detector',
            'description': 'Detects Cross-Site Scripting (XSS) script tag, event handler, and polyglot injections.',
            'severity': 'CRITICAL',
            'enabled': False
        }
    }

    def __init__(self, detectors_dir: str, alert_callback: Callable[[str, Dict[str, Any]], None]):
        """
        Initialize the Detector Manager.
        
        Args:
            detectors_dir: Absolute path to the detectors directory.
            alert_callback: Callback invoked when a detector triggers an alert.
                            Signature: alert_callback(detector_name, alert_dict)
        """
        self.detectors_dir = detectors_dir
        self.alert_callback = alert_callback
        
        self.discovered_detectors: Dict[str, Dict[str, Any]] = {}
        self.active_instances: Dict[str, Any] = {}
        
        # Thread tracking for background-run detectors (ARP and SynScan)
        self.background_threads: Dict[str, threading.Thread] = {}
        self.background_events: Dict[str, threading.Event] = {}
        self.background_queues: Dict[str, queue.Queue] = {}

        # Add detectors path to sys.path
        if self.detectors_dir not in sys.path:
            sys.path.append(self.detectors_dir)

        self.discover_detectors()

    def discover_detectors(self):
        """Scan the detectors directory and load all valid security detector plugins."""
        logger.info(f"Scanning directory for detectors: {self.detectors_dir}")
        if not os.path.exists(self.detectors_dir):
            logger.error(f"Detectors directory not found: {self.detectors_dir}")
            return

        for filename in os.listdir(self.detectors_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                # Skip signature_detector as standard rules match inline in app.py
                if filename == "signature_detector.py":
                    continue
                    
                module_name = filename[:-3]
                try:
                    module = importlib.import_module(module_name)
                    # Search for detector classes inside the module
                    for class_name, obj in inspect.getmembers(module, inspect.isclass):
                        if obj.__module__ == module_name and (class_name.endswith("Detector") or class_name.endswith("SpoofDetector")):
                            self._register_detector(class_name, obj, module_name)
                except Exception as e:
                    logger.error(f"Failed to load detector module {module_name}: {e}")

    def _register_detector(self, class_name: str, cls_obj: Any, module_name: str):
        """Register a discovered detector with metadata."""
        # Get metadata from class fields, docstrings, or fallbacks
        fallback = self.METADATA_FALLBACK.get(class_name, {})
        
        name = getattr(cls_obj, "NAME", fallback.get("name", class_name))
        desc = inspect.getdoc(cls_obj) or fallback.get("description", "Dynamic security detector.")
        # Strip long description down to first line or summary
        if desc and "\n" in desc:
            desc = desc.split("\n")[0]
            
        severity = getattr(cls_obj, "SEVERITY", fallback.get("severity", "HIGH"))
        default_enabled = getattr(cls_obj, "ENABLED", fallback.get("enabled", True))
        
        self.discovered_detectors[class_name] = {
            'class_name': class_name,
            'module_name': module_name,
            'class_object': cls_obj,
            'name': name,
            'description': desc,
            'severity': severity,
            'enabled': default_enabled
        }
        
        logger.info(f"Discovered detector: {class_name} ({name}) - Enabled by default: {default_enabled}")

    def get_detectors_metadata(self) -> List[Dict[str, Any]]:
        """Return metadata list of all discovered detectors for the dashboard UI."""
        metadata = []
        for class_name, info in self.discovered_detectors.items():
            metadata.append({
                'id': class_name,
                'name': info['name'],
                'description': info['description'],
                'severity': info['severity'],
                'enabled': info['enabled']
            })
        return metadata

    def toggle_detector(self, class_name: str, enabled: bool) -> bool:
        """Enable or disable a detector dynamically."""
        if class_name not in self.discovered_detectors:
            logger.warning(f"Attempted to toggle unknown detector: {class_name}")
            return False
            
        info = self.discovered_detectors[class_name]
        prev_state = info['enabled']
        info['enabled'] = enabled
        
        if prev_state != enabled:
            logger.info(f"Toggled detector '{class_name}' to {'ENABLED' if enabled else 'DISABLED'}")
            if enabled:
                self._start_detector_instance(class_name)
            else:
                self._stop_detector_instance(class_name)
        return True

    def start_all_enabled(self):
        """Instantiate and start all detectors that are marked as enabled."""
        for class_name, info in self.discovered_detectors.items():
            if info['enabled']:
                self._start_detector_instance(class_name)

    def _start_detector_instance(self, class_name: str):
        """Instantiate a detector class and configure its execution context."""
        if class_name in self.active_instances:
            return  # Already running
            
        info = self.discovered_detectors[class_name]
        cls_obj = info['class_object']
        
        logger.info(f"Starting detector: {class_name}...")
        
        # Define uniform alert receiver
        def emit_alert_handler(src_ip, dst_ip, sid, msg, pkt=None):
            # Resolve threat based on message or detector default
            threat = info['severity']
            if 'critical' in msg.lower():
                threat = 'CRITICAL'
            elif 'high' in msg.lower():
                threat = 'HIGH'
            elif 'medium' in msg.lower():
                threat = 'MEDIUM'
            elif 'low' in msg.lower():
                threat = 'LOW'
                
            self.alert_callback(class_name, {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'sid': sid,
                'msg': msg,
                'threat': threat
            })

        try:
            # Check if this is a thread-based (originally Process-based) detector
            sig = inspect.signature(cls_obj.__init__)
            if 'task_queue' in sig.parameters and 'stop_event' in sig.parameters:
                # Handle queue + thread based detectors (ArpSpoofDetector, SynScanDetector)
                task_queue = queue.Queue()
                stop_event = threading.Event()
                
                # Instantiate detector (avoid starting as an OS Process!)
                inst = cls_obj(task_queue=task_queue, stop_event=stop_event)
                
                # Monkeypatch alert/log triggers
                if class_name == "ArpSpoofDetector":
                    self._patch_arp_detector(inst, emit_alert_handler)
                elif class_name == "SynScanDetector":
                    self._patch_synscan_detector(inst, emit_alert_handler)
                
                # Launch .run() inside a daemon Thread instead of a Process
                t = threading.Thread(target=inst.run, name=f"Thread-{class_name}", daemon=True)
                t.start()
                
                self.active_instances[class_name] = inst
                self.background_queues[class_name] = task_queue
                self.background_events[class_name] = stop_event
                self.background_threads[class_name] = t
                logger.info(f"Started thread-based detector {class_name} successfully.")
                
            else:
                # Handle packet-callback based detectors
                # Most accept (emit_alert) or (emit_alert, sensitivity)
                kwargs = {'emit_alert': emit_alert_handler}
                if 'sensitivity' in sig.parameters:
                    kwargs['sensitivity'] = 'moderate'
                
                inst = cls_obj(**kwargs)
                self.active_instances[class_name] = inst
                logger.info(f"Initialized callback-based detector {class_name} successfully.")
                
        except Exception as e:
            logger.error(f"Failed to start detector {class_name}: {e}")

    def _stop_detector_instance(self, class_name: str):
        """Stop and tear down a running detector instance."""
        if class_name not in self.active_instances:
            return
            
        logger.info(f"Stopping detector: {class_name}...")
        
        # Stop background thread if applicable
        if class_name in self.background_events:
            self.background_events[class_name].set()
            
        # Clean up references
        self.active_instances.pop(class_name, None)
        self.background_events.pop(class_name, None)
        self.background_queues.pop(class_name, None)
        self.background_threads.pop(class_name, None)
        logger.info(f"Stopped detector {class_name} successfully.")

    def _patch_arp_detector(self, inst: Any, alert_handler: Callable):
        """Monkeypatch ArpSpoofDetector alert handler to route into the dashboard."""
        def custom_alert(msg, pkt_list=None):
            # Run original log file writer
            inst._write_log(msg)
            # Route to dashboard
            threat = 'HIGH' if ('SPOOFING' in msg or 'FLOOD' in msg) else 'MEDIUM'
            alert_handler(
                src_ip="ARP Protocol",
                dst_ip="Local Network",
                sid=1000005,
                msg=msg
            )
        inst._alert = custom_alert

    def _patch_synscan_detector(self, inst: Any, alert_handler: Callable):
        """Monkeypatch SynScanDetector alert emitter to route into the dashboard."""
        def custom_emit_alert(src: str, dst: str, scan_type: str, count: int, ts: float):
            msg = (
                f"[ALERT] SYN-SCAN Detected (custom detector) "
                f"src={src} -> {dst} ports={count} window={inst.WINDOW_SEC}s "
                f"priority=HIGH type={scan_type}"
            )
            # Run original log file writer
            inst._write_log(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} {msg}")
            # Route to dashboard
            alert_handler(
                src_ip=src,
                dst_ip=dst,
                sid=1000013 if 'target' in scan_type else 1000014,
                msg=msg
            )
        inst._emit_alert = custom_emit_alert

    def process_packet(self, pkt: Any):
        """
        Process a Scapy packet through all active detectors with strict error isolation.
        
        Args:
            pkt: A parsed Scapy Packet object.
        """
        timestamp = time.time()
        
        for class_name, inst in list(self.active_instances.items()):
            # Verify if still enabled
            if not self.discovered_detectors[class_name]['enabled']:
                continue
                
            try:
                # 1. Thread-based detectors (ArpSpoofDetector, SynScanDetector)
                if class_name in self.background_queues:
                    # They expect raw packet bytes
                    pkt_bytes = bytes(pkt)
                    self.background_queues[class_name].put(pkt_bytes)
                    
                # 2. Callback-based detectors
                elif hasattr(inst, 'process'):
                    # Check method arguments
                    sig = inspect.signature(inst.process)
                    if 'timestamp' in sig.parameters:
                        inst.process(pkt, timestamp=timestamp)
                    elif 'ts' in sig.parameters:
                        inst.process(pkt, ts=timestamp)
                    else:
                        inst.process(pkt)
                        
            except Exception as e:
                logger.error(f"Error isolation: Detector '{class_name}' failed to process packet: {e}")

    def shutdown(self):
        """Gracefully shut down all background threads and processes."""
        logger.info("Shutting down Detector Manager...")
        for name in list(self.background_events.keys()):
            self._stop_detector_instance(name)
