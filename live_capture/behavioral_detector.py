"""
Real-time Behavioral Threat Detector.

Works alongside the ML classifier by analyzing aggregate traffic patterns
to detect attacks that individual flow classification might miss:
- DDoS/HTTP Flood: Abnormally high outbound flow rate from source
- Port Scan: Flows to many different destination IPs in a short window
- Brute Force: Repeated connections to authentication ports (21, 22, 23, 3389)
"""
import time
from collections import defaultdict
from utils.logger import get_logger

log = get_logger(__name__)

# Auth-related ports for brute force detection
AUTH_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 993, 995, 3306, 3389, 5432, 5900}


class BehavioralDetector:
    """Sliding-window behavioral analysis for live traffic."""

    def __init__(self, window_seconds=30):
        self.window = window_seconds
        # src_ip -> list of timestamps (total outbound rate)
        self.src_flow_times = defaultdict(list)
        # src_ip -> set of distinct dst_ips contacted
        self.src_dst_ips_seen = defaultdict(set)
        # dest_ip -> list of timestamps
        self.dest_flow_times = defaultdict(list)
        # dest_ip -> set of dest_ports
        self.dest_ports_seen = defaultdict(set)
        # dest_ip:dest_port -> list of timestamps (for auth ports only)
        self.auth_attempts = defaultdict(list)

    def _prune(self, timestamps: list) -> list:
        """Remove entries older than the sliding window."""
        cutoff = time.time() - self.window
        return [t for t in timestamps if t > cutoff]

    def analyze(self, src_ip: str, dst_ip: str, dst_port: int) -> dict:
        """
        Analyze a flow and return behavioral detection results.
        Returns dict with:
          - behavioral_attack: str or None (attack type name)
          - behavioral_confidence: float 0-1
          - behavioral_reason: str (human-readable explanation)
        """
        now = time.time()

        # --- Update sliding windows ---
        # Track outbound rate from source
        self.src_flow_times[src_ip].append(now)
        self.src_flow_times[src_ip] = self._prune(self.src_flow_times[src_ip])
        self.src_dst_ips_seen[src_ip].add(dst_ip)

        # Track per-destination
        self.dest_flow_times[dst_ip].append(now)
        self.dest_flow_times[dst_ip] = self._prune(self.dest_flow_times[dst_ip])
        self.dest_ports_seen[dst_ip].add(dst_port)

        if dst_port in AUTH_PORTS:
            key = f"{dst_ip}:{dst_port}"
            self.auth_attempts[key].append(now)
            self.auth_attempts[key] = self._prune(self.auth_attempts[key])

        # --- Detection Rules ---

        # 1. HTTP Flood / DDoS: High outbound rate from a single source
        #    >40 flows from same source in the window = flood
        src_flow_count = len(self.src_flow_times[src_ip])
        if src_flow_count >= 40:
            confidence = min(src_flow_count / 80.0, 1.0)
            return {
                "behavioral_attack": "HTTP_Flood",
                "behavioral_confidence": confidence,
                "behavioral_reason": f"DDoS: {src_flow_count} outbound flows from {src_ip} in {self.window}s"
            }

        # 2. Port Scan: Many distinct destination IPs from same source
        #    >12 different IPs contacted = scanning
        dst_ip_count = len(self.src_dst_ips_seen[src_ip])
        if dst_ip_count >= 12:
            confidence = min(dst_ip_count / 25.0, 1.0)
            return {
                "behavioral_attack": "Port_Scan",
                "behavioral_confidence": confidence,
                "behavioral_reason": f"Scan: {dst_ip_count} distinct hosts contacted by {src_ip}"
            }

        # 3. Brute Force: Repeated connections to auth ports
        if dst_port in AUTH_PORTS:
            key = f"{dst_ip}:{dst_port}"
            auth_count = len(self.auth_attempts[key])
            if auth_count >= 10:
                confidence = min(auth_count / 30.0, 1.0)
                return {
                    "behavioral_attack": "Brute_Force",
                    "behavioral_confidence": confidence,
                    "behavioral_reason": f"Brute Force: {auth_count} auth attempts to {dst_ip}:{dst_port}"
                }

        return {
            "behavioral_attack": None,
            "behavioral_confidence": 0.0,
            "behavioral_reason": ""
        }
