"""
Real-time Behavioral Threat Detector.

Works alongside the ML classifier by analyzing aggregate traffic patterns
to detect attacks that individual flow classification might miss:
- DDoS: Many flows to the same destination in a short time window
- Port Scan: Flows to many different ports on the same destination
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
        self.dest_flow_times[dst_ip].append(now)
        self.dest_flow_times[dst_ip] = self._prune(self.dest_flow_times[dst_ip])

        self.dest_ports_seen[dst_ip].add(dst_port)

        if dst_port in AUTH_PORTS:
            key = f"{dst_ip}:{dst_port}"
            self.auth_attempts[key].append(now)
            self.auth_attempts[key] = self._prune(self.auth_attempts[key])

        # --- Detection Rules ---

        # 1. DDoS Detection: >50 flows to same dest IP within window
        flow_count = len(self.dest_flow_times[dst_ip])
        if flow_count >= 50:
            confidence = min(flow_count / 100.0, 1.0)
            return {
                "behavioral_attack": "HTTP_Flood",
                "behavioral_confidence": confidence,
                "behavioral_reason": f"DDoS: {flow_count} flows to {dst_ip} in {self.window}s window"
            }

        # 2. Port Scan Detection: >15 distinct ports on same dest IP within window
        port_count = len(self.dest_ports_seen[dst_ip])
        if port_count >= 15:
            confidence = min(port_count / 50.0, 1.0)
            return {
                "behavioral_attack": "Port_Scan",
                "behavioral_confidence": confidence,
                "behavioral_reason": f"Port Scan: {port_count} distinct ports scanned on {dst_ip}"
            }

        # 3. Brute Force Detection: >10 auth-port connections in window
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
