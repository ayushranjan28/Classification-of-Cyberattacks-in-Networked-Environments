"""
Real-time Behavioral Threat Detector.

Works alongside the ML classifier by analyzing aggregate traffic patterns
to detect attacks that individual flow classification might miss:
- DDoS/HTTP Flood: Abnormally high outbound flow rate from source
- Port Scan: Flows to many different destination IPs in a short window
- Brute Force: Repeated connections to authentication ports (21, 22, 23, 3389)

Thresholds are tuned to avoid false positives from normal OS/browser background
traffic (Windows Update, DNS, CDN, telemetry, etc.).
"""
import time
import socket
from collections import defaultdict
from utils.logger import get_logger

log = get_logger(__name__)

# Auth-related ports for brute force detection (strictly remote-access / login ports)
AUTH_PORTS = {21, 22, 23, 3389, 5900}

# IPs that should NEVER be flagged — localhost, broadcast, multicast, well-known DNS
_SAFE_IP_PREFIXES = (
    "127.",          # loopback
    "0.",            # unspecified
    "224.",          # multicast
    "239.",          # multicast
    "255.",          # broadcast
    "169.254.",      # link-local
    "ff",            # IPv6 multicast
    "::1",           # IPv6 loopback
    "fe80:",         # IPv6 link-local
)
_SAFE_IPS = {
    "8.8.8.8", "8.8.4.4",           # Google DNS
    "1.1.1.1", "1.0.0.1",           # Cloudflare DNS
    "208.67.222.222", "208.67.220.220",  # OpenDNS
}

def _is_safe_ip(ip: str) -> bool:
    """Return True if the IP belongs to a known-safe address range."""
    if ip in _SAFE_IPS:
        return True
    for prefix in _SAFE_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False

def _get_local_ips() -> set:
    """Return a set of all IP addresses assigned to this machine."""
    local_ips = {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            local_ips.add(info[4][0])
    except Exception:
        pass
    return local_ips


class BehavioralDetector:
    """Sliding-window behavioral analysis for live traffic."""

    def __init__(self, window_seconds=30):
        self.window = window_seconds
        self.local_ips = _get_local_ips()

        # src_ip -> list of timestamps (total outbound rate)
        self.src_flow_times = defaultdict(list)
        # src_ip -> list of (timestamp, dst_ip) for sliding window
        self.src_dst_ips_seen = defaultdict(list)
        
        # dest_ip -> list of timestamps
        self.dest_flow_times = defaultdict(list)
        # dest_ip -> list of (timestamp, dest_port) for sliding window
        self.dest_ports_seen = defaultdict(list)
        
        # dest_ip:dest_port -> list of timestamps (for auth ports only)
        self.auth_attempts = defaultdict(list)

    def _prune(self, timestamps: list) -> list:
        """Remove entries older than the sliding window."""
        cutoff = time.time() - self.window
        return [t for t in timestamps if t > cutoff]

    def _prune_tuples(self, tuples: list) -> list:
        """Remove (timestamp, value) entries older than the sliding window."""
        cutoff = time.time() - self.window
        return [(t, v) for t, v in tuples if t > cutoff]

    def analyze(self, src_ip: str, dst_ip: str, dst_port: int) -> dict:
        """
        Analyze a flow and return behavioral detection results.
        Returns dict with:
          - behavioral_attack: str or None (attack type name)
          - behavioral_confidence: float 0-1
          - behavioral_reason: str (human-readable explanation)
        """
        no_attack = {
            "behavioral_attack": None,
            "behavioral_confidence": 0.0,
            "behavioral_reason": ""
        }

        # Skip analysis for known-safe IPs and local machine traffic
        if _is_safe_ip(src_ip) or _is_safe_ip(dst_ip):
            return no_attack
        if src_ip in self.local_ips and dst_ip in self.local_ips:
            return no_attack

        now = time.time()

        # --- Update sliding windows ---
        # Track outbound rate from source
        self.src_flow_times[src_ip].append(now)
        self.src_flow_times[src_ip] = self._prune(self.src_flow_times[src_ip])
        
        self.src_dst_ips_seen[src_ip].append((now, dst_ip))
        self.src_dst_ips_seen[src_ip] = self._prune_tuples(self.src_dst_ips_seen[src_ip])

        # Track per-destination
        self.dest_flow_times[dst_ip].append(now)
        self.dest_flow_times[dst_ip] = self._prune(self.dest_flow_times[dst_ip])
        
        self.dest_ports_seen[dst_ip].append((now, dst_port))
        self.dest_ports_seen[dst_ip] = self._prune_tuples(self.dest_ports_seen[dst_ip])

        if dst_port in AUTH_PORTS:
            key = f"{dst_ip}:{dst_port}"
            self.auth_attempts[key].append(now)
            self.auth_attempts[key] = self._prune(self.auth_attempts[key])

        # --- Detection Rules (tuned to avoid false positives) ---

        # 1. HTTP Flood / DDoS: High outbound rate from a single source
        #    >60 flows from same source in the window = flood
        #    (normal browsing + OS telemetry rarely exceeds ~40 in 30s)
        src_flow_count = len(self.src_flow_times[src_ip])
        if src_flow_count >= 60:
            confidence = min(src_flow_count / 120.0, 1.0)
            return {
                "behavioral_attack": "HTTP_Flood",
                "behavioral_confidence": confidence,
                "behavioral_reason": f"DDoS: {src_flow_count} outbound flows from {src_ip} in {self.window}s"
            }

        # 2. Port Scan: Many distinct destination IPs from same source
        #    >25 different IPs contacted = scanning
        #    (normal DNS + CDN rarely exceeds ~15 unique IPs in 30s)
        unique_dst_ips = set(ip for t, ip in self.src_dst_ips_seen[src_ip])
        dst_ip_count = len(unique_dst_ips)
        if dst_ip_count >= 25:
            confidence = min(dst_ip_count / 50.0, 1.0)
            return {
                "behavioral_attack": "Port_Scan",
                "behavioral_confidence": confidence,
                "behavioral_reason": f"Scan: {dst_ip_count} distinct hosts contacted by {src_ip}"
            }

        # 3. Brute Force: Repeated connections to auth ports
        #    >25 attempts to same auth service = brute force
        if dst_port in AUTH_PORTS:
            key = f"{dst_ip}:{dst_port}"
            auth_count = len(self.auth_attempts[key])
            if auth_count >= 25:
                confidence = min(auth_count / 50.0, 1.0)
                return {
                    "behavioral_attack": "Brute_Force",
                    "behavioral_confidence": confidence,
                    "behavioral_reason": f"Brute Force: {auth_count} auth attempts to {dst_ip}:{dst_port}"
                }

        return no_attack
