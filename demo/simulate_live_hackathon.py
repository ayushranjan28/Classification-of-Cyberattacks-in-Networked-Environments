import time
import random
import sys
import threading
from pathlib import Path
import urllib.request
import socket

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logger import get_logger
from demo.generate_test_traffic import simulate_port_scan, simulate_http_flood

log = get_logger(__name__)

NORMAL_URLS = [
    "https://www.google.com",
    "https://www.github.com",
    "https://www.wikipedia.org",
    "https://www.python.org",
    "https://news.ycombinator.com"
]

def generate_normal_burst():
    """Generates a small burst of normal web traffic."""
    log.info("🟢 [NORMAL] Generating safe background traffic...")
    url = random.choice(NORMAL_URLS)
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            response.read()
    except Exception:
        pass

def generate_attack_burst():
    """Randomly selects and generates a cyber attack."""
    attack_type = random.choice(["scan", "dos"])
    
    if attack_type == "scan":
        log.warning("🔴 [ATTACK] Launching Stealth Port Scan!")
        # Smaller scale scan for a burst
        simulate_port_scan(target_ip="127.0.0.1", start_port=1, end_port=100)
    else:
        log.warning("🔴 [ATTACK] Launching HTTP DDoS Flood!")
        # Smaller scale flood for a burst
        simulate_http_flood(target_ip="127.0.0.1", target_port=80, requests=100)

def start_simulation():
    print("\n=======================================================")
    print("   AI-SOC: Live Hackathon Presentation Simulator")
    print("=======================================================\n")
    print("This script will run endlessly. It continuously generates")
    print("safe, normal traffic. At random intervals, it will launch")
    print("a cyberattack to demonstrate the AI's detection capabilities.")
    print("Press Ctrl+C to stop.\n")
    
    try:
        while True:
            # 85% chance of normal traffic, 15% chance of an attack
            if random.random() < 0.85:
                generate_normal_burst()
                # Pause between 1 to 3 seconds for normal traffic
                time.sleep(random.uniform(1.0, 3.0))
            else:
                generate_attack_burst()
                # Pause longer after an attack to let the dashboard digest it
                time.sleep(random.uniform(4.0, 6.0))
    except KeyboardInterrupt:
        print("\nSimulation stopped by user.")

if __name__ == "__main__":
    start_simulation()
