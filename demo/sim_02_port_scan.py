import threading
import time
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)

# Simulate port scanning by hitting many different ports/services on real servers
# We use different URLs and vary the paths to create diverse flow patterns
SCAN_TARGETS = [
    ("http://example.com", 80),
    ("http://example.org", 80),
    ("http://info.cern.ch", 80),
    ("http://httpbin.org/get", 80),
    ("http://neverssl.com", 80),
    ("https://example.com", 443),
    ("https://example.org", 443),
    ("https://www.google.com", 443),
    ("https://www.github.com", 443),
    ("https://www.wikipedia.org", 443),
    ("https://www.python.org", 443),
    ("https://httpbin.org/get", 443),
    ("https://www.cloudflare.com", 443),
    ("https://api.github.com", 443),
    ("https://pypi.org", 443),
    ("https://news.ycombinator.com", 443),
    ("https://stackoverflow.com", 443),
    ("https://www.reddit.com", 443),
    ("https://www.mozilla.org", 443),
    ("https://www.apache.org", 443),
]

def run(rounds=5):
    print("\n=======================================================")
    print("   AI-SOC Demo: Stealth Port Scan Attack")
    print("=======================================================\n")
    total = len(SCAN_TARGETS) * rounds
    log.warning(f"🔴 [ATTACK] Launching Port Scan simulation ({total} probes across {len(SCAN_TARGETS)} targets)...")
    
    completed = [0]
    
    def probe(url):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Nmap-Scanner/7.92'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read(256)
            completed[0] += 1
        except Exception:
            completed[0] += 1  # Even failed connections generate network flows

    threads = []
    for round_num in range(rounds):
        for url, port in SCAN_TARGETS:
            t = threading.Thread(target=probe, args=(url,))
            threads.append(t)
            t.start()
            time.sleep(0.03)  # Slight stagger

    for t in threads:
        t.join()
        
    log.info(f"✅ Port Scan simulation complete. {completed[0]} probes sent.")

if __name__ == "__main__":
    run()
