import urllib.request
import time
import sys
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logger import get_logger

log = get_logger(__name__)

def generate_normal_traffic():
    """Simulates safe, normal background web traffic."""
    urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.wikipedia.org",
        "https://www.python.org",
    ]
    
    log.info("🌐 Generating NORMAL background web traffic...")
    
    for i in range(15):
        url = urls[i % len(urls)]
        try:
            log.info(f"[{i+1}/15] Fetching {url}...")
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                response.read()
            time.sleep(1.5)  # Pause to simulate normal human browsing pace
        except Exception as e:
            log.warning(f"Failed to fetch {url}: {e}")
            
    log.info("✅ Normal traffic generation complete. Check your dashboard!")

if __name__ == "__main__":
    generate_normal_traffic()
