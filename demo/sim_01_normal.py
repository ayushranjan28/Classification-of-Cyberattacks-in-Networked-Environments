import time
import sys
import urllib.request
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)

def run():
    urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.wikipedia.org",
        "https://www.python.org",
        "https://news.ycombinator.com"
    ]
    
    print("\n=======================================================")
    print("   AI-SOC Demo: Normal Background Traffic")
    print("=======================================================\n")
    log.info("🟢 [NORMAL] Generating safe background traffic...")
    
    for i in range(20):
        url = urls[i % len(urls)]
        try:
            log.info(f"[{i+1}/20] Browsing {url}...")
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                response.read()
            time.sleep(1.5)  # Human pace
        except Exception as e:
            log.warning(f"Failed to fetch {url}: {e}")
            
    log.info("✅ Normal traffic generation complete.")

if __name__ == "__main__":
    run()
