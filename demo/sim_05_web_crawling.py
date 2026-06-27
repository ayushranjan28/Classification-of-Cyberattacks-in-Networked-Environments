import socket
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)

def run(target_ip="127.0.0.1", target_port=80, pages=50):
    print("\n=======================================================")
    print("   AI-SOC Demo: Web Crawling Attack")
    print("=======================================================\n")
    log.warning(f"🔴 [ATTACK] Launching Web Crawler against {target_ip}:{target_port} ({pages} pages)...")
    
    for i in range(pages):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((target_ip, target_port))
                # Simulate sequential requests
                request = f"GET /page_{i}.html HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Python-Crawler\r\n\r\n"
                s.sendall(request.encode())
        except (socket.timeout, ConnectionRefusedError):
            pass
        time.sleep(0.1) # Moderate pace

    log.info("✅ Web Crawling simulation complete.")

if __name__ == "__main__":
    run()
