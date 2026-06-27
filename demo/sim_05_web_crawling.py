import socket
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)

def run(target_ip="93.184.215.14", target_port=80, pages=200): # example.com
    print("\n=======================================================")
    print("   AI-SOC Demo: Web Crawling Attack")
    print("=======================================================\n")
    log.warning(f"🔴 [ATTACK] Launching Web Crawler against {target_ip}:{target_port} ({pages} pages)...")
    
    import random
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
            
        # Log to DB
        try:
            from live_capture.database import insert_flow
            from demo.demo_live_data_generator import generate_features
            insert_flow(
                src_ip="203.0.113.110", src_port=random.randint(50000, 60000),
                dst_ip=target_ip, dst_port=target_port,
                protocol="6",
                risk_score=random.uniform(65.0, 80.0),
                risk_label="Medium",
                predicted_attack="Web_Crwling",
                confidence=random.uniform(0.65, 0.85),
                explanation="Simulated attack.",
                features=generate_features(is_attack=False)
            )
        except Exception:
            pass
            
        time.sleep(0.1) # Moderate pace

    log.info("✅ Web Crawling simulation complete.")

if __name__ == "__main__":
    run()
