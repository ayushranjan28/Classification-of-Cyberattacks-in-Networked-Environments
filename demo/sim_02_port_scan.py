import threading
import socket
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)

def run(target_ip="45.33.32.156", start_port=1, end_port=200): # scanme.nmap.org
    print("\n=======================================================")
    print("   AI-SOC Demo: Stealth Port Scan Attack")
    print("=======================================================\n")
    log.warning(f"🔴 [ATTACK] Launching Stealth Port Scan against {target_ip}:{start_port}-{end_port}...")
    
    import random
    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                s.connect((target_ip, port))
        except (socket.timeout, ConnectionRefusedError):
            pass
            
        # Log to DB
        try:
            from live_capture.database import insert_flow
            from demo.demo_live_data_generator import generate_features
            insert_flow(
                src_ip="10.0.0.42", src_port=random.randint(50000, 60000),
                dst_ip=target_ip, dst_port=port,
                protocol="6",
                risk_score=random.uniform(85.0, 97.0),
                risk_label="High",
                predicted_attack="Port_Scan",
                confidence=random.uniform(0.85, 0.95),
                features=generate_features(is_attack=True)
            )
        except Exception:
            pass

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()
        
        # Stagger slightly to ensure packets are registered cleanly by the sniffer
        if port % 100 == 0:
            time.sleep(0.05)

    for t in threads:
        t.join()
        
    log.info("✅ Port Scan simulation complete.")

if __name__ == "__main__":
    run()
