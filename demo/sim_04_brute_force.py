import socket
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)

def run(target_ip="195.144.107.198", target_port=21, attempts=10): # test.rebex.net
    print("\n=======================================================")
    print("   AI-SOC Demo: FTP/SSH Brute Force Attack")
    print("=======================================================\n")
    log.warning(f"🔴 [ATTACK] Launching Brute Force against {target_ip}:{target_port} ({attempts} attempts)...")
    
    import random
    for i in range(attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((target_ip, target_port))
                # Simulate login packet
                s.sendall(b"USER admin\r\nPASS password123\r\n")
        except (socket.timeout, ConnectionRefusedError):
            pass
            
        # Log to DB
        try:
            from live_capture.database import insert_flow
            from demo.demo_live_data_generator import generate_features
            insert_flow(
                src_ip="198.51.100.7", src_port=random.randint(50000, 60000),
                dst_ip=target_ip, dst_port=target_port,
                protocol="6",
                risk_score=random.uniform(82.0, 95.0),
                risk_label="High",
                predicted_attack="Brute_Force",
                confidence=random.uniform(0.75, 0.90),
                features=generate_features(is_attack=True)
            )
        except Exception:
            pass
            
        time.sleep(0.02) # Slightly slower than DoS to mimic brute force

    log.info("✅ Brute Force simulation complete.")

if __name__ == "__main__":
    run()
