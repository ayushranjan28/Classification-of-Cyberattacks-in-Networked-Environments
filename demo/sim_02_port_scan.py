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
    
    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                s.connect((target_ip, port))
        except (socket.timeout, ConnectionRefusedError):
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
