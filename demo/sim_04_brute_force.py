import threading
import time
import sys
import urllib.request
import urllib.parse
import socket
from pathlib import Path
import random

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)

# Simulate brute force by rapidly POSTing to login-like endpoints
LOGIN_TARGETS = [
    "http://httpbin.org/post",
    "http://httpbin.org/post",
    "http://httpbin.org/post",
]

USERNAMES = ["admin", "root", "user", "test", "administrator", "guest", "support"]
PASSWORDS = ["password", "123456", "admin", "root", "letmein", "qwerty", "welcome"]

def run(attempts=10):
    print("\n=======================================================")
    print("   AI-SOC Demo: FTP/SSH Brute Force Attack")
    print("=======================================================\n")
    log.warning(f"🔴 [ATTACK] Launching Brute Force simulation ({attempts} login attempts)...")
    
    completed = [0]
    
    def try_login(username, password):
        try:
            url = LOGIN_TARGETS[completed[0] % len(LOGIN_TARGETS)]
            data = urllib.parse.urlencode({
                'username': username, 
                'password': password
            }).encode()
            req = urllib.request.Request(url, data=data, headers={
                'User-Agent': 'Hydra/9.3',
                'Content-Type': 'application/x-www-form-urlencoded'
            })
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read(256)
            completed[0] += 1
        except Exception:
            completed[0] += 1
            
        # Log to DB to simulate detection
        try:
            from live_capture.database import insert_flow
            from demo.demo_live_data_generator import generate_features
            url = LOGIN_TARGETS[0]
            host = url.split("//")[1].split("/")[0]
            target_ip = socket.gethostbyname(host)
            
            insert_flow(
                src_ip="198.51.100.7", src_port=random.randint(50000, 60000),
                dst_ip=target_ip, dst_port=80,
                protocol="6",
                risk_score=random.uniform(82.0, 95.0),
                risk_label="High",
                predicted_attack="Brute_Force",
                confidence=random.uniform(0.75, 0.90),
                features=generate_features(is_attack=True)
            )
        except Exception:
            pass

    threads = []
    for i in range(attempts):
        user = USERNAMES[i % len(USERNAMES)]
        pw = PASSWORDS[i % len(PASSWORDS)]
        t = threading.Thread(target=try_login, args=(user, pw))
        threads.append(t)
        t.start()
        time.sleep(0.03)

    for t in threads:
        t.join()
        
    log.info(f"✅ Brute Force simulation complete. {completed[0]} attempts sent.")

if __name__ == "__main__":
    run()
