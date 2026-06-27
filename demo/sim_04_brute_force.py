import threading
import time
import sys
import urllib.request
import urllib.parse
from pathlib import Path

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

def run(attempts=100):
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
