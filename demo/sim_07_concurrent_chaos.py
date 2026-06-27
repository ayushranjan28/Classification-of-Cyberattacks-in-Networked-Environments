import time
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger
import demo.sim_01_normal as sim_normal
import demo.sim_02_port_scan as sim_scan
import demo.sim_03_http_ddos as sim_dos
import demo.sim_04_brute_force as sim_brute

log = get_logger(__name__)

def run_concurrently():
    print("\n=======================================================")
    print("   AI-SOC Demo: CONCURRENT CHAOS (All at once!)")
    print("=======================================================\n")
    log.warning("🚨 INITIATING SIMULTANEOUS MULTI-VECTOR ATTACK 🚨")
    
    # We will run normal traffic, port scan, DDoS, and brute force all at the exact same time
    threads = []
    
    # 1. Start normal traffic (make it loop a bit longer)
    t_normal = threading.Thread(target=sim_normal.run)
    threads.append(t_normal)
    
    # 2. Start Port Scan
    t_scan = threading.Thread(target=lambda: sim_scan.run(rounds=1))
    threads.append(t_scan)
    
    # 3. Start HTTP DDoS
    t_dos = threading.Thread(target=lambda: sim_dos.run(requests_count=50))
    threads.append(t_dos)
    
    # 4. Start Brute Force
    t_brute = threading.Thread(target=lambda: sim_brute.run(attempts=10))
    threads.append(t_brute)

    # Start all threads simultaneously
    for t in threads:
        t.start()
        
    # Wait for all attacks to finish
    for t in threads:
        t.join()
        
    log.info("\n✅ Concurrent Chaos Simulation Complete! Check your dashboard!")

if __name__ == "__main__":
    run_concurrently()
