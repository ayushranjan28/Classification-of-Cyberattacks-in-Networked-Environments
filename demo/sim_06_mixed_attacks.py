import time
import sys
from pathlib import Path
import random

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger
import demo.sim_01_normal as sim_normal
import demo.sim_02_port_scan as sim_scan
import demo.sim_03_http_ddos as sim_dos
import demo.sim_04_brute_force as sim_brute
import demo.sim_05_web_crawling as sim_crawl

log = get_logger(__name__)

def run():
    print("\n=======================================================")
    print("   AI-SOC Demo: Mixed Attack Simulation")
    print("=======================================================\n")
    log.info("Starting a chaotic mix of normal traffic and various cyber attacks...")
    
    # 1. Start with normal traffic
    sim_normal.run()
    time.sleep(2)
    
    # 2. Randomly execute 3 attacks
    attacks = [
        ("Stealth Port Scan", lambda: sim_scan.run(end_port=50)),
        ("HTTP DDoS", lambda: sim_dos.run(requests=200)),
        ("FTP Brute Force", lambda: sim_brute.run(attempts=10)),
        ("Web Crawling", lambda: sim_crawl.run(pages=10))
    ]
    
    random.shuffle(attacks)
    
    for i in range(3):
        name, func = attacks[i]
        log.warning(f"\n⚠️ Injecting next threat: {name}...")
        func()
        time.sleep(3)
        
    # 3. Finish with normal traffic to show recovery
    log.info("\n🟢 Returning to normal background traffic...")
    sim_normal.run()
    
    log.info("\n✅ Mixed Attack Simulation Complete!")

if __name__ == "__main__":
    run()
