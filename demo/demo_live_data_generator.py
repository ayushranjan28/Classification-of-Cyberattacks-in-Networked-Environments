import sys
import time
import random
import json
from pathlib import Path
from datetime import datetime

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import PROJECT_ROOT, ATTACK_LABELS
from live_capture.database import init_db, insert_flow, update_flow_attack
from utils.logger import get_logger

log = get_logger("live_generator")

# Some mock IP pools and port pools
BENIGN_IPS = [
    "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.15",
    "172.217.16.142", "142.250.190.46", "208.80.154.224", "18.205.222.128"
]

ATTACK_IPS = [
    "10.0.0.15", "10.0.0.42", "198.51.100.7", "203.0.113.110"
]

TARGET_IP = "192.168.1.100"

def generate_features(is_attack=False):
    """Generate realistic flow feature dictionary matching CICFlowMeter features."""
    return {
        "flow_duration": random.randint(1000, 5000000) if not is_attack else random.randint(100, 10000),
        "flow_byts_s": random.uniform(10.0, 5000.0) if not is_attack else random.uniform(50000.0, 5000000.0),
        "flow_pkts_s": random.uniform(1.0, 100.0) if not is_attack else random.uniform(500.0, 50000.0),
        "tot_fwd_pkts": random.randint(1, 50),
        "tot_bwd_pkts": random.randint(1, 50),
        "totlen_fwd_pkts": random.randint(20, 5000),
        "totlen_bwd_pkts": random.randint(20, 5000),
        "fwd_pkt_len_max": random.uniform(20.0, 1500.0),
        "fwd_pkt_len_min": random.uniform(0.0, 60.0),
        "fwd_pkt_len_mean": random.uniform(20.0, 500.0),
        "fwd_pkt_len_std": random.uniform(0.0, 300.0),
        "bwd_pkt_len_max": random.uniform(20.0, 1500.0),
        "bwd_pkt_len_min": random.uniform(0.0, 60.0),
        "bwd_pkt_len_mean": random.uniform(20.0, 500.0),
        "bwd_pkt_len_std": random.uniform(0.0, 300.0),
        "pkt_len_max": random.uniform(20.0, 1500.0),
        "pkt_len_min": random.uniform(0.0, 60.0),
        "pkt_len_mean": random.uniform(20.0, 500.0),
        "pkt_len_std": random.uniform(0.0, 300.0),
        "pkt_len_var": random.uniform(0.0, 90000.0),
        "fwd_header_len": random.randint(20, 1000),
        "bwd_header_len": random.randint(20, 1000),
        "fwd_seg_size_min": random.randint(20, 40),
        "fwd_act_data_pkts": random.randint(0, 30),
        "flow_iat_mean": random.uniform(10.0, 50000.0),
        "flow_iat_max": random.uniform(50.0, 200000.0),
        "flow_iat_min": random.uniform(0.1, 100.0),
        "flow_iat_std": random.uniform(0.0, 30000.0),
        "fwd_iat_tot": random.uniform(50.0, 500000.0),
        "fwd_iat_max": random.uniform(50.0, 200000.0),
        "fwd_iat_min": random.uniform(0.1, 100.0),
        "fwd_iat_mean": random.uniform(10.0, 50000.0),
        "fwd_iat_std": random.uniform(0.0, 30000.0),
        "bwd_iat_tot": random.uniform(50.0, 500000.0),
        "bwd_iat_max": random.uniform(50.0, 200000.0),
        "bwd_iat_min": random.uniform(0.1, 100.0),
        "bwd_iat_mean": random.uniform(10.0, 50000.0),
        "bwd_iat_std": random.uniform(0.0, 30000.0),
        "fwd_psh_flags": random.randint(0, 5),
        "bwd_psh_flags": random.randint(0, 5),
        "fwd_urg_flags": random.randint(0, 2),
        "bwd_urg_flags": random.randint(0, 2),
        "fin_flag_cnt": random.randint(0, 2),
        "syn_flag_cnt": random.randint(0, 2) if not is_attack else random.randint(10, 100),
        "rst_flag_cnt": random.randint(0, 1),
        "psh_flag_cnt": random.randint(0, 15),
        "ack_flag_cnt": random.randint(1, 30),
        "urg_flag_cnt": random.randint(0, 1),
        "ece_flag_cnt": random.randint(0, 1),
        "down_up_ratio": random.uniform(0.1, 5.0),
        "pkt_size_avg": random.uniform(20.0, 800.0),
        "init_fwd_win_byts": random.randint(1024, 65535),
        "init_bwd_win_byts": random.randint(1024, 65535),
        "active_max": random.uniform(0.0, 1000000.0),
        "active_min": random.uniform(0.0, 1000000.0),
        "active_mean": random.uniform(0.0, 1000000.0),
        "active_std": random.uniform(0.0, 1000.0),
        "idle_max": random.uniform(0.0, 5000000.0),
        "idle_min": random.uniform(0.0, 5000000.0),
        "idle_mean": random.uniform(0.0, 5000000.0),
        "idle_std": random.uniform(0.0, 10000.0),
        "fwd_byts_b_avg": 0, "fwd_pkts_b_avg": 0,
        "bwd_byts_b_avg": 0, "bwd_pkts_b_avg": 0,
        "fwd_blk_rate_avg": 0, "bwd_blk_rate_avg": 0,
        "fwd_seg_size_avg": random.uniform(20.0, 500.0),
        "bwd_seg_size_avg": random.uniform(20.0, 500.0),
        "cwr_flag_count": 0,
        "subflow_fwd_pkts": random.randint(1, 50),
        "subflow_bwd_pkts": random.randint(1, 50),
        "subflow_fwd_byts": random.randint(20, 5000),
        "subflow_bwd_byts": random.randint(20, 5000),
    }

def main():
    print("=========================================================")
    print("   AI-SOC Live Traffic Simulator & Generator Daemon")
    print("   Bypasses raw socket dependencies (No Npcap required)")
    print("=========================================================")
    
    init_db()
    
    # Wipe old database contents for clean start
    import sqlite3
    from live_capture.database import DB_PATH
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM live_flows")
        conn.commit()
        conn.close()
        log.info("🧹 Wiped old traffic data for a clean session.")
    except Exception as e:
        log.warning(f"Failed to wipe database: {e}")
        
    log.info("🎧 Starting background simulation stream...")
    log.info("Press Ctrl+C to terminate the simulation.")
    
    try:
        attack_timer = time.time()
        while True:
            # 1. Generate normal traffic flow (every 1-3 seconds)
            src_ip = random.choice(BENIGN_IPS)
            dst_ip = random.choice([ip for ip in BENIGN_IPS if ip != src_ip] + [TARGET_IP])
            src_port = random.randint(49152, 65535)
            dst_port = random.choice([80, 443, 8080, 22])
            protocol = random.choice(["6", "17"]) # TCP or UDP
            
            risk_score = random.uniform(2.0, 18.0)
            confidence = random.uniform(0.85, 0.99)
            
            insert_flow(
                src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port,
                protocol=protocol,
                risk_score=risk_score,
                risk_label="Low",
                predicted_attack="Normal",
                confidence=confidence,
                features=generate_features(is_attack=False)
            )
            log.info(f"✅ Normal Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Risk: {risk_score:.1f}%")
            
            # 2. Inject periodic attack simulations (every 25 seconds)
            if time.time() - attack_timer > 25:
                attack_type = random.choice(["Port_Scan", "HTTP_DDoS", "Brute_Force", "Web_Crwling"])
                attacker_ip = random.choice(ATTACK_IPS)
                
                log.warning(f"🚨 INJECTING SIMULATED ATTACK: {attack_type} from {attacker_ip}")
                
                if attack_type == "Port_Scan":
                    # Generate many connections to different ports
                    for i in range(15):
                        p = random.randint(20, 1000)
                        risk_score = random.uniform(85.0, 98.0)
                        confidence = random.uniform(0.70, 0.92)
                        
                        insert_flow(
                            src_ip=attacker_ip, src_port=random.randint(50000, 60000),
                            dst_ip=TARGET_IP, dst_port=p,
                            protocol="6",
                            risk_score=risk_score,
                            risk_label="Critical" if risk_score > 90 else "High",
                            predicted_attack="Port_Scan",
                            confidence=confidence,
                            features=generate_features(is_attack=True)
                        )
                        log.warning(f"🚨 ATTACK DETECTED [High]: {attacker_ip} -> {TARGET_IP}:{p} | Type: Port_Scan")
                        time.sleep(0.1)
                        
                elif attack_type == "HTTP_DDoS":
                    # Generate many connections to port 80
                    for _ in range(50):
                        risk_score = random.uniform(88.0, 99.5)
                        confidence = random.uniform(0.80, 0.95)
                        
                        insert_flow(
                            src_ip=attacker_ip, src_port=random.randint(50000, 60000),
                            dst_ip=TARGET_IP, dst_port=80,
                            protocol="6",
                            risk_score=risk_score,
                            risk_label="Critical",
                            predicted_attack="HTTP_DDoS",
                            confidence=confidence,
                            features=generate_features(is_attack=True)
                        )
                        log.warning(f"🚨 ATTACK DETECTED [Critical]: {attacker_ip} -> {TARGET_IP}:80 | Type: HTTP_DDoS")
                        time.sleep(0.05)
                        
                elif attack_type == "Brute_Force":
                    # Generate multiple connections to port 22 or 3389
                    auth_port = random.choice([22, 3389])
                    for _ in range(12):
                        risk_score = random.uniform(82.0, 95.0)
                        confidence = random.uniform(0.75, 0.90)
                        
                        insert_flow(
                            src_ip=attacker_ip, src_port=random.randint(50000, 60000),
                            dst_ip=TARGET_IP, dst_port=auth_port,
                            protocol="6",
                            risk_score=risk_score,
                            risk_label="High",
                            predicted_attack="Brute_Force",
                            confidence=confidence,
                            features=generate_features(is_attack=True)
                        )
                        log.warning(f"🚨 ATTACK DETECTED [High]: {attacker_ip} -> {TARGET_IP}:{auth_port} | Type: Brute_Force")
                        time.sleep(0.2)
                        
                elif attack_type == "Web_Crwling":
                    # Generate crawling connections
                    for _ in range(10):
                        risk_score = random.uniform(65.0, 80.0)
                        confidence = random.uniform(0.65, 0.85)
                        
                        insert_flow(
                            src_ip=attacker_ip, src_port=random.randint(50000, 60000),
                            dst_ip=TARGET_IP, dst_port=80,
                            protocol="6",
                            risk_score=risk_score,
                            risk_label="Medium",
                            predicted_attack="Web_Crwling",
                            confidence=confidence,
                            features=generate_features(is_attack=False)
                        )
                        log.warning(f"🚨 ATTACK DETECTED [Medium]: {attacker_ip} -> {TARGET_IP}:80 | Type: Web_Crwling")
                        time.sleep(0.3)
                
                # Reset attack timer
                attack_timer = time.time()
                log.info("🟢 Attack injection complete. Resuming background traffic...")
            
            # Wait for next flow
            time.sleep(random.uniform(0.8, 2.5))
            
    except KeyboardInterrupt:
        log.info("Live traffic simulation stopped gracefully.")

if __name__ == "__main__":
    main()
