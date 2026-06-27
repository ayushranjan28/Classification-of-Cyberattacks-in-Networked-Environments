import socket
import threading
import time
import argparse
from utils.logger import get_logger

log = get_logger(__name__)

def simulate_port_scan(target_ip="127.0.0.1", start_port=1, end_port=1000):
    """Simulates a rapid SYN/Connect port scan against the target."""
    log.info(f"🚨 Starting simulated Port Scan against {target_ip}:{start_port}-{end_port}...")
    
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
        if port % 50 == 0:
            time.sleep(0.05)

    for t in threads:
        t.join()
        
    log.info("✅ Port Scan simulation complete.")

def simulate_http_flood(target_ip="127.0.0.1", target_port=80, requests=500):
    """Simulates a TCP/HTTP flood (DoS) attack."""
    log.info(f"🚨 Starting simulated HTTP Flood (DoS) against {target_ip}:{target_port} ({requests} requests)...")
    
    def send_req():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                s.connect((target_ip, target_port))
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
        except (socket.timeout, ConnectionRefusedError):
            pass

    threads = []
    for _ in range(requests):
        t = threading.Thread(target=send_req)
        threads.append(t)
        t.start()
        time.sleep(0.01)

    for t in threads:
        t.join()
        
    log.info("✅ HTTP Flood simulation complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-SOC Safe Demonstration Traffic Generator")
    parser.add_argument("--type", choices=["scan", "dos", "all"], default="all", help="Type of attack to simulate")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: localhost)")
    
    args = parser.parse_args()
    
    print("\n=======================================================")
    print("   AI-SOC: Safe Demonstration Traffic Generator")
    print("=======================================================\n")
    print("WARNING: This script generates rapid network traffic.")
    print("Ensure you have permission and are targeting a safe host.\n")
    
    if args.type in ["scan", "all"]:
        simulate_port_scan(args.target)
        time.sleep(2)
        
    if args.type in ["dos", "all"]:
        simulate_http_flood(args.target)
