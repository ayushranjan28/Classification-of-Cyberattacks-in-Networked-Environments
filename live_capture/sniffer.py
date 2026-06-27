import sys
from pathlib import Path
import threading
import argparse

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

from live_capture.inference import LiveInferenceEngine
from live_capture.database import init_db, update_flow_attack
from live_capture.firewall import block_ip
from live_capture.notifier import send_notification
from live_capture.behavioral_detector import BehavioralDetector
from utils.logger import get_logger

# Import CICFlowMeter components
from cicflowmeter.sniffer import create_sniffer
import cicflowmeter.flow_session
from cicflowmeter.writer import OutputWriter
import cicflowmeter.writer

log = get_logger(__name__)

class InferenceWriter(OutputWriter):
    """Custom CICFlowMeter writer that sends flows to our ML inference engine."""
    def __init__(self, engine: LiveInferenceEngine) -> None:
        self.engine = engine
        self.behavioral = BehavioralDetector(window_seconds=30)

    def write(self, data: dict) -> None:
        try:
            # Extract basic routing info for the database log
            src_ip = data.get("src_ip", "Unknown")
            src_port = int(data.get("src_port", 0))
            dst_ip = data.get("dst_ip", "Unknown")
            dst_port = int(data.get("dst_port", 0))
            protocol = str(data.get("protocol", "Unknown"))
            
            # Skip flows that are always benign (loopback, broadcast, multicast)
            _SKIP_PREFIXES = ("127.", "0.", "224.", "239.", "255.", "169.254.", "ff", "::1", "fe80:")
            if any(src_ip.startswith(p) or dst_ip.startswith(p) for p in _SKIP_PREFIXES):
                return
            
            # 1. ML Inference (per-flow classification)
            result = self.engine.score_flow(data, src_ip, src_port, dst_ip, dst_port, protocol)
            
            # 2. Behavioral Analysis (aggregate pattern detection)
            beh = self.behavioral.analyze(src_ip, dst_ip, dst_port)
            
            # If behavioral detector found an attack, override the ML result
            if beh["behavioral_attack"] and result["predicted_attack"] == "Normal":
                result["predicted_attack"] = beh["behavioral_attack"]
                result["confidence"] = beh["behavioral_confidence"]
                result["risk_score"] = max(result["risk_score"], 75.0 + beh["behavioral_confidence"] * 25.0)
                result["risk_label"] = "Critical" if result["risk_score"] >= 81 else "High"
                # Update the database row with the corrected attack type
                update_flow_attack(
                    src_ip=src_ip, src_port=src_port,
                    dst_ip=dst_ip, dst_port=dst_port,
                    predicted_attack=result["predicted_attack"],
                    risk_score=result["risk_score"],
                    risk_label=result["risk_label"],
                    confidence=result["confidence"]
                )
                log.warning(f"🚨 BEHAVIORAL ATTACK [{result['risk_label']}]: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {beh['behavioral_reason']}")
            
            # Active Defense & Logging
            if result["predicted_attack"] != "Normal":
                log.warning(f"🚨 ATTACK DETECTED [{result['risk_label']}]: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Type: {result['predicted_attack']} (Conf: {result['confidence']:.2f})")
                
                # If risk is Critical, block it automatically using Windows Firewall
                if result["risk_label"] == "Critical":
                    send_notification(
                        title=f"🛑 Critical Threat Blocked",
                        message=f"AI-IDS blocked {src_ip} from executing a {result['predicted_attack']} attack."
                    )
                    block_ip(src_ip, result["predicted_attack"])
                    
                # If risk is High, alert the user but don't block
                elif result["risk_label"] == "High":
                    send_notification(
                        title=f"⚠️ High Threat Detected",
                        message=f"AI-IDS detected {result['predicted_attack']} from {src_ip}. Check the dashboard!"
                    )
                    
            else:
                log.info(f"✅ Normal Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Risk: {result['risk_score']:.1f}%")
        except Exception as e:
            log.error(f"Error scoring flow: {e}")

# Monkey-patch the writer factory to support our custom InferenceWriter
original_factory = cicflowmeter.writer.output_writer_factory

def custom_writer_factory(output_mode, output):
    if output_mode == "inference":
        return InferenceWriter(engine=output)
    return original_factory(output_mode, output)

cicflowmeter.flow_session.output_writer_factory = custom_writer_factory
cicflowmeter.writer.output_writer_factory = custom_writer_factory


def start_live_capture(interface: str = None):
    """Start sniffing traffic and feeding it to the AI models."""
    log.info("Initializing Live Capture System...")
    
    # 1. Initialize SQLite Database
    init_db()
    
    # Wipe old flows on startup for clean demo runs
    import sqlite3
    from live_capture.database import DB_PATH
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM live_flows")
        conn.commit()
        conn.close()
        log.info("🧹 Wiped old traffic data for a clean session.")
    except Exception as e:
        log.warning(f"Failed to wipe database on startup: {e}")
        
    # 2. Load ML Models
    engine = LiveInferenceEngine()
    
    # 3. Create Sniffer
    from scapy.config import conf
    if not interface:
        interface = conf.iface.name if hasattr(conf.iface, "name") else conf.iface
        
    log.info(f"Binding to network interface: {interface}")
    sniffer, session = create_sniffer(
        input_file=None,
        input_interface=interface,
        output_mode="inference",
        output=engine,
        verbose=False
    )
    
    # 4. Start Capturing
    log.info("🎧 Listening for live network traffic. Press Ctrl+C to stop.")
    try:
        sniffer.start()
        sniffer.join()
    except KeyboardInterrupt:
        log.info("Stopping capture...")
        sniffer.stop()
    finally:
        if session:
            if hasattr(session, "_gc_stop"):
                session._gc_stop.set()
                session._gc_thread.join(timeout=2.0)
            if hasattr(session, "flush_flows"):
                session.flush_flows()
            elif hasattr(session, "garbage_collect"):
                try:
                    session.garbage_collect(None)
                except Exception:
                    pass
        log.info("Live capture stopped gracefully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Real-Time Network Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff (e.g., eth0, Wi-Fi)")
    args = parser.parse_args()
    
    start_live_capture(args.interface)
