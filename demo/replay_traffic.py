import sys
import argparse
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

from live_capture.inference import LiveInferenceEngine
from live_capture.database import init_db
from live_capture.sniffer import custom_writer_factory
from utils.logger import get_logger

# Import CICFlowMeter components
from cicflowmeter.sniffer import create_sniffer
import cicflowmeter.flow_session
import cicflowmeter.writer

log = get_logger(__name__)

def replay_pcap(pcap_path: str):
    """
    Replays a .pcap file through the Inference Engine.
    This acts as a failsafe if live packet sniffing fails during the demo.
    """
    if not Path(pcap_path).exists():
        log.error(f"❌ PCAP file not found: {pcap_path}")
        return

    log.info("Initializing Failsafe Replay Mode...")
    
    # 1. Initialize SQLite Database
    init_db()
    
    # 2. Load ML Models
    engine = LiveInferenceEngine()
    
    # 3. Patch CICFlowMeter
    cicflowmeter.flow_session.output_writer_factory = custom_writer_factory
    cicflowmeter.writer.output_writer_factory = custom_writer_factory
    
    # 4. Create Sniffer in Offline (File) Mode
    log.info(f"Replaying PCAP file: {pcap_path}")
    sniffer, session = create_sniffer(
        input_file=pcap_path,
        input_interface=None,
        output_mode="inference",
        output=engine,
        verbose=False
    )
    
    # 5. Start Capturing
    log.info("📡 Processing packets... (Check the Streamlit dashboard!)")
    try:
        sniffer.start()
        sniffer.join()
    except KeyboardInterrupt:
        log.info("Stopping replay...")
        sniffer.stop()
    finally:
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        session.flush_flows()
        log.info("✅ Replay complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-SOC Failsafe Replay Mode")
    parser.add_argument("pcap_file", help="Path to the .pcap file to replay")
    
    args = parser.parse_args()
    replay_pcap(args.pcap_file)
