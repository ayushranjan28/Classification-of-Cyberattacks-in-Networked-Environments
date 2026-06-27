import subprocess
from utils.logger import get_logger

log = get_logger(__name__)

# Keep a set of blocked IPs in memory to avoid duplicate rules
_BLOCKED_IPS = set()

def block_ip(ip_address: str, attack_type: str):
    """
    Blocks an IP address using Windows Firewall.
    Must be run as Administrator.
    """
    if ip_address in _BLOCKED_IPS:
        return
        
    log.warning(f"🛡️ [IPS] Initiating Windows Firewall block for malicious IP: {ip_address}")
    
    rule_name = f"AI-SOC Block: {ip_address} ({attack_type})"
    
    # Netsh command to add a block rule for the remote IP on any port
    command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip_address}"
    ]
    
    try:
        # Run command silently without opening a new console window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        result = subprocess.run(command, capture_output=True, text=True, startupinfo=startupinfo)
        
        if result.returncode == 0:
            log.info(f"✅ Successfully added Windows Firewall rule for {ip_address}")
            _BLOCKED_IPS.add(ip_address)
        else:
            if "Access is denied" in result.stdout or "Access is denied" in result.stderr:
                log.error("❌ Access Denied: Cannot modify Windows Firewall. Please run the AI-SOC as Administrator.")
            else:
                log.error(f"❌ Failed to add firewall rule: {result.stderr or result.stdout}")
    except Exception as e:
        log.error(f"❌ Exception executing netsh: {e}")
