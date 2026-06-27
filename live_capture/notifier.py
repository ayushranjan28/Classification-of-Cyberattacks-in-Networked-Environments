from win10toast import ToastNotifier
import threading
from utils.logger import get_logger

log = get_logger(__name__)
toaster = ToastNotifier()

def send_notification(title: str, message: str, duration: int = 5):
    """
    Sends a native Windows 10/11 desktop toast notification.
    Runs in a background thread to prevent blocking the sniffer.
    """
    log.info(f"🔔 System Notification: {title} - {message}")
    
    def _notify():
        try:
            # We remove threaded=True because we are already spawning this in our own background thread.
            # win10toast's internal threading can cause COM/WPARAM errors when nested.
            toaster.show_toast(
                title=title,
                msg=message,
                duration=duration,
                threaded=False
            )
        except Exception as e:
            # Suppress any deep win32gui/ctypes errors so the sniffer daemon never crashes
            log.warning(f"Native Windows notification suppressed due to OS error: {e}")
            
    # Always spawn in a thread since win10toast's threaded=True sometimes blocks slightly during initialization
    t = threading.Thread(target=_notify, daemon=True)
    t.start()
