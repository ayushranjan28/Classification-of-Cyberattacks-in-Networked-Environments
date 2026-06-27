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
            # icon_path can be added if we have a custom icon
            toaster.show_toast(
                title=title,
                msg=message,
                duration=duration,
                threaded=True
            )
        except Exception as e:
            log.error(f"Failed to send Windows notification: {e}")
            
    # Always spawn in a thread since win10toast's threaded=True sometimes blocks slightly during initialization
    t = threading.Thread(target=_notify, daemon=True)
    t.start()
