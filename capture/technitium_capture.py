import time
import logging
from config.config import Config

logger = logging.getLogger(__name__)

def tail_log(filepath: str = Config.TECHNITIUM_LOG_PATH):
    """
    Will watch the Technitium DNS log, gives a new line when they come in.
    Will be running in conjunction with tshark.
    """
    try:
        f = open(filepath, "r", encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError) as e:
        logger.warning(f"Technitium DNS log could not be opened: {e} — Technitium capture disabled")
        return

    with f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if line:
                yield ("technitium", line.strip())  # tag the source as technitium
            else:
                time.sleep(0.1)
