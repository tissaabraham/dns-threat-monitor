import time
import logging
from config.config import Config

logger = logging.getLogger(__name__)

#Now using config/env variables, not hardcoded paths.
def tail_log(filepath: str = Config.DNSMASQ_LOG_PATH):
    """
    Will watch the dnsmasq log, gives a new line when they come in.
    Will be running in conjunction with tshark.
    """
    try:
        f = open(filepath, "r")
    except FileNotFoundError:
        logger.warning(f"dnsmasq log not found: {filepath} — dnsmasq capture disabled")
        return

    with f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if line:
                yield ("dnsmasq", line.strip())  # tag the source
            else:
                time.sleep(0.1)