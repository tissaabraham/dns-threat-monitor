import time
import logging
from datetime import date
from pathlib import Path
from config.config import Config

logger = logging.getLogger(__name__)

def _current_log_path(log_dir: Path) -> Path:
    return log_dir / f"{date.today().isoformat()}.log"

def tail_log(log_dir: str = Config.TECHNITIUM_LOG_PATH):
    """
    Watches the Technitium DNS query log directory for new lines.
    Technitium writes one log file per day named YYYY-MM-DD.log inside the
    configured queries directory. When the date rolls over the watcher moves
    to the new file automatically.
    """
    queries_dir = Path(log_dir)
    current_path = _current_log_path(queries_dir)
    current_date = date.today()

    try:
        f = open(current_path, "r", encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError) as e:
        logger.warning(f"Technitium DNS log could not be opened: {e} — Technitium capture disabled")
        return

    with f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if line:
                stripped = line.strip()
                if stripped:
                    yield ("technitium", stripped)
            else:
                time.sleep(0.1)
                today = date.today()
                if today != current_date:
                    # date rolled over — close old file and open the new one
                    current_date = today
                    current_path = _current_log_path(queries_dir)
                    try:
                        new_f = open(current_path, "r", encoding="utf-8", errors="replace")
                    except (FileNotFoundError, PermissionError) as e:
                        logger.warning(f"Could not open new Technitium log for {today}: {e}")
                        continue
                    f.close()
                    f = new_f
