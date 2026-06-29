import threading
import queue
from .technitium_capture import tail_log as technitium_tail_log
from .tshark_capture import stream_tshark


def combined_capture():
    """
    Combines two info sources: Technitium and tshark.
    Uses threading and queue to run them concurrently.
    
    Yields tuples of (source, line) where source is 'technitium' or 'tshark'.
    """
    q = queue.Queue()

    def run_technitium():
        for item in technitium_tail_log():
            q.put(item)

    def run_tshark():
        for item in stream_tshark():
            q.put(item)

    # Start both capture threads
    threading.Thread(target=run_technitium, daemon=True).start()
    threading.Thread(target=run_tshark, daemon=True).start()

    # Yield items as they arrive
    while True:
        yield q.get()
