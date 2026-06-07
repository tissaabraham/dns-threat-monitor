import threading
import queue
import platform
from .dnsmasq_capture import tail_log
from .tshark_capture import stream_tshark


def combined_capture():
    """
    For now we're using two info sources, which are outputting data at the same time.
        > Thanks to DNS encryption, we gotta use both. Tshark will tell us when something gets around DNSMASQ and communicates privately.
    Since we gotta read both in the main.py, if we don't combine them, then tail_log() never ends, and stream_tshark() never starts.
    Threading lets us run two methods concurrently, capturing both outputs as a unified stream.
    And since the code can only read one input at a time, we'll use the queue.
        As a source sends on an input, they'll form... a queue.
            The code will then look at the input at the top of the queue in the order they cmoe in.

    Yield() will give a tuple (from either of the sources) as they reach the top of the queue.
        (source [tshark/dnsmasq], captured packet line)
    """
    q = queue.Queue()

    def run_dnsmasq():
        for item in tail_log():
            q.put(item)

    def run_tshark():
        for item in stream_tshark():
            q.put(item)

    # dnsmasq only exists on Linux — skip it on Windows
    if platform.system() != "Windows":
        threading.Thread(target=run_dnsmasq, daemon=True).start()

    threading.Thread(target=run_tshark, daemon=True).start()    #daemon=True will kill the two methods when we stop the program

    # Make a tuple from inputs as they arrive
    while True:
        yield q.get()   #If queue empty, simply waits for next input