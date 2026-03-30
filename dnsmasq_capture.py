import time

LOG_PATH = "/var/log/dnsmasq.log"

def tail_log(filepath: str = LOG_PATH):
    """
    Will watch the dnsmasq log, gives a new line when they come in.
    Will be running in conjunction with tshark.
    """

    with open(filepath, "r") as f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if line:
                yield ("dnsmasq", line.strip())  # tag the source
            else:
                time.sleep(0.1)