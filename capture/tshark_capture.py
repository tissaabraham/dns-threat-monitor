import subprocess
import logging
import platform
import re

logger = logging.getLogger(__name__)


def detect_interface() -> str:
    """
    Auto-detect the best network interface for the current platform.
    Queries tshark -D and picks from a platform-specific preference list.
    On Windows, tshark -D shows: N. \\Device\\NPF_{...} (Friendly Name)
    On Linux, tshark -D shows:   N. eth0
    """
    system = platform.system()
    if system == "Windows":
        preferred = ["Wi-Fi", "Ethernet", "Local Area Connection"]
    else:
        preferred = ["eth0", "wlan0", "enp0s3", "ens33"]

    try:
        result = subprocess.run(["tshark", "-D"], capture_output=True, text=True, timeout=5)
        lines = result.stdout.strip().splitlines()

        # Build list of (device_or_name, friendly_name) tuples
        interfaces = []
        for line in lines:
            line = re.sub(r"^\d+\.\s*", "", line)  # strip leading "N. "
            m = re.match(r"(\S+)\s+\((.+)\)$", line)
            if m:
                interfaces.append((m.group(1), m.group(2)))  # device path + friendly name
            else:
                interfaces.append((line.strip(), line.strip()))  # Linux: name only

        # Match preferred names against friendly names (case-insensitive)
        for pref in preferred:
            for _, friendly in interfaces:
                if pref.lower() == friendly.lower():
                    return friendly  # tshark accepts friendly names on Windows

        # Fall back to first non-loopback friendly name
        for _, friendly in interfaces:
            if "loopback" not in friendly.lower() and friendly.lower() != "lo":
                return friendly

    except Exception:
        pass

    return preferred[0]


INTERFACE = detect_interface()


def stream_tshark(interface: str = INTERFACE):
    """
    This will run tshark as a subprocess and give us the dns packet lines.
        For now, only running on port 53.

    Will be running in conjunction with DNSMASQ.
        Though, do we even need it if DNSMASQ is giving structured data too?
        Might catch something DNSMASQ misses at least.
    """
    cmd = [
        "tshark",
        "-i", interface,
        "-f", "udp port 53",    # only capture DNS traffic
        "-l",                    # clear the output after each packet (since we're streaming the info)
        "-T", "fields",          # Only outputting the specific fields
        "-e", "frame.time",     # Timestamp
        "-e", "ip.src",     #Source IP
        "-e", "ip.dst",     #Destination IP
        "-e", "dns.qry.name",   #Name of domain being queried
        "-e", "dns.qry.type",   #Type of DNS query
        "-e", "dns.flags.response", #Is it a response?
        "-e", "dns.resp.code",  #What's the response code?
        "-e", "dns.a",           #What's the IPV4 address?
        "-E", "separator=|"      # separate fields with a "|"
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # suppress tshark's status messages so they don't get in the way
            text=True
        )
    except FileNotFoundError:
        logger.warning("tshark not found — tshark capture disabled. Install Wireshark/tshark to enable packet capture.")
        return  # exit generator cleanly; capture thread will stop without crashing

    for line in process.stdout:
        line = line.strip()
        if line:
            yield ("tshark", line)  # tag the source so we know where caught it.