import subprocess

INTERFACE = "eth0"  # Change this to match the network interface we're using

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

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,  # suppress tshark's status messages so they don't get in the way
        text=True
    )

    for line in process.stdout:
        line = line.strip()
        if line:
            yield ("tshark", line)  # tag the source so we know where caught it.