import re   #RegEx
from datetime import datetime, timezone
from database.dataModels import DnsEvent

# dnsmasq log pattern - searches the input for matching format.
DNSMASQ_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+"
    r"dnsmasq\[\d+\]:\s+"
    r"(?P<event_type>query|reply)\[?(?P<query_type>[A-Z]*)\]?\s+"
    r"(?P<domain>[\w.\-]+)\s+"
    r"(?P<connector>from|is|to)\s+"
    r"(?P<value>[\w.\-:]+)"
)

# Technitium DNS log pattern - searches the input for matching format.
# Actual format: [2026-06-29 18:49:35 UTC] [127.0.0.1:12345] [UDP] QNAME: example.com; QTYPE: A; QCLASS: IN; RCODE: NoError; ANSWER: [1.2.3.4]
TECHNITIUM_PATTERN = re.compile(
    r"\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?:UTC|Local)\]\s+"
    r"\[(?P<client>[\d.:a-fA-F]+):\d+\]\s+"
    r"\[[A-Z]+\]\s+"
    r"QNAME:\s+(?P<domain>[\w.\-]+);\s+"
    r"QTYPE:\s+(?P<query_type>[A-Z]+);\s+"
    r"QCLASS:\s+\w+;\s+"
    r"RCODE:\s+(?P<response_code>\w+);\s+"
    r"ANSWER:\s+\[(?P<answer>[^\]]*)?\]"
)

#Parse dnsmasq log line into a DnsEvent.
def parse_dnsmasq_line(line: str) -> DnsEvent | None:

    match = DNSMASQ_PATTERN.match(line)
    if not match:
        return None

    groups = match.groupdict()
    timestamp_str = f"{groups['month']} {groups['day']} {groups['time']} 2026"
    timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
    timestamp = timestamp.replace(tzinfo=timezone.utc)

    is_response = groups["event_type"] == "reply"
    connector = groups.get("connector")
    value = groups["value"]

    # Detect NXDOMAIN-style replies where dnsmasq logs "reply <domain> from <ip>"
    # (i.e. no 'is <ip>' payload). In these cases we treat as NXDOMAIN (response_code 3)
    if is_response and connector == "from":
        response_code = 3
        resolved_ips = []
    else:
        response_code = 3 if value == "NXDOMAIN" else 0
        resolved_ips = [value] if is_response and value != "NXDOMAIN" else []

    return DnsEvent(
        timestamp=timestamp,
        source_ip="" if is_response else value,
        domain=normalise_domain(groups["domain"]),
        query_type=groups["query_type"] or "UNKNOWN",
        is_response=is_response,
        response_code=response_code,
        resolved_ips=resolved_ips
    )

def parse_technitium_line(line: str) -> DnsEvent | None:
    """
    Parse Technitium DNS log line into a DnsEvent.
    """
    match = TECHNITIUM_PATTERN.match(line)
    if not match:
        return None

    groups = match.groupdict()

    try:
        timestamp = datetime.strptime(
            groups['timestamp'], "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        timestamp = datetime.now(timezone.utc)

    response_code_map = {
        "NoError": 0,
        "NxDomain": 3,
        "ServFail": 2,
        "Refused": 5,
        "NOERROR": 0,
        "NXDOMAIN": 3,
        "SERVFAIL": 2,
        "REFUSED": 5,
    }
    response_code = response_code_map.get(groups.get("response_code", ""), 0)
    is_nxdomain = response_code == 3

    answer_raw = (groups.get("answer") or "").strip()
    resolved_ips = [a.strip() for a in answer_raw.split(",") if a.strip() and not is_nxdomain]

    return DnsEvent(
        timestamp=timestamp,
        source_ip=groups["client"],
        domain=normalise_domain(groups["domain"]),
        query_type=groups["query_type"] or "UNKNOWN",
        is_response=True,
        response_code=response_code,
        resolved_ips=resolved_ips
    )

"""
    Parse a tshark line into a DnsEvent.
    Tshark fields:
        timestamp|src_ip|dst_ip|domain|query_type|is_response|resp_code|resolved_ip
"""
def parse_tshark_line(line: str) -> DnsEvent | None:
    parts = line.split("|")
    if len(parts) < 8:
        return None

    timestamp_raw, src_ip, dst_ip, domain, qtype, is_resp, resp_code, resolved = parts

    if not domain:
        return None  # not a DNS query we care about

    try:
        timestamp = datetime.strptime(
            timestamp_raw.strip(), "%b %d, %Y %H:%M:%S.%f %Z"
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        timestamp = datetime.now(timezone.utc)  # fallback if format differs

    is_response = is_resp == "1"
    response_code = int(resp_code) if resp_code.strip().isdigit() else 0
    resolved_ips = [resolved] if resolved.strip() else []

    return DnsEvent(
        timestamp=timestamp,
        source_ip=src_ip.strip(),
        domain=normalise_domain(domain.strip()),
        query_type=qtype.strip() or "UNKNOWN",
        is_response=is_response,
        response_code=response_code,
        resolved_ips=resolved_ips
    )

def parse_line(source: str, line: str) -> DnsEvent | None:
    """
    Sends a line to the right parse method depending on the source.
    ToDo Only method main.py should be calling from here.
    """
    if source == "dnsmasq":
        return parse_dnsmasq_line(line)
    elif source == "technitium":
        return parse_technitium_line(line)
    elif source == "tshark":
        return parse_tshark_line(line)
    return None

#If we're trying to match with our lists, best to be normalised.
#Will also remove any trailing '.'s, just in case.
def normalise_domain(domain: str) -> str:
    return domain.rstrip(".").lower()

def get_root_domain(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain
#If the domain contains a subdomain, remove it and take just the actual domain and TLD.