from dataclasses import  dataclass, field
from datetime import datetime, timezone


@dataclass
class Alert:
    timestamp: datetime
    source_ip: str
    domain: str
    severity: str   #"Low", "Medium", "High"
    score: int
    rules_triggered: list
    status: str = "new" #Default val, assuming we're going with new -> acknowledged -> resolved -> archived like we said.

@dataclass
class DnsEvent:
    timestamp: datetime
    source_ip: str
    domain: str
    query_type: str
    is_response: bool
    response_code: int
    resolved_ips: list = field(default_factory=list) #Sets the default obj type as list


##  We can use these to make sure we're always using the same format.
##  They're kinda like java record classes - Only exist to store data.
##  So Tissa can always know what format the data will be in for the DB, and I don't need to worry about mislabelling.
##  Might also help Rob if he needs to grab specific info from any of the events.

## So, when I'm creating an event, it will always look like this:
event = DnsEvent(
    timestamp=datetime.now(timezone.utc),
    source_ip="123.456.7.8",
    domain="badsite.xyz",
    query_type="A",
    is_response=False,
    response_code=0
)

'''
=== MOST COMMON QUERY TYPES ===
A - Looking for IPv4 address
AAAA - Looking for IPv6 address
MX - Looking for mail server (for email)
TXT - Looking for text records (Usually spam verification, etc)
CNAME - Looking for alias, as the domain points to another domain
PTR - Reverse lookup - if given IP, what's the name?
NS - What are the nameservers for the domain?
'''