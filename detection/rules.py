from collections import defaultdict, deque
from datetime import datetime, timedelta
from database.dataModels import DnsEvent
import math
from collections import Counter
from config.config import Config

class RuleEngine:
    """
    Checks events against a set of rules.
        -> Keeps track of recent activity to spot patterns over time.
    """

    SUSPICIOUS_TLDS = Config.SUSPICIOUS_TLDS
    QUERY_RATE_LIMIT = Config.HIGH_QUERY_RATE_LIMIT
    NXDOMAIN_LIMIT = Config.NXDOMAIN_LIMIT
    SUBDOMAIN_LIMIT = Config.SUBDOMAIN_LIMIT

    def __init__(self):
        # These track recent events per IP address
        # deque is like a list but more efficient for adding/removing from both ends, apparently
        self.query_times: dict = defaultdict(deque)  # IP → [timestamps]
        self.nxdomain_times: dict = defaultdict(deque)  # IP → [timestamps]
        self.subdomains: dict = defaultdict(set)  # root domain → {subdomains}

    def check(self, event: DnsEvent) -> list:
        #Returns a list of rule names that were triggered.

        triggered = []

        if self._check_suspicious_tld(event):
            triggered.append("suspicious_tld")

        if self._check_high_query_rate(event):
            triggered.append("high_query_rate")

        if self._check_nxdomain_flood(event):
            triggered.append("nxdomain_flood")

        if self._check_subdomain_abuse(event):
            triggered.append("subdomain_abuse")

        if self._check_dga_pattern(event):
            triggered.append("dga_pattern")

        return triggered

    def _check_suspicious_tld(self, event: DnsEvent) -> bool:
        #Flag domains with known unusual top-level domains.
        for tld in self.SUSPICIOUS_TLDS:
            if event.domain.endswith(tld):
                return True
        return False

    def _check_high_query_rate(self, event: DnsEvent) -> bool:
        #Flag if one device is making too many queries per minute.
        return self._rate_exceeded(
            self.query_times[event.source_ip],
            window_seconds=60,
            limit=self.QUERY_RATE_LIMIT,
            now=event.timestamp
        )

    def _check_nxdomain_flood(self, event: DnsEvent) -> bool:
        #Flag if one device is getting too many 'not found' replies.
        if not (event.is_response and event.response_code == 3):
            return False  # not an NXDOMAIN, skip
        return self._rate_exceeded(
            self.nxdomain_times[event.source_ip],
            window_seconds=60,
            limit=self.NXDOMAIN_LIMIT,
            now=event.timestamp
        )

    def _check_subdomain_abuse(self, event: DnsEvent) -> bool:
        """
        Flag if too many unique subdomains of one domain are being queried.
        e.g. data1.evil.com, data2.evil.com, data3.evil.com...
            -> Signs of DNS tunnelling
        """
        parts = event.domain.split(".")
        if len(parts) < 3:
            return False  # no subdomain to check

        root = ".".join(parts[-2:])
        subdomain = parts[0]
        self.subdomains[root].add(subdomain)
        return len(self.subdomains[root]) > self.SUBDOMAIN_LIMIT

    def _rate_exceeded(self, timestamps: deque, window_seconds: int,
                       limit: int, now: datetime) -> bool:
        """
        Helper: checks if 'limit' events occurred within the window.
        Removes timestamps that are outside the window as it goes.
        """
        window = timedelta(seconds=window_seconds)
        timestamps.append(now)
        while timestamps and now - timestamps[0] > window:
            timestamps.popleft()  # remove old events outside the window
        return len(timestamps) > limit


    @staticmethod #Since not touching instance data, needs to be static
    def _string_entropy(s: str) -> float:  #Uses Shannon Entropy to detect randomness
        """
            Higher value, more random.
            Lower value, less random/more predictable.
            It's not the most effective, but it still helps.
                abcabcabc   - Moderately random
                bbbbbbbbb   - Very random
                ababababa   - Slightly more random
                    > Counts repeats of individual letters basically, so it's not foolproof.
                > Still, should help with randomly generated domains.
        """
        counts = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())



    @staticmethod
    def _looks_like_dga(domain: str) -> bool:
        """
                Check to see if it could be a Domain Generation Algorithm,
                making different domains for DDOS and DNS tunnelling.
                Sends the domains to the entropy checker, which will then have it's result checked.
        """
        label = domain.split(".")[0]  # just the leftmost label
        # Consider long labels likely DGA-ish, or very high-entropy short labels
        return len(label) > 12 or RuleEngine._string_entropy(label) > 3.0

    def _check_dga_pattern(self, event: DnsEvent) -> bool:
        return self._looks_like_dga(event.domain)