dataModels.py will contain the format for all the events we'll be using.
  > ThreatCacheEntry, DnsEvent, Alert
> We all import and use the classes from here, to prevent any issues.
Since we're using two inputs (dnsMasq and tshark), we'll need to take both inputs and try normalise them.
    > So, we'll use tshark_capture.py to stream the data from tshark, dnsmasq_capture.py to stream the data from dnsmasq.
> Since that's two input streams, we'll need to combine them. For ease of naming, I'll just call it capture_combo.py.

Then, the output of capture_combo.py gets parsed and broken down to the specific parts to create a DNSEvent.
The DNSEvent gets sent to the threat detector, which will compare the domain against the blacklist and then the domain against a set of rules.
  i) Don't query too often in a minute
  ii) Not too many unique subdomains for a domain
  iii) Check for suspicious TLDs
  iv) Make sure that the domain doesn't look randomly generated
  v) Make sure the query doesn't return NXDOMAIN too often

Each of these rules will add to a score if triggered, and the higher the score, the higher the alert.
