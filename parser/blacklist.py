import threading
import requests     #For online requests
from urllib.parse import urlparse
from .input_parser import get_root_domain

# Major platforms where phishing pages get hosted — the domain itself is NOT malicious.
# Without this, URL-based feeds (OpenPhish) add e.g. 'github.com' to the blacklist
# just because a phishing page was hosted on GitHub, causing massive false positives.
WHITELISTED_DOMAINS = {
    "github.com", "githubusercontent.com", "raw.githubusercontent.com",
    "google.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "amazon.com", "amazonaws.com",
    "cloudflare.com", "cdn.jsdelivr.net", "jsdelivr.net",
    "facebook.com", "instagram.com",
    "youtube.com", "youtu.be",
    "twitter.com", "t.co",
    "linkedin.com",
    "apple.com", "icloud.com",
    "dropbox.com",
    "wordpress.com", "wp.com",
    "blogspot.com", "blogger.com",
    "bit.ly", "tinyurl.com",
}


class Blacklist:

    def __init__(self):
        self.domains: set = set()
        self._lock = threading.Lock()  # Stops read/write errors, only one thing can hold it at a time.
        self._refresh_urls: list = []  # store URLs so we can re-download them


    def load_from_file(self, filepath: str):
        """
                Load domains from local save file.
                Called at startup.
                This file is for if we want to create our own fake malicious site for testing, or if we have to test a specific site, or if we want to permanently flag a specific domain for some reason.
            """
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.domains.add(line.lower())
        print(f"Loaded {len(self.domains)} domains from {filepath}")

    #Download and add domains from a URL, will always be updated in the background.
    def load_from_url(self, url: str):
        try:
            response = requests.get(url, timeout=10)
            new_domains = set()
            for line in response.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    extracted = self.extract_domain(line)
                    if extracted:
                        new_domains.add(extracted)

            # Safely swap in the new domains, lock stops it causing an error.
            with self._lock:
                self.domains.update(new_domains)

            print(f"Loaded {len(self.domains)} domains total after refresh")

        except Exception as e:
            # If the download fails, keep using the existing list
            print(f"Blacklist refresh failed: {e}, keeping existing list")


    def start_auto_refresh(self, url: str, interval_hours: int = 24):
        """
                Start a background refresh cycle for the given URL.
                Refreshes immediately, then again every however many hours.
                Call this once per URL we want to keep updated.
            """
        self._refresh_urls.append(url)

        def refresh():
            print(f"Refreshing blacklist from {url}...")
            self.load_from_url(url)
            # Schedule the next refresh, otherwise it wouldn't restart
            t = threading.Timer(interval_hours * 3600, refresh)
            t.daemon = True # Now it won't block the code exiting.
            t.start()

        # Do the first refresh immediately instead of waiting 24hrs
        threading.Thread(target=refresh, daemon=True).start()

    def load_from_url_sync(self, url: str):
        """
            Downloads and loads a URL immediately, waiting for completion.
            Used at startup to ensure the blacklist is fully populated
            before beginning monitoring.
        """
        print(f"Loading {url}...")
        self.load_from_url(url)  # just calls the existing method directly
        print("Done.")

    #Check if a domain (or its root) is on the blacklist.
    def is_malicious(self, domain: str) -> bool:
        root = get_root_domain(domain)
        with self._lock:
            return domain in self.domains or root in self.domains

    def extract_domain(self, url_or_domain: str) -> str:
        """
            Will handle both plain domains and full URLs (Needed if using OpenPhish too)
            "https://evil.xyz/path" → "evil.xyz"
            "evil.xyz" → "evil.xyz"
            Skips whitelisted domains to avoid false positives from URL-based feeds.
        """
        if url_or_domain.startswith("http"):
            domain = urlparse(url_or_domain).netloc.lower()
        else:
            domain = url_or_domain.lower()

        # Skip whitelisted domains — they appear in feeds because phishing
        # pages are *hosted* on them, not because the domain is malicious.
        if domain in WHITELISTED_DOMAINS:
            return None
        return domain
