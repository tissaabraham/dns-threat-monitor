import threading
import requests     #For online requests
from urllib.parse import urlparse
from .input_parser import get_root_domain

class Blacklist:

    def __init__(self):
        self.domains: set = set()
        self._lock = threading.Lock()  # Stops read/write errors, only one thing can hold it at a time.
        self._refresh_urls: list = []  # store URLs so we can re-download them

    """
        Load domains from local save file.
        Called at startup.
        This file is for if we want to create our own fake malicious site for testing, or if we have to test a specific site, or if we want to permanently flag a specific domain for some reason.
    """
    def load_from_file(self, filepath: str):
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
                    new_domains.add(self.extract_domain(line))

            # Safely swap in the new domains, lock stops it causing an error.
            with self._lock:
                self.domains.update(new_domains)

            print(f"Loaded {len(self.domains)} domains total after refresh")

        except Exception as e:
            # If the download fails, keep using the existing list
            print(f"Blacklist refresh failed: {e}, keeping existing list")

    """
        Start a background refresh cycle for the given URL.
        Refreshes immediately, then again every however many hours.
        Call this once per URL we want to keep updated.
    """
    def start_auto_refresh(self, url: str, interval_hours: int = 24):
        self._refresh_urls.append(url)

        def refresh():
            print(f"Refreshing blacklist from {url}...")
            self.load_from_url(url)
            # Schedule the next refresh, otherwise it wouldn't restart
            threading.Timer(interval_hours * 3600, refresh).start()

        # Do the first refresh immediately instead of waiting 24hrs
        threading.Thread(target=refresh, daemon=True).start()

#Check if a domain (or its root) is on the blacklist.
    def is_malicious(self, domain: str) -> bool:
        root = get_root_domain(domain)
        with self._lock:
            return domain in self.domains or root in self.domains

    def extract_domain(self, url_or_domain: str) -> str:
        if url_or_domain.startswith("http"):
            return urlparse(url_or_domain).netloc.lower()
        return url_or_domain.lower()
"""
    Will handle both plain domains and full URLs (Needed if using OpenPhish too)
    "https://evil.xyz/path" → "evil.xyz"
    "evil.xyz" → "evil.xyz"
"""