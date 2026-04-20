
"""
This is just for testing my section of the code, can be implemented with the main code when
"""
from parser.blacklist import Blacklist
import time

def main():
    blacklist = Blacklist()
    blacklist.load_from_file("threats.txt") # Load local threats file immediately (Our own custom list of domains for testing.)

    # Start auto-refreshing from live threat feeds, a new method call for each
    blacklist.start_auto_refresh("https://urlhaus.abuse.ch/downloads/text/", interval_hours=24)
    blacklist.start_auto_refresh("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", interval_hours=12)  # this one refreshes more frequently
    """
        From here on, blacklist.is_malicious() will always use the most current list, shouldn't need to think about it again.
        Will need to look into reaching out to OpenPhish to maybe use the non-free version.
    """
    time.sleep(5)
    print("There are currently this many URLs known:", len(blacklist.domains))


if __name__ == "__main__":
    main()