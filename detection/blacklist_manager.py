"""
Blacklist Manager Module

Manages fetching and updating malicious domain blacklists from multiple sources.
"""

import logging
import requests
from typing import Set
from datetime import datetime, timedelta
import json
import csv
from io import StringIO

logger = logging.getLogger(__name__)


class BlacklistManager:
    """
    Manages malicious domain blacklist updates from multiple sources.
    
    Sources:
    - URLhaus: https://urlhaus-api.abuse.ch/v1/urls/csv/
    - OpenPhish: https://openphish.com/feed.txt
    - Malware Domains List
    """
    
    def __init__(self, update_interval_hours: int = 24):
        """
        Initialize blacklist manager.
        
        Args:
            update_interval_hours: Hours between blacklist updates
        """
        self.update_interval = timedelta(hours=update_interval_hours)
        self.last_update = None
        self.blacklist = set()
        
    def should_update(self) -> bool:
        """Check if blacklist should be updated."""
        if self.last_update is None:
            return True
        return datetime.now() - self.last_update >= self.update_interval
    
    def update_blacklist(self) -> bool:
        """
        Update blacklist from all sources.
        
        Returns:
            True if update successful
        """
        if not self.should_update():
            logger.info("Blacklist recently updated, skipping update")
            return False
        
        try:
            logger.info("Updating malicious domain blacklist...")
            
            # Update from URLhaus
            urlhaus_domains = self._fetch_urlhaus()
            logger.info(f"Fetched {len(urlhaus_domains)} domains from URLhaus")
            
            # Update from OpenPhish
            openphish_domains = self._fetch_openphish()
            logger.info(f"Fetched {len(openphish_domains)} domains from OpenPhish")
            
            # Combine all sources
            self.blacklist = urlhaus_domains | openphish_domains
            self.last_update = datetime.now()
            
            logger.info(f"Blacklist updated with {len(self.blacklist)} total domains")
            return True
            
        except Exception as e:
            logger.error(f"Error updating blacklist: {e}")
            return False
    
    def _fetch_urlhaus(self) -> Set[str]:
        """Fetch malicious domains from URLhaus."""
        try:
            url = "https://urlhaus-api.abuse.ch/v1/urls/csv/"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            domains = set()
            reader = csv.DictReader(StringIO(response.text))
            for row in reader:
                if 'domain' in row:
                    domain = row['domain'].strip().lower()
                    if domain:
                        domains.add(domain)
            
            return domains
        except Exception as e:
            logger.error(f"Error fetching URLhaus data: {e}")
            return set()
    
    def _fetch_openphish(self) -> Set[str]:
        """Fetch phishing domains from OpenPhish."""
        try:
            url = "https://openphish.com/feed.txt"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            domains = set()
            for line in response.text.strip().split('\n'):
                if line.startswith('http'):
                    # Extract domain from URL
                    try:
                        from urllib.parse import urlparse
                        domain = urlparse(line).netloc.lower()
                        if domain:
                            domains.add(domain)
                    except:
                        pass
            
            return domains
        except Exception as e:
            logger.error(f"Error fetching OpenPhish data: {e}")
            return set()
    
    def get_blacklist(self) -> Set[str]:
        """Get current blacklist."""
        return self.blacklist.copy()
    
    def get_blacklist_stats(self) -> dict:
        """Get blacklist statistics."""
        return {
            'total_domains': len(self.blacklist),
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'next_update': (self.last_update + self.update_interval).isoformat() 
                          if self.last_update else None
        }

