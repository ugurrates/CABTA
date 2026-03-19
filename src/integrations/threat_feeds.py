"""
Author: Ugur Ates
Free threat feed integrations with caching.

Sources:
- USOM (Turkish national CERT) - JSON API with cached lookups
- SSL Blacklist (abuse.ch) - CSV parsed into set with TTL cache
"""

import aiohttp
import time
import csv
import io
from typing import Dict, List, Set, Optional
import logging

logger = logging.getLogger(__name__)


class ThreatFeeds:
    """
    Free threat feed aggregator with in-memory caching.

    Feeds are downloaded once and cached for ``cache_ttl_seconds`` (default 1h).
    Subsequent lookups use the cached sets for fast O(1) membership testing.
    """

    DEFAULT_CACHE_TTL = 3600  # 1 hour

    def __init__(self, config: Dict):
        """Initialize threat feeds."""
        self.config = config
        self.timeout = aiohttp.ClientTimeout(total=30)
        self._cache_ttl = config.get('timeouts', {}).get(
            'feed_cache_ttl', self.DEFAULT_CACHE_TTL
        )

        # USOM caches
        self._usom_urls: Set[str] = set()
        self._usom_ips: Set[str] = set()
        self._usom_domains: Set[str] = set()
        self._usom_last_update: float = 0

        # SSL Blacklist caches
        self._sslbl_sha1: Set[str] = set()
        self._sslbl_ips: Set[str] = set()
        self._sslbl_last_update: float = 0

    # ------------------------------------------------------------------
    # USOM
    # ------------------------------------------------------------------

    async def _refresh_usom_cache(self) -> None:
        """Download and parse USOM feed lists into sets."""
        now = time.time()
        if now - self._usom_last_update < self._cache_ttl and self._usom_ips:
            return  # cache still valid

        logger.info("[USOM] Refreshing threat feed cache")
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # USOM JSON API (paginated, page 1 has most recent entries)
                api_url = 'https://www.usom.gov.tr/api/address/index?page=1'
                try:
                    async with session.get(api_url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            models = data.get('models', []) if isinstance(data, dict) else []
                            for entry in models:
                                value = entry.get('url', '') or entry.get('value', '')
                                ioc_type = entry.get('type', '')
                                value_lower = value.strip().lower()
                                if ioc_type == 'url' or '://' in value:
                                    self._usom_urls.add(value_lower)
                                elif ioc_type == 'ip':
                                    self._usom_ips.add(value_lower)
                                elif ioc_type == 'domain':
                                    self._usom_domains.add(value_lower)
                                else:
                                    # Generic: add to all relevant sets
                                    self._usom_ips.add(value_lower)
                                    self._usom_domains.add(value_lower)
                except Exception as e:
                    logger.warning(f"[USOM] JSON API failed, falling back to text lists: {e}")

                # Fallback: plain text lists
                for list_url, target_set in [
                    ('https://www.usom.gov.tr/url-list.txt', self._usom_urls),
                    ('https://www.usom.gov.tr/ip-list.txt', self._usom_ips),
                ]:
                    try:
                        async with session.get(list_url) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                for line in text.splitlines():
                                    line = line.strip().lower()
                                    if line and not line.startswith('#'):
                                        target_set.add(line)
                    except Exception as e:
                        logger.warning(f"[USOM] Failed to fetch {list_url}: {e}")

            self._usom_last_update = now
            total = len(self._usom_urls) + len(self._usom_ips) + len(self._usom_domains)
            logger.info(f"[USOM] Cache refreshed: {total} indicators loaded")

        except Exception as e:
            logger.error(f"[USOM] Cache refresh failed: {e}")

    async def check_usom(self, ioc: str) -> Dict:
        """
        Check IOC against USOM threat feed (cached).

        Args:
            ioc: IP, domain, or URL to check

        Returns:
            USOM check result dict
        """
        try:
            await self._refresh_usom_cache()

            ioc_lower = ioc.strip().lower()
            found_in: Optional[str] = None

            if ioc_lower in self._usom_ips:
                found_in = 'IP list'
            elif ioc_lower in self._usom_domains:
                found_in = 'Domain list'
            elif ioc_lower in self._usom_urls:
                found_in = 'URL list'
            else:
                # Check if domain is part of any cached URL
                for cached_url in self._usom_urls:
                    if ioc_lower in cached_url:
                        found_in = 'URL list (partial match)'
                        break

            if found_in:
                return {
                    'status': '✓',
                    'source': 'USOM',
                    'score': 85,
                    'message': f'Found in USOM {found_in}',
                    'found': True,
                }

            return {
                'status': '✗',
                'source': 'USOM',
                'score': 0,
                'message': 'Not found in USOM feeds',
                'found': False,
            }

        except Exception as e:
            logger.error(f"[USOM] Error: {e}")
            return {'status': '⚠', 'source': 'USOM', 'error': str(e), 'found': False}

    # ------------------------------------------------------------------
    # SSL Blacklist (abuse.ch)
    # ------------------------------------------------------------------

    async def _refresh_sslbl_cache(self) -> None:
        """Download and parse SSLBL CSV into sets of SHA1 fingerprints and IPs."""
        now = time.time()
        if now - self._sslbl_last_update < self._cache_ttl and self._sslbl_sha1:
            return

        logger.info("[SSLBL] Refreshing SSL Blacklist cache")
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    'https://sslbl.abuse.ch/blacklist/sslblacklist.csv'
                ) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        new_sha1: Set[str] = set()
                        new_ips: Set[str] = set()

                        for line in text.splitlines():
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            parts = line.split(',')
                            if len(parts) >= 2:
                                # CSV format: Listingdate,SHA1,Listingreason
                                sha1 = parts[1].strip().lower()
                                if len(sha1) == 40:
                                    new_sha1.add(sha1)
                            # Also try IP-based blacklist entries
                            if len(parts) >= 1:
                                candidate = parts[0].strip()
                                # Simple IPv4 check
                                octets = candidate.split('.')
                                if len(octets) == 4:
                                    try:
                                        if all(0 <= int(o) <= 255 for o in octets):
                                            new_ips.add(candidate)
                                    except ValueError:
                                        pass

                        self._sslbl_sha1 = new_sha1
                        self._sslbl_ips = new_ips
                        self._sslbl_last_update = now
                        logger.info(
                            f"[SSLBL] Cache refreshed: {len(new_sha1)} SHA1, "
                            f"{len(new_ips)} IPs"
                        )

                # Also fetch IP blacklist separately
                try:
                    async with session.get(
                        'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv'
                    ) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            for line in text.splitlines():
                                line = line.strip()
                                if not line or line.startswith('#'):
                                    continue
                                parts = line.split(',')
                                if parts:
                                    ip = parts[0].strip()
                                    octets = ip.split('.')
                                    if len(octets) == 4:
                                        try:
                                            if all(0 <= int(o) <= 255 for o in octets):
                                                self._sslbl_ips.add(ip)
                                        except ValueError:
                                            pass
                except Exception as e:
                    logger.warning(f"[SSLBL] IP blacklist fetch failed: {e}")

        except Exception as e:
            logger.error(f"[SSLBL] Cache refresh failed: {e}")

    async def check_ssl_blacklist(self, ioc: str) -> Dict:
        """
        Check IOC against SSL Blacklist (abuse.ch).

        Supports both SHA1 certificate fingerprints and IP addresses.

        Args:
            ioc: SHA1 hash or IP address

        Returns:
            SSL blacklist result dict
        """
        try:
            await self._refresh_sslbl_cache()

            ioc_lower = ioc.strip().lower()

            # Check as SHA1 fingerprint
            if len(ioc_lower) == 40 and all(c in '0123456789abcdef' for c in ioc_lower):
                if ioc_lower in self._sslbl_sha1:
                    return {
                        'status': '✓',
                        'source': 'SSL Blacklist',
                        'score': 90,
                        'message': 'Certificate SHA1 found in SSLBL',
                        'found': True,
                    }

            # Check as IP
            if ioc_lower in self._sslbl_ips:
                return {
                    'status': '✓',
                    'source': 'SSL Blacklist',
                    'score': 85,
                    'message': 'IP found in SSLBL C2 blacklist',
                    'found': True,
                }

            return {
                'status': '✗',
                'source': 'SSL Blacklist',
                'score': 0,
                'message': 'Not found in SSL Blacklist',
                'found': False,
            }

        except Exception as e:
            logger.error(f"[SSLBlacklist] Error: {e}")
            return {
                'status': '⚠',
                'source': 'SSL Blacklist',
                'error': str(e),
                'found': False,
            }
