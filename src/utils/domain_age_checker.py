"""
Blue Team Assistant - Domain Age Checker

WHOIS-based domain age analysis for threat intelligence enrichment.
Newly registered domains are a strong indicator of malicious infrastructure.

Author: Ugur Ates
"""

import logging
import socket
import threading
from datetime import datetime, timezone
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory cache (thread-safe)
# ---------------------------------------------------------------------------

_cache: Dict[str, Dict] = {}
_cache_lock = threading.Lock()
_CACHE_MAX_SIZE = 1024


def _cache_get(domain: str) -> Optional[Dict]:
    """Retrieve cached WHOIS result."""
    with _cache_lock:
        return _cache.get(domain)


def _cache_set(domain: str, result: Dict) -> None:
    """Store WHOIS result in cache (LRU eviction when full)."""
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX_SIZE:
            # Evict oldest entry
            oldest_key = next(iter(_cache))
            del _cache[oldest_key]
        _cache[domain] = result


# ---------------------------------------------------------------------------
# Risk-level thresholds (days)
# ---------------------------------------------------------------------------

_THRESHOLDS = {
    'critical': 7,      # < 7 days old
    'high': 30,          # < 30 days old
    'medium': 90,        # < 90 days old
    'low': 365,          # < 1 year old
}


def _determine_risk_level(age_days: int) -> str:
    """Map domain age to risk level."""
    if age_days < 0:
        return 'unknown'
    if age_days < _THRESHOLDS['critical']:
        return 'critical'
    if age_days < _THRESHOLDS['high']:
        return 'high'
    if age_days < _THRESHOLDS['medium']:
        return 'medium'
    if age_days < _THRESHOLDS['low']:
        return 'low'
    return 'none'


# ---------------------------------------------------------------------------
# WHOIS lookup strategies
# ---------------------------------------------------------------------------

def _whois_lookup(domain: str) -> Optional[datetime]:
    """Primary: use python-whois library to get creation_date."""
    try:
        import whois  # python-whois
        w = whois.whois(domain)

        creation_date = w.creation_date
        if creation_date is None:
            return None

        # Some registrars return a list of dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Ensure it is a datetime
        if isinstance(creation_date, datetime):
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            return creation_date

        # Attempt to parse string representation
        if isinstance(creation_date, str):
            for fmt in (
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d',
                '%d-%b-%Y',
            ):
                try:
                    dt = datetime.strptime(creation_date, fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

        return None

    except ImportError:
        logger.debug("[DOMAIN-AGE] python-whois not installed, falling back to socket WHOIS")
        return None
    except Exception as exc:
        logger.debug(f"[DOMAIN-AGE] python-whois failed for {domain}: {exc}")
        return None


def _socket_whois_lookup(domain: str, timeout: int = 10) -> Optional[datetime]:
    """Fallback: raw socket WHOIS query to whois.iana.org / registrar servers."""
    try:
        # Query the appropriate WHOIS server
        tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
        whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'info': 'whois.afilias.net',
            'io': 'whois.nic.io',
            'co': 'whois.nic.co',
            'xyz': 'whois.nic.xyz',
            'ru': 'whois.tcinet.ru',
            'de': 'whois.denic.de',
            'uk': 'whois.nic.uk',
        }
        server = whois_servers.get(tld, 'whois.iana.org')

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, 43))
        sock.sendall((domain + '\r\n').encode('utf-8'))

        response = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        text = response.decode('utf-8', errors='ignore').lower()

        # Parse creation date from raw WHOIS text
        creation_keywords = [
            'creation date:', 'created:', 'created on:', 'registration date:',
            'domain name commencement date:', 'registered on:', 'registered:',
        ]

        for line in text.splitlines():
            line_stripped = line.strip()
            for keyword in creation_keywords:
                if line_stripped.startswith(keyword):
                    date_str = line_stripped[len(keyword):].strip()
                    return _parse_date_string(date_str)

        return None

    except (socket.timeout, socket.error) as exc:
        logger.debug(f"[DOMAIN-AGE] Socket WHOIS failed for {domain}: {exc}")
        return None
    except Exception as exc:
        logger.debug(f"[DOMAIN-AGE] Socket WHOIS unexpected error for {domain}: {exc}")
        return None


def _parse_date_string(date_str: str) -> Optional[datetime]:
    """Try multiple date formats to parse a date string."""
    formats = [
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d',
        '%d-%b-%Y',
        '%d/%m/%Y',
        '%Y/%m/%d',
        '%d.%m.%Y',
        '%Y.%m.%d',
    ]
    # Clean up common suffixes
    date_str = date_str.strip().rstrip('.')

    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_domain_age(domain: str, timeout: int = 10) -> Dict:
    """
    Check domain age via WHOIS lookup.

    Uses python-whois library with fallback to raw socket WHOIS.
    Results are cached in memory to avoid repeated lookups.

    Args:
        domain: Domain name to check (e.g., 'example.com')
        timeout: Socket timeout in seconds for fallback method

    Returns:
        Structured result::

            {
                'domain': str,
                'creation_date': str | None,   # ISO format
                'age_days': int | None,
                'is_newly_registered': bool,    # True if < 30 days
                'risk_level': str,              # critical/high/medium/low/none/unknown
                'error': str | None,
            }
    """
    # Normalize
    domain = domain.lower().strip().rstrip('.')
    if not domain:
        return _error_result(domain, 'Empty domain')

    # Check cache
    cached = _cache_get(domain)
    if cached is not None:
        logger.debug(f"[DOMAIN-AGE] Cache hit: {domain}")
        return cached

    logger.info(f"[DOMAIN-AGE] Checking domain age: {domain}")

    # Strategy 1: python-whois
    creation_date = _whois_lookup(domain)

    # Strategy 2: raw socket fallback
    if creation_date is None:
        creation_date = _socket_whois_lookup(domain, timeout=timeout)

    # Build result
    if creation_date is None:
        result = _error_result(domain, 'No WHOIS creation date available')
        _cache_set(domain, result)
        return result

    now = datetime.now(timezone.utc)
    age_days = (now - creation_date).days

    result = {
        'domain': domain,
        'creation_date': creation_date.isoformat(),
        'age_days': age_days,
        'is_newly_registered': age_days < 30,
        'risk_level': _determine_risk_level(age_days),
        'error': None,
    }

    logger.info(
        f"[DOMAIN-AGE] {domain} registered {age_days} days ago "
        f"(risk: {result['risk_level']})"
    )

    _cache_set(domain, result)
    return result


def _error_result(domain: str, error_msg: str) -> Dict:
    """Return a standardized error result."""
    return {
        'domain': domain,
        'creation_date': None,
        'age_days': None,
        'is_newly_registered': False,
        'risk_level': 'unknown',
        'error': error_msg,
    }


def clear_cache() -> None:
    """Clear the domain age cache."""
    with _cache_lock:
        _cache.clear()
    logger.debug("[DOMAIN-AGE] Cache cleared")
