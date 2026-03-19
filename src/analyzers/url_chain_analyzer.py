"""
Author: Ugur Ates
URL Chain Analyzer - Redirect Following & Reputation Check
Best Practice: Follow redirect chains, detect phishing infrastructure
"""

import re
import logging
import unicodedata
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs
import requests

logger = logging.getLogger(__name__)
class URLChainAnalyzer:
    """
    URL redirect chain analysis and reputation checking.
    
    Features:
    - Redirect chain following
    - URL defanging
    - Suspicious TLD detection
    - URL shortener detection
    - Parameter extraction
    - Domain reputation (if integrated)
    """
    
    SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
        'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in'
    ]
    
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
        '.top', '.xyz', '.club', '.work', '.click',
        '.loan', '.download', '.racing', '.accountant', '.win'
    ]
    
    @staticmethod
    def analyze_url(url: str, follow_redirects: bool = True, max_hops: int = 10) -> Dict:
        """
        Analyze URL and follow redirect chain.
        
        Args:
            url: URL to analyze
            follow_redirects: Follow redirects
            max_hops: Maximum redirect hops
        
        Returns:
            Complete URL analysis
        """
        result = {
            'original_url': url,
            'parsed': {},
            'redirect_chain': [],
            'final_url': url,
            'total_hops': 0,
            'is_shortened': False,
            'suspicious_tld': False,
            'risk_score': 0,
            'indicators': []
        }
        
        try:
            # Parse URL
            result['parsed'] = URLChainAnalyzer._parse_url(url)
            
            # Check if shortened
            if result['parsed']['domain'] in URLChainAnalyzer.SHORTENERS:
                result['is_shortened'] = True
                result['indicators'].append('URL shortener detected')
                result['risk_score'] += 10
            
            # Check TLD
            tld = '.' + result['parsed']['domain'].split('.')[-1]
            if tld in URLChainAnalyzer.SUSPICIOUS_TLDS:
                result['suspicious_tld'] = True
                result['indicators'].append(f'Suspicious TLD: {tld}')
                result['risk_score'] += 15
            
            # Follow redirects
            if follow_redirects:
                chain = URLChainAnalyzer._follow_redirects(url, max_hops)
                result['redirect_chain'] = chain
                result['total_hops'] = len(chain)
                if chain:
                    result['final_url'] = chain[-1]['url']
                
                # Check for excessive redirects
                if result['total_hops'] > 5:
                    result['indicators'].append('Excessive redirects')
                    result['risk_score'] += 20
            
            # Check for IP-based URLs
            if URLChainAnalyzer._is_ip_url(url):
                result['indicators'].append('IP-based URL (suspicious)')
                result['risk_score'] += 25
            
            logger.info(f"[URL-CHAIN] Analysis complete - Risk: {result['risk_score']}")
            
        except Exception as e:
            logger.error(f"[URL-CHAIN] Analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _parse_url(url: str) -> Dict:
        """Parse URL components."""
        parsed = urlparse(url)
        
        return {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path,
            'params': parse_qs(parsed.query),
            'fragment': parsed.fragment
        }
    
    @staticmethod
    def _follow_redirects(url: str, max_hops: int) -> List[Dict]:
        """Follow HTTP redirects."""
        chain = []
        
        try:
            session = requests.Session()
            session.max_redirects = max_hops
            
            response = session.get(
                url,
                allow_redirects=True,
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            # Get redirect chain from history
            for resp in response.history:
                chain.append({
                    'url': resp.url,
                    'status': resp.status_code,
                    'location': resp.headers.get('Location', '')
                })
            
            # Add final URL
            chain.append({
                'url': response.url,
                'status': response.status_code,
                'location': ''
            })
        
        except Exception as e:
            logger.warning(f"[URL-CHAIN] Redirect following failed: {e}")
        
        return chain
    
    @staticmethod
    def _is_ip_url(url: str) -> bool:
        """Check if URL uses IP address instead of domain."""
        ip_pattern = r'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
        return bool(re.match(ip_pattern, url))

    # ------------------------------------------------------------------
    # URL Defanging
    # ------------------------------------------------------------------

    @staticmethod
    def defang_url(url: str) -> str:
        """
        Defang a URL for safe sharing in reports and tickets.

        Replaces ``http`` with ``hxxp``, ``://`` with ``[://]``, and
        ``.`` in the domain with ``[.]``.

        Example::

            https://evil.com/payload  ->  hxxps[://]evil[.]com/payload
        """
        defanged = url.replace('https://', 'hxxps[://]').replace('http://', 'hxxp[://]')
        # Split at the protocol replacement to find the domain+path part
        for proto in ('hxxps[://]', 'hxxp[://]'):
            if defanged.startswith(proto):
                remainder = defanged[len(proto):]
                slash_idx = remainder.find('/')
                if slash_idx >= 0:
                    domain_part = remainder[:slash_idx].replace('.', '[.]')
                    return proto + domain_part + '/' + remainder[slash_idx + 1:]
                else:
                    return proto + remainder.replace('.', '[.]')
        # No scheme matched, just defang dots everywhere
        return defanged.replace('.', '[.]')

    @staticmethod
    def refang_url(defanged: str) -> str:
        """
        Reverse defanging to restore the original URL.

        Reverses the transformations applied by :meth:`defang_url`.
        """
        url = defanged.replace('hxxps[://]', 'https://').replace('hxxp[://]', 'http://')
        url = url.replace('[.]', '.')
        return url

    # ------------------------------------------------------------------
    # Homograph / IDN Detection
    # ------------------------------------------------------------------

    # Characters that visually resemble ASCII letters (partial map)
    CONFUSABLES = {
        '\u0430': 'a',  # Cyrillic а
        '\u0435': 'e',  # Cyrillic е
        '\u043e': 'o',  # Cyrillic о
        '\u0440': 'p',  # Cyrillic р
        '\u0441': 'c',  # Cyrillic с
        '\u0445': 'x',  # Cyrillic х
        '\u0443': 'y',  # Cyrillic у
        '\u04bb': 'h',  # Cyrillic Һ
        '\u0456': 'i',  # Cyrillic і
        '\u0455': 's',  # Cyrillic ѕ
        '\u0501': 'd',  # Cyrillic ԁ
        '\u051b': 'q',  # Cyrillic ԛ
        '\u0261': 'g',  # Latin small g hook
        '\u1d00': 'a',  # Latin letter small capital A
    }

    @staticmethod
    def detect_homograph(domain: str) -> Dict:
        """
        Detect IDN homograph attacks in a domain name.

        Checks whether the domain contains mixed Unicode scripts or
        characters from the confusables table.

        Returns a dict with ``is_homograph``, ``scripts_found``,
        ``confusable_chars``, and ``ascii_equivalent``.
        """
        result: Dict = {
            'is_homograph': False,
            'domain': domain,
            'scripts_found': set(),
            'confusable_chars': [],
            'ascii_equivalent': '',
            'risk_score': 0,
        }

        ascii_equiv_parts: List[str] = []
        has_non_ascii = False

        for ch in domain:
            if ch in ('.', '-'):
                ascii_equiv_parts.append(ch)
                continue

            script = unicodedata.category(ch)
            try:
                script_name = unicodedata.script(ch) if hasattr(unicodedata, 'script') else unicodedata.name(ch, '').split()[0]
            except (ValueError, IndexError):
                script_name = 'UNKNOWN'
            result['scripts_found'].add(script_name)

            if ord(ch) > 127:
                has_non_ascii = True
                mapped = URLChainAnalyzer.CONFUSABLES.get(ch)
                if mapped:
                    result['confusable_chars'].append({
                        'char': ch,
                        'codepoint': f'U+{ord(ch):04X}',
                        'looks_like': mapped,
                    })
                    ascii_equiv_parts.append(mapped)
                else:
                    ascii_equiv_parts.append('?')
            else:
                ascii_equiv_parts.append(ch)

        result['ascii_equivalent'] = ''.join(ascii_equiv_parts)
        result['scripts_found'] = list(result['scripts_found'])

        if has_non_ascii:
            result['is_homograph'] = True
            result['risk_score'] = 40
            if result['confusable_chars']:
                result['risk_score'] = 80  # high confidence attack

        return result

    # ------------------------------------------------------------------
    # Typosquatting Detection
    # ------------------------------------------------------------------

    POPULAR_DOMAINS = [
        'google.com', 'facebook.com', 'amazon.com', 'apple.com',
        'microsoft.com', 'paypal.com', 'netflix.com', 'linkedin.com',
        'twitter.com', 'instagram.com', 'github.com', 'dropbox.com',
        'yahoo.com', 'outlook.com', 'office365.com', 'chase.com',
        'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
        'dhl.com', 'fedex.com', 'ups.com', 'usps.com',
    ]

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Compute Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return URLChainAnalyzer._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(
                    prev[j + 1] + 1,      # deletion
                    curr[j] + 1,           # insertion
                    prev[j] + (c1 != c2),  # substitution
                ))
            prev = curr
        return prev[-1]

    @classmethod
    def detect_typosquatting(cls, domain: str, threshold: int = 2) -> List[Dict]:
        """
        Detect typosquatting by comparing the domain against popular targets.

        Returns a list of matches where Levenshtein distance <= *threshold*.
        Common patterns detected:
        - Character substitution (``goggle.com``)
        - Missing/extra characters (``gogle.com``, ``gooogle.com``)
        - Transposed characters (``goolge.com``)
        """
        matches: List[Dict] = []
        domain_lower = domain.lower().strip()

        # Only compare the second-level domain (strip TLD)
        domain_base = domain_lower.rsplit('.', 1)[0] if '.' in domain_lower else domain_lower

        for target in cls.POPULAR_DOMAINS:
            target_base = target.rsplit('.', 1)[0]
            if domain_base == target_base:
                continue  # exact match, not typosquatting

            dist = cls._levenshtein(domain_base, target_base)
            if 0 < dist <= threshold:
                # Classify the squatting technique
                technique = 'character substitution'
                if len(domain_base) != len(target_base):
                    if len(domain_base) > len(target_base):
                        technique = 'extra character (addition)'
                    else:
                        technique = 'missing character (omission)'
                elif dist == 1:
                    # Check for transposition
                    for k in range(len(domain_base) - 1):
                        swapped = list(target_base)
                        swapped[k], swapped[k + 1] = swapped[k + 1], swapped[k]
                        if ''.join(swapped) == domain_base:
                            technique = 'character transposition'
                            break

                matches.append({
                    'target_domain': target,
                    'distance': dist,
                    'technique': technique,
                    'risk': 'HIGH' if dist == 1 else 'MEDIUM',
                })

        return matches

    # ------------------------------------------------------------------
    # Enhanced analysis combining all checks
    # ------------------------------------------------------------------

    @classmethod
    def deep_analyze_url(cls, url: str, follow_redirects: bool = True) -> Dict:
        """
        Perform a deep URL analysis combining redirect chain, homograph,
        typosquatting, defanging, and risk scoring.
        """
        # Start with basic analysis
        result = cls.analyze_url(url, follow_redirects=follow_redirects)

        domain = result.get('parsed', {}).get('domain', '')
        if not domain:
            return result

        # Homograph detection
        homograph = cls.detect_homograph(domain)
        result['homograph'] = homograph
        if homograph['is_homograph']:
            result['indicators'].append('IDN homograph attack detected')
            result['risk_score'] += homograph['risk_score']

        # Typosquatting detection
        typosquat = cls.detect_typosquatting(domain)
        result['typosquatting'] = typosquat
        if typosquat:
            best = typosquat[0]
            result['indicators'].append(
                f"Possible typosquatting of {best['target_domain']} "
                f"(distance={best['distance']}, {best['technique']})"
            )
            result['risk_score'] += 30 if best['distance'] == 1 else 20

        # Defanged version
        result['defanged_url'] = cls.defang_url(url)

        # Cap risk score at 100
        result['risk_score'] = min(result['risk_score'], 100)

        return result


def analyze_url_chain(url: str) -> Dict:
    """Main entry point for URL analysis."""
    return URLChainAnalyzer.analyze_url(url)
