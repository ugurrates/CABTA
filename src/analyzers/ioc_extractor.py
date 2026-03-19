"""
Author: Ugur Ates
IOC (Indicator of Compromise) Extractor
Comprehensive pattern matching for all IOC types
"""

import re
import logging
from typing import Dict, List, Set

logger = logging.getLogger(__name__)
class IOCExtractor:
    """
    Extract all types of IOCs from text.
    
    Supports:
    - IPv4/IPv6 addresses
    - Domains
    - URLs
    - Email addresses
    - File hashes (MD5, SHA1, SHA256, SHA512)
    - Bitcoin addresses
    - CVE identifiers
    - File paths
    """
    
    # Regex patterns
    IPV4_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    IPV6_PATTERN = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    DOMAIN_PATTERN = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    URL_PATTERN = r'https?://[^\s<>"{}|\\^`\[\]]+'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    SHA512_PATTERN = r'\b[a-fA-F0-9]{128}\b'
    BITCOIN_PATTERN = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    CVE_PATTERN = r'CVE-\d{4}-\d{4,7}'
    
    @staticmethod
    def extract_all(text: str) -> Dict[str, List[str]]:
        """
        Extract all IOC types from text.
        
        Args:
            text: Input text
        
        Returns:
            Dict with IOC types as keys and lists of IOCs as values
        """
        result = {
            'ipv4': [],
            'ipv6': [],
            'domains': [],
            'urls': [],
            'emails': [],
            'md5': [],
            'sha1': [],
            'sha256': [],
            'sha512': [],
            'bitcoin': [],
            'cve': []
        }
        
        try:
            # Extract each type
            result['ipv4'] = IOCExtractor._extract_ipv4(text)
            result['ipv6'] = IOCExtractor._extract_ipv6(text)
            result['urls'] = IOCExtractor._extract_urls(text)
            result['domains'] = IOCExtractor._extract_domains(text)
            result['emails'] = IOCExtractor._extract_emails(text)
            result['md5'] = IOCExtractor._extract_md5(text)
            result['sha1'] = IOCExtractor._extract_sha1(text)
            result['sha256'] = IOCExtractor._extract_sha256(text)
            result['sha512'] = IOCExtractor._extract_sha512(text)
            result['bitcoin'] = IOCExtractor._extract_bitcoin(text)
            result['cve'] = IOCExtractor._extract_cve(text)
            
            # Count totals
            total = sum(len(v) for v in result.values())
            result['total_iocs'] = total
            
            logger.info(f"[IOC] Extracted {total} IOCs")
            
        except Exception as e:
            logger.error(f"[IOC] Extraction failed: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _extract_ipv4(text: str) -> List[str]:
        """Extract IPv4 addresses."""
        ips = re.findall(IOCExtractor.IPV4_PATTERN, text)
        # Filter out invalid IPs
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                valid_ips.append(ip)
        return list(set(valid_ips))
    
    @staticmethod
    def _extract_ipv6(text: str) -> List[str]:
        """Extract IPv6 addresses."""
        return list(set(re.findall(IOCExtractor.IPV6_PATTERN, text)))
    
    @staticmethod
    def _extract_domains(text: str) -> List[str]:
        """Extract domain names."""
        domains = re.findall(IOCExtractor.DOMAIN_PATTERN, text.lower())
        # Filter out common false positives
        filtered = [d for d in domains if '.' in d and len(d) > 4]
        return list(set(filtered))
    
    @staticmethod
    def _extract_urls(text: str) -> List[str]:
        """Extract URLs."""
        return list(set(re.findall(IOCExtractor.URL_PATTERN, text)))
    
    @staticmethod
    def _extract_emails(text: str) -> List[str]:
        """Extract email addresses."""
        return list(set(re.findall(IOCExtractor.EMAIL_PATTERN, text)))
    
    @staticmethod
    def _extract_md5(text: str) -> List[str]:
        """Extract MD5 hashes."""
        return list(set(re.findall(IOCExtractor.MD5_PATTERN, text)))
    
    @staticmethod
    def _extract_sha1(text: str) -> List[str]:
        """Extract SHA1 hashes."""
        return list(set(re.findall(IOCExtractor.SHA1_PATTERN, text)))
    
    @staticmethod
    def _extract_sha256(text: str) -> List[str]:
        """Extract SHA256 hashes."""
        return list(set(re.findall(IOCExtractor.SHA256_PATTERN, text)))
    
    @staticmethod
    def _extract_sha512(text: str) -> List[str]:
        """Extract SHA512 hashes."""
        return list(set(re.findall(IOCExtractor.SHA512_PATTERN, text)))
    
    @staticmethod
    def _extract_bitcoin(text: str) -> List[str]:
        """Extract Bitcoin addresses."""
        return list(set(re.findall(IOCExtractor.BITCOIN_PATTERN, text)))
    
    @staticmethod
    def _extract_cve(text: str) -> List[str]:
        """Extract CVE identifiers."""
        return list(set(re.findall(IOCExtractor.CVE_PATTERN, text, re.IGNORECASE)))
    
    @staticmethod
    def extract_from_file(file_path: str) -> Dict[str, List[str]]:
        """
        Extract IOCs from file.
        
        Args:
            file_path: Path to file
        
        Returns:
            Dict with extracted IOCs
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
            return IOCExtractor.extract_all(text)
        except Exception as e:
            logger.error(f"[IOC] File extraction failed: {e}")
            return {'error': str(e)}
def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Main entry point for IOC extraction.
    
    Args:
        text: Input text
    
    Returns:
        Dict with all extracted IOCs
    """
    return IOCExtractor.extract_all(text)
