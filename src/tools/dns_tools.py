"""
Author: Ugur Ates
DNS Tools Suite
Comprehensive DNS, reverse DNS, WHOIS, and MX record tools
Integrated from Sooty
"""

import socket
import dns.resolver
import dns.reversename
import whois
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)
class DNSTools:
    """
    Comprehensive DNS analysis tools.
    
    Features:
    - DNS lookup (A, AAAA, MX, TXT, NS)
    - Reverse DNS lookup
    - WHOIS lookup
    - MX record verification
    - Name server enumeration
    """
    
    @staticmethod
    def dns_lookup(domain: str) -> Dict:
        """
        Perform comprehensive DNS lookup.
        
        Args:
            domain: Domain name
        
        Returns:
            Dict with DNS records
        """
        result = {
            'domain': domain,
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'txt_records': [],
            'ns_records': [],
            'cname_records': []
        }
        
        try:
            # A records (IPv4)
            try:
                answers = dns.resolver.resolve(domain, 'A')
                result['a_records'] = [str(r) for r in answers]
            except:
                pass
            
            # AAAA records (IPv6)
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                result['aaaa_records'] = [str(r) for r in answers]
            except:
                pass
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                result['mx_records'] = [{'priority': r.preference, 'server': str(r.exchange)} for r in answers]
            except:
                pass
            
            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                result['txt_records'] = [str(r) for r in answers]
            except:
                pass
            
            # NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                result['ns_records'] = [str(r) for r in answers]
            except:
                pass
            
            # CNAME records
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                result['cname_records'] = [str(r) for r in answers]
            except:
                pass
            
            result['success'] = True
            logger.info(f"[DNS] Lookup completed for {domain}")
            
        except Exception as e:
            logger.error(f"[DNS] Lookup failed: {e}")
            result['error'] = str(e)
            result['success'] = False
        
        return result
    
    @staticmethod
    def reverse_dns(ip: str) -> Dict:
        """
        Perform reverse DNS lookup.
        
        Args:
            ip: IP address
        
        Returns:
            Dict with reverse DNS results
        """
        result = {
            'ip': ip,
            'hostname': None,
            'ptr_records': []
        }
        
        try:
            # Standard reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                result['hostname'] = hostname
            except:
                pass
            
            # PTR record lookup
            try:
                rev_name = dns.reversename.from_address(ip)
                answers = dns.resolver.resolve(rev_name, 'PTR')
                result['ptr_records'] = [str(r) for r in answers]
            except:
                pass
            
            result['success'] = True
            logger.info(f"[RDNS] Reverse DNS completed for {ip}")
            
        except Exception as e:
            logger.error(f"[RDNS] Lookup failed: {e}")
            result['error'] = str(e)
            result['success'] = False
        
        return result
    
    @staticmethod
    def whois_lookup(domain: str) -> Dict:
        """
        Perform WHOIS lookup.
        
        Args:
            domain: Domain name
        
        Returns:
            Dict with WHOIS data
        """
        result = {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'status': [],
            'raw': None
        }
        
        try:
            w = whois.whois(domain)
            
            result['registrar'] = w.registrar
            result['creation_date'] = str(w.creation_date) if w.creation_date else None
            result['expiration_date'] = str(w.expiration_date) if w.expiration_date else None
            result['name_servers'] = w.name_servers if w.name_servers else []
            result['status'] = w.status if isinstance(w.status, list) else [w.status] if w.status else []
            result['raw'] = str(w)
            
            result['success'] = True
            logger.info(f"[WHOIS] Lookup completed for {domain}")
            
        except Exception as e:
            logger.error(f"[WHOIS] Lookup failed: {e}")
            result['error'] = str(e)
            result['success'] = False
        
        return result
    
    @staticmethod
    def mx_verification(domain: str) -> Dict:
        """
        Verify MX records and mail server configuration.
        
        Args:
            domain: Domain name
        
        Returns:
            Dict with MX verification results
        """
        result = {
            'domain': domain,
            'has_mx': False,
            'mx_count': 0,
            'mx_records': [],
            'issues': []
        }
        
        try:
            # Get MX records
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = [(r.preference, str(r.exchange)) for r in answers]
            mx_records.sort()  # Sort by priority
            
            result['has_mx'] = True
            result['mx_count'] = len(mx_records)
            result['mx_records'] = [{'priority': p, 'server': s} for p, s in mx_records]
            
            # Check for issues
            if len(mx_records) == 0:
                result['issues'].append('No MX records found')
            elif len(mx_records) == 1:
                result['issues'].append('Single MX record (no redundancy)')
            
            # Verify MX servers are reachable
            for _, mx_server in mx_records:
                mx_server = mx_server.rstrip('.')
                try:
                    socket.gethostbyname(mx_server)
                except:
                    result['issues'].append(f'MX server not resolvable: {mx_server}')
            
            result['success'] = True
            logger.info(f"[MX] Verification completed for {domain}")
            
        except dns.resolver.NoAnswer:
            result['issues'].append('No MX records configured')
            result['success'] = False
        except Exception as e:
            logger.error(f"[MX] Verification failed: {e}")
            result['error'] = str(e)
            result['success'] = False
        
        return result
def dns_lookup(domain: str) -> Dict:
    """Main entry point for DNS lookup."""
    return DNSTools.dns_lookup(domain)
def reverse_dns(ip: str) -> Dict:
    """Main entry point for reverse DNS."""
    return DNSTools.reverse_dns(ip)
def whois_lookup(domain: str) -> Dict:
    """Main entry point for WHOIS."""
    return DNSTools.whois_lookup(domain)
