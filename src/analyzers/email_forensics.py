"""
Author: Ugur AtesDFIR-Grade Email Forensics Module."""

import email
import re
from datetime import datetime
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)
class EmailForensics:
    """
    DFIR-grade email forensics analyzer.
    
    Features:
    - Header timeline reconstruction
    - Authentication chain validation (SPF/DKIM/DMARC)
    - Relay path forensics
    - Sender reputation analysis
    - Mail infrastructure fingerprinting
    - Originating IP investigation
    """
    
    @staticmethod
    def reconstruct_header_timeline(msg: email.message.Message) -> List[Dict]:
        """
        Reconstruct email delivery timeline from Received headers.
        
        Args:
            msg: Email message object
        
        Returns:
            List of relay hops with timestamps
        """
        timeline = []
        
        # Get all Received headers (in reverse chronological order)
        received_headers = msg.get_all('Received', [])
        
        for idx, header in enumerate(reversed(received_headers)):
            hop = {
                'hop_number': idx + 1,
                'header': header,
                'timestamp': None,
                'from_server': None,
                'from_ip': None,
                'by_server': None,
                'protocol': None
            }
            
            # Extract timestamp
            timestamp_match = re.search(r';\s*(.+)$', header)
            if timestamp_match:
                try:
                    timestamp_str = timestamp_match.group(1).strip()
                    # Try to parse various date formats
                    for fmt in ['%a, %d %b %Y %H:%M:%S %z', '%d %b %Y %H:%M:%S %z']:
                        try:
                            hop['timestamp'] = datetime.strptime(timestamp_str, fmt)
                            break
                        except:
                            continue
                except:
                    hop['timestamp_raw'] = timestamp_match.group(1).strip()
            
            # Extract from server
            from_match = re.search(r'from\s+([^\s]+)', header, re.IGNORECASE)
            if from_match:
                hop['from_server'] = from_match.group(1)
            
            # Extract from IP
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
            if ip_match:
                hop['from_ip'] = ip_match.group(1)
            
            # Extract by server
            by_match = re.search(r'by\s+([^\s]+)', header, re.IGNORECASE)
            if by_match:
                hop['by_server'] = by_match.group(1)
            
            # Extract protocol
            protocol_match = re.search(r'with\s+([A-Z]+)', header, re.IGNORECASE)
            if protocol_match:
                hop['protocol'] = protocol_match.group(1)
            
            timeline.append(hop)
        
        return timeline
    
    @staticmethod
    def validate_authentication_chain(msg: email.message.Message) -> Dict:
        """
        Validate SPF, DKIM, DMARC authentication.
        
        Args:
            msg: Email message object
        
        Returns:
            Authentication results
        """
        auth_results = {
            'spf': {'status': 'NONE', 'details': None},
            'dkim': {'status': 'NONE', 'details': None},
            'dmarc': {'status': 'NONE', 'details': None},
            'arc': {'status': 'NONE', 'details': None},
            'overall_pass': False
        }
        
        # Parse Authentication-Results header
        auth_header = msg.get('Authentication-Results', '')
        
        if auth_header:
            # SPF
            spf_match = re.search(r'spf=(\w+)', auth_header, re.IGNORECASE)
            if spf_match:
                auth_results['spf']['status'] = spf_match.group(1).upper()
                
                # Extract SPF details
                spf_details_match = re.search(r'spf=\w+\s+\(([^)]+)\)', auth_header, re.IGNORECASE)
                if spf_details_match:
                    auth_results['spf']['details'] = spf_details_match.group(1)
            
            # DKIM
            dkim_match = re.search(r'dkim=(\w+)', auth_header, re.IGNORECASE)
            if dkim_match:
                auth_results['dkim']['status'] = dkim_match.group(1).upper()
                
                # Extract DKIM domain
                dkim_domain_match = re.search(r'header\.d=([^\s;]+)', auth_header, re.IGNORECASE)
                if dkim_domain_match:
                    auth_results['dkim']['domain'] = dkim_domain_match.group(1)
            
            # DMARC
            dmarc_match = re.search(r'dmarc=(\w+)', auth_header, re.IGNORECASE)
            if dmarc_match:
                auth_results['dmarc']['status'] = dmarc_match.group(1).upper()
                
                # Extract DMARC policy
                dmarc_policy_match = re.search(r'header\.from=([^\s;]+)', auth_header, re.IGNORECASE)
                if dmarc_policy_match:
                    auth_results['dmarc']['from_domain'] = dmarc_policy_match.group(1)
            
            # ARC
            arc_match = re.search(r'arc=(\w+)', auth_header, re.IGNORECASE)
            if arc_match:
                auth_results['arc']['status'] = arc_match.group(1).upper()
        
        # Check overall authentication
        spf_pass = auth_results['spf']['status'] == 'PASS'
        dkim_pass = auth_results['dkim']['status'] == 'PASS'
        dmarc_pass = auth_results['dmarc']['status'] == 'PASS'
        
        auth_results['overall_pass'] = spf_pass and dkim_pass and dmarc_pass
        auth_results['authentication_score'] = sum([spf_pass, dkim_pass, dmarc_pass]) * 33  # 0-100
        
        return auth_results
    
    @staticmethod
    def analyze_relay_path(timeline: List[Dict]) -> Dict:
        """
        Analyze email relay path for anomalies.
        
        Args:
            timeline: Email timeline from reconstruct_header_timeline
        
        Returns:
            Relay path analysis
        """
        analysis = {
            'total_hops': len(timeline),
            'originating_ip': None,
            'originating_server': None,
            'suspicious_hops': [],
            'time_anomalies': [],
            'geo_anomalies': []
        }
        
        if timeline:
            # First hop is originating server
            first_hop = timeline[0]
            analysis['originating_ip'] = first_hop.get('from_ip')
            analysis['originating_server'] = first_hop.get('from_server')
            
            # Check for suspicious patterns
            for hop in timeline:
                hop_suspicious = []
                
                # Check for suspicious server names
                from_server = hop.get('from_server', '').lower()
                if any(suspicious in from_server for suspicious in ['unknown', 'localhost', '127.0.0.1']):
                    hop_suspicious.append('Suspicious server name')
                
                # Check for private IPs in external hops
                from_ip = hop.get('from_ip', '')
                if from_ip and hop.get('hop_number', 0) > 1:
                    if from_ip.startswith('10.') or from_ip.startswith('192.168.') or from_ip.startswith('172.'):
                        hop_suspicious.append('Private IP in external relay')
                
                if hop_suspicious:
                    analysis['suspicious_hops'].append({
                        'hop': hop.get('hop_number'),
                        'reasons': hop_suspicious,
                        'details': hop
                    })
            
            # Check time anomalies
            for i in range(1, len(timeline)):
                prev_hop = timeline[i-1]
                curr_hop = timeline[i]
                
                prev_time = prev_hop.get('timestamp')
                curr_time = curr_hop.get('timestamp')
                
                if prev_time and curr_time:
                    time_diff = (curr_time - prev_time).total_seconds()
                    
                    # Flag if time goes backwards or huge delays
                    if time_diff < 0:
                        analysis['time_anomalies'].append({
                            'hops': f"{prev_hop.get('hop_number')} → {curr_hop.get('hop_number')}",
                            'issue': 'Time goes backwards',
                            'diff_seconds': time_diff
                        })
                    elif time_diff > 3600:  # > 1 hour
                        analysis['time_anomalies'].append({
                            'hops': f"{prev_hop.get('hop_number')} → {curr_hop.get('hop_number')}",
                            'issue': 'Unusual delay',
                            'diff_seconds': time_diff
                        })
        
        return analysis

    @staticmethod
    def calculate_hop_delays(timeline: List[Dict]) -> Dict:
        """
        Calculate delivery delays between each hop in the relay chain.

        Returns a dict with per-hop delays, total delivery time,
        average delay, and the slowest hop.
        """
        delays: List[Dict] = []
        total_seconds = 0.0

        for i in range(1, len(timeline)):
            prev_ts = timeline[i - 1].get('timestamp')
            curr_ts = timeline[i].get('timestamp')

            if prev_ts and curr_ts:
                diff = (curr_ts - prev_ts).total_seconds()
                delays.append({
                    'from_hop': timeline[i - 1].get('hop_number'),
                    'to_hop': timeline[i].get('hop_number'),
                    'delay_seconds': round(diff, 2),
                    'from_server': timeline[i - 1].get('by_server', ''),
                    'to_server': timeline[i].get('by_server', ''),
                })
                total_seconds += diff

        slowest = max(delays, key=lambda d: d['delay_seconds']) if delays else None

        return {
            'hop_delays': delays,
            'total_delivery_seconds': round(total_seconds, 2),
            'average_delay_seconds': round(total_seconds / len(delays), 2) if delays else 0,
            'slowest_hop': slowest,
            'hop_count': len(timeline),
        }

    @staticmethod
    def detect_forged_headers(msg: email.message.Message) -> Dict:
        """
        Detect potentially forged or manipulated email headers.

        Checks:
        - Multiple From headers (RFC violation)
        - Received header count vs expected
        - X-Originating-IP vs first Received hop mismatch
        - Date header in the future
        - Missing mandatory headers (Date, From, Message-ID)
        """
        issues: List[str] = []
        risk_score = 0

        # Multiple From headers (should only be one)
        from_headers = msg.get_all('From', [])
        if len(from_headers) > 1:
            issues.append('Multiple From headers detected (potential spoofing)')
            risk_score += 25

        # Missing mandatory headers
        for required in ('Date', 'From', 'Message-ID'):
            if not msg.get(required):
                issues.append(f'Missing mandatory header: {required}')
                risk_score += 10

        # Date header in the future
        date_str = msg.get('Date', '')
        if date_str:
            for fmt in ('%a, %d %b %Y %H:%M:%S %z', '%d %b %Y %H:%M:%S %z'):
                try:
                    email_date = datetime.strptime(date_str.strip(), fmt)
                    from datetime import timezone
                    now = datetime.now(timezone.utc)
                    if email_date > now:
                        diff_min = (email_date - now).total_seconds() / 60
                        if diff_min > 5:  # allow 5 min clock skew
                            issues.append(f'Date header is {diff_min:.0f} minutes in the future')
                            risk_score += 15
                    break
                except (ValueError, TypeError):
                    continue

        # X-Originating-IP vs first Received hop
        x_orig = msg.get('X-Originating-IP', '')
        first_received_ip = None
        received_headers = msg.get_all('Received', [])
        if received_headers:
            # Last Received header = first hop
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received_headers[-1])
            if ip_match:
                first_received_ip = ip_match.group(1)

        if x_orig and first_received_ip:
            orig_ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', x_orig)
            if orig_ip and orig_ip.group(1) != first_received_ip:
                issues.append(
                    f'X-Originating-IP ({orig_ip.group(1)}) != first Received hop IP ({first_received_ip})'
                )
                risk_score += 20

        # Too few Received headers for external email
        if len(received_headers) < 2 and not any(
            h for h in (msg.get('X-Mailer', ''), msg.get('User-Agent', '')) if h
        ):
            issues.append('Suspiciously few Received headers for external email')
            risk_score += 10

        return {
            'forged_header_issues': issues,
            'forged_header_risk': min(risk_score, 100),
        }

    @staticmethod
    def fingerprint_mail_infrastructure(msg: email.message.Message) -> Dict:
        """
        Fingerprint mail infrastructure (MTA/MUA).
        
        Args:
            msg: Email message object
        
        Returns:
            Infrastructure fingerprint
        """
        fingerprint = {
            'mta': None,  # Mail Transfer Agent
            'mua': None,  # Mail User Agent
            'x_mailer': None,
            'message_id_domain': None,
            'suspicious_headers': []
        }
        
        # X-Mailer header
        x_mailer = msg.get('X-Mailer', '')
        if x_mailer:
            fingerprint['x_mailer'] = x_mailer
            fingerprint['mua'] = x_mailer
        
        # User-Agent header
        user_agent = msg.get('User-Agent', '')
        if user_agent:
            fingerprint['mua'] = user_agent
        
        # Message-ID domain
        message_id = msg.get('Message-ID', '')
        if message_id:
            domain_match = re.search(r'@([a-zA-Z0-9.-]+)>', message_id)
            if domain_match:
                fingerprint['message_id_domain'] = domain_match.group(1)
        
        # Check for suspicious headers
        all_headers = dict(msg.items())
        suspicious_header_patterns = [
            'X-PHP-Originating-Script',
            'X-Spam-',
            'X-Virus-',
            'X-Originating-IP',
            'X-Mailer-LID'
        ]
        
        for header_name in all_headers.keys():
            for pattern in suspicious_header_patterns:
                if pattern in header_name:
                    fingerprint['suspicious_headers'].append({
                        'header': header_name,
                        'value': all_headers[header_name]
                    })
        
        return fingerprint
    
    @staticmethod
    def analyze_sender_reputation(from_addr: str, from_domain: str) -> Dict:
        """
        Analyze sender reputation (basic heuristics).
        
        Args:
            from_addr: From email address
            from_domain: From domain
        
        Returns:
            Sender reputation analysis
        """
        reputation = {
            'from_address': from_addr,
            'from_domain': from_domain,
            'suspicious_patterns': [],
            'risk_score': 0  # 0-100
        }
        
        # Check for suspicious patterns in email address
        if from_addr:
            # Extract username part for analysis
            username = from_addr.split('@')[0] if '@' in from_addr else from_addr

            # Check for numeric-heavy addresses (username part only)
            if username and sum(c.isdigit() for c in username) > len(username) * 0.5:
                reputation['suspicious_patterns'].append('Numeric-heavy address')
                reputation['risk_score'] += 20

            # Check for random-looking strings
            if len(username) > 15 and not any(word in username.lower() for word in ['admin', 'support', 'info', 'contact']):
                reputation['suspicious_patterns'].append('Random-looking username')
                reputation['risk_score'] += 15
            
            # Check for suspicious keywords
            suspicious_keywords = ['noreply', 'no-reply', 'donotreply', 'notification']
            if any(keyword in from_addr.lower() for keyword in suspicious_keywords):
                reputation['suspicious_patterns'].append('Generic sender address')
                reputation['risk_score'] += 10
        
        # Check domain reputation (basic heuristics)
        if from_domain:
            # Check for free email providers
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'mail.com']
            if from_domain.lower() in free_providers:
                reputation['is_free_provider'] = True
                reputation['risk_score'] += 5  # Slight risk increase for business emails
            
            # Check for new gTLDs often used in phishing
            suspicious_tlds = ['.top', '.xyz', '.club', '.work', '.click', '.link', '.gq', '.ml', '.tk']
            if any(from_domain.endswith(tld) for tld in suspicious_tlds):
                reputation['suspicious_patterns'].append(f'Suspicious TLD: {from_domain.split(".")[-1]}')
                reputation['risk_score'] += 25
            
            # Check for domain length (very short or very long)
            domain_name = from_domain.split('.')[0]
            if len(domain_name) < 3:
                reputation['suspicious_patterns'].append('Very short domain name')
                reputation['risk_score'] += 15
            elif len(domain_name) > 30:
                reputation['suspicious_patterns'].append('Very long domain name')
                reputation['risk_score'] += 10
        
        # Cap risk score at 100
        reputation['risk_score'] = min(reputation['risk_score'], 100)
        
        return reputation
    
    @staticmethod
    def perform_full_forensics(msg: email.message.Message, from_addr: str, from_domain: str) -> Dict:
        """
        Perform complete DFIR-grade email forensics.
        
        Args:
            msg: Email message object
            from_addr: From email address
            from_domain: From domain
        
        Returns:
            Complete forensics analysis
        """
        logger.info("[EMAIL-FORENSICS] Starting DFIR-grade analysis...")
        
        forensics = {
            'timeline': EmailForensics.reconstruct_header_timeline(msg),
            'authentication': EmailForensics.validate_authentication_chain(msg),
            'infrastructure': EmailForensics.fingerprint_mail_infrastructure(msg),
            'sender_reputation': EmailForensics.analyze_sender_reputation(from_addr, from_domain)
        }
        
        # Add relay path analysis
        forensics['relay_analysis'] = EmailForensics.analyze_relay_path(forensics['timeline'])

        # Add hop delay analysis
        forensics['hop_delays'] = EmailForensics.calculate_hop_delays(forensics['timeline'])

        # Add forged header detection
        forensics['forged_headers'] = EmailForensics.detect_forged_headers(msg)

        # Calculate overall forensics risk score (HIGH = BAD)
        auth_score = forensics['authentication'].get('authentication_score', 0)
        reputation_risk = forensics['sender_reputation'].get('risk_score', 0)

        # More suspicious findings = higher risk score
        suspicious_hops_count = len(forensics['relay_analysis'].get('suspicious_hops', []))
        time_anomalies_count = len(forensics['relay_analysis'].get('time_anomalies', []))
        
        #  FIX: Calculate proper RISK score (HIGH = BAD for phishing)
        # Start from 0 and ADD risks
        forensics_risk_score = 0
        
        # Authentication failures add to risk
        forensics_risk_score += max(0, 100 - auth_score)  # If auth_score is low, risk is high
        
        # Reputation risk
        forensics_risk_score += reputation_risk
        
        # Suspicious relay hops
        forensics_risk_score += suspicious_hops_count * 10
        
        # Time anomalies
        forensics_risk_score += time_anomalies_count * 15

        # Forged header risk
        forensics_risk_score += forensics['forged_headers'].get('forged_header_risk', 0)

        # Normalize to 0-100
        forensics_risk_score = max(0, min(100, forensics_risk_score))
        
        # Store both scores for backward compatibility
        forensics['forensics_score'] = forensics_risk_score  # Risk score (HIGH = BAD)
        forensics['safety_score'] = max(0, min(100, auth_score - reputation_risk - (suspicious_hops_count * 10) - (time_anomalies_count * 15)))  # Legacy
        
        logger.info(f"[EMAIL-FORENSICS] Analysis complete. Risk Score: {forensics_risk_score}/100")
        
        return forensics
