"""
Author: Ugur Ates
SOC Output Formatter - Professional IR/SOC-Grade Output
Based on comprehensive SOC/Blue Team/Incident Responder workflow specifications.
"""

from typing import Dict, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
class SOCOutputFormatter:
    """
    Professional SOC-grade output formatter.
    
    Generates comprehensive, actionable reports for:
    - Email Forensics (7-step IR workflow)
    - Malware Analysis (PE static analysis)
    - IOC Investigation (22+ sources)
    """
    
    # Box drawing characters
    BOX_TOP = "╔══════════════════════════════════════════════════════════════════════════════╗"
    BOX_MID = "║"
    BOX_BOT = "╚══════════════════════════════════════════════════════════════════════════════╝"
    BOX_SINGLE_TOP = "┌────────────────────────────────────────────────────────────────────────────┐"
    BOX_SINGLE_MID = "│"
    BOX_SINGLE_BOT = "└────────────────────────────────────────────────────────────────────────────┘"
    
    SECTION_SEP = "══════════════════════════════════════════════════════════════════════════════"
    
    @classmethod
    def format_email_report(cls, result: Dict, email_path: str) -> str:
        """
        Format comprehensive email forensics report.
        
        Follows professional IR workflow:
        1. Header Forensics
        2. Sender Verification
        3. Content Analysis
        4. Link/URL Analysis
        5. Attachment Analysis
        6. IOC Extraction & Correlation
        7. Verdict & Recommendations
        """
        lines = []
        
        # ==================== HEADER ====================
        lines.append(cls.BOX_TOP)
        lines.append(f"{cls.BOX_MID}  📧 EMAIL FORENSIC ANALYSIS REPORT{' ' * 42}{cls.BOX_MID}")
        lines.append(f"{cls.BOX_MID}  Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}{' ' * 30}{cls.BOX_MID}")
        lines.append(cls.BOX_BOT)
        lines.append("")
        
        # ==================== VERDICT BOX ====================
        verdict = result.get('verdict', 'UNKNOWN')
        composite_score = result.get('composite_score', 0)
        
        verdict_emoji = {'PHISHING': '🎣', 'SUSPICIOUS': '⚠️', 'SPAM': '📧', 'CLEAN': '✅', 'UNKNOWN': '❓'}
        risk_level = "CRITICAL" if composite_score >= 85 else "HIGH" if composite_score >= 60 else "MEDIUM" if composite_score >= 30 else "LOW"
        
        lines.append(cls.BOX_SINGLE_TOP)
        lines.append(f"{cls.BOX_SINGLE_MID}  {verdict_emoji.get(verdict, '')} VERDICT: {verdict}{' ' * (60 - len(verdict))}{cls.BOX_SINGLE_MID}")
        lines.append(f"{cls.BOX_SINGLE_MID}  Composite Score: {composite_score}/100 ({risk_level}){' ' * (48 - len(str(composite_score)) - len(risk_level))}{cls.BOX_SINGLE_MID}")
        lines.append(cls.BOX_SINGLE_BOT)
        lines.append("")
        
        # ==================== SECTION 1: EMAIL METADATA ====================
        lines.append(cls.SECTION_SEP)
        lines.append(" SECTION 1: EMAIL METADATA")
        lines.append(cls.SECTION_SEP)
        lines.append("")
        
        email_data = result.get('email_data', {})
        lines.append(f"  Subject    : {email_data.get('subject', 'N/A')}")
        lines.append(f"  From       : {email_data.get('from', 'N/A')}")
        lines.append(f"  To         : {email_data.get('to', 'N/A')}")
        lines.append(f"  Date       : {email_data.get('date', 'N/A')}")
        lines.append(f"  Message-ID : {email_data.get('message_id', 'N/A')}")
        
        # Anomalies
        advanced = result.get('advanced_analysis', {})
        header_analysis = advanced.get('header_analysis', {})
        anomalies = header_analysis.get('anomalies', [])
        
        if anomalies:
            lines.append("")
            lines.append("  ⚠️  ANOMALIES DETECTED:")
            for anomaly in anomalies[:5]:
                lines.append(f"      • {anomaly}")
        lines.append("")
        
        # ==================== SECTION 2: HEADER FORENSICS ====================
        lines.append(cls.SECTION_SEP)
        lines.append(" SECTION 2: HEADER FORENSICS")
        lines.append(cls.SECTION_SEP)
        lines.append("")
        
        forensics = result.get('forensics', {})
        
        # Timeline
        timeline = forensics.get('timeline', [])
        if timeline:
            lines.append(f"┌─ DELIVERY TIMELINE ({len(timeline)} hops)")
            lines.append("│")
            
            for hop in timeline[:6]:
                hop_num = hop.get('hop_number', '?')
                from_server = hop.get('from_server', 'Unknown')
                from_ip = hop.get('from_ip', '')
                timestamp = hop.get('timestamp', hop.get('timestamp_raw', 'Unknown'))
                protocol = hop.get('protocol', '')
                
                lines.append(f"│  HOP {hop_num} │ {timestamp}")
                lines.append(f"│        │ From: {from_server}" + (f" [{from_ip}]" if from_ip else ""))
                if hop.get('by_server'):
                    lines.append(f"│        │ To: {hop.get('by_server')}")
                if protocol:
                    lines.append(f"│        │ Protocol: {protocol}")
                lines.append("│")
            
            if len(timeline) > 6:
                lines.append(f"│  ... {len(timeline) - 6} more hops")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # Authentication
        auth = forensics.get('authentication', {})
        if auth:
            lines.append("┌─ AUTHENTICATION RESULTS")
            lines.append("│")
            
            spf = auth.get('spf', {})
            spf_status = spf.get('status', 'UNKNOWN')
            spf_emoji = "✅" if spf_status.upper() == 'PASS' else "❌" if spf_status.upper() in ['FAIL', 'SOFTFAIL'] else "⚪"
            lines.append(f"│  SPF     │ {spf_emoji} {spf_status.upper()}")
            if spf.get('details'):
                lines.append(f"│          │ {spf.get('details')}")
            
            dkim = auth.get('dkim', {})
            dkim_status = dkim.get('status', 'UNKNOWN')
            dkim_emoji = "✅" if dkim_status.upper() == 'PASS' else "❌" if dkim_status.upper() == 'FAIL' else "⚪"
            lines.append(f"│  DKIM    │ {dkim_emoji} {dkim_status.upper()}")
            if dkim.get('domain'):
                lines.append(f"│          │ Domain: {dkim.get('domain')}")
            
            dmarc = auth.get('dmarc', {})
            dmarc_status = dmarc.get('status', 'UNKNOWN')
            dmarc_emoji = "✅" if dmarc_status.upper() == 'PASS' else "❌" if dmarc_status.upper() == 'FAIL' else "⚪"
            lines.append(f"│  DMARC   │ {dmarc_emoji} {dmarc_status.upper()}")
            
            lines.append("│")
            
            overall = auth.get('overall_pass', False)
            if overall:
                lines.append("│  ┌─────────────────────────────────────────────┐")
                lines.append("│  │ ✅ AUTHENTICATION VERDICT: PASS            │")
                lines.append("│  └─────────────────────────────────────────────┘")
            else:
                lines.append("│  ┌─────────────────────────────────────────────┐")
                lines.append("│  │ 🚨 AUTHENTICATION VERDICT: FAIL            │")
                lines.append("│  │    Authentication mechanisms failed.       │")
                lines.append("│  └─────────────────────────────────────────────┘")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # Relay Anomalies
        relay = forensics.get('relay_analysis', {})
        suspicious_hops = relay.get('suspicious_hops', [])
        time_anomalies = relay.get('time_anomalies', [])
        
        if suspicious_hops or time_anomalies:
            lines.append("┌─ RELAY PATH ANOMALIES")
            
            if suspicious_hops:
                lines.append(f"│  🚨 Suspicious Hops: {len(suspicious_hops)}")
                for sh in suspicious_hops[:3]:
                    reasons = ', '.join(sh.get('reasons', []))
                    lines.append(f"│    Hop {sh.get('hop')}: {reasons}")
            
            if time_anomalies:
                lines.append(f"│  🚨 Time Anomalies: {len(time_anomalies)}")
                for ta in time_anomalies[:3]:
                    lines.append(f"│    {ta.get('hops')}: {ta.get('issue')}")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # Sender Reputation
        reputation = forensics.get('sender_reputation', {})
        if reputation:
            lines.append("┌─ SENDER REPUTATION")
            lines.append(f"│  Risk Score: {reputation.get('risk_score', 0)}/100")
            lines.append(f"│  From: {reputation.get('from_address', 'Unknown')}")
            lines.append(f"│  Domain: {reputation.get('from_domain', 'Unknown')}")
            
            suspicious_patterns = reputation.get('suspicious_patterns', [])
            if suspicious_patterns:
                lines.append("│")
                lines.append("│  🚨 Suspicious Patterns:")
                for pattern in suspicious_patterns[:5]:
                    lines.append(f"│    • {pattern}")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 3: CONTENT ANALYSIS ====================
        lines.append(cls.SECTION_SEP)
        lines.append(" SECTION 3: CONTENT ANALYSIS")
        lines.append(cls.SECTION_SEP)
        lines.append("")
        
        content_issues_found = False
        
        # Brand Impersonation
        brand_impersonation = advanced.get('brand_impersonation', [])
        if brand_impersonation:
            content_issues_found = True
            lines.append("┌─ BRAND IMPERSONATION")
            for imp in brand_impersonation[:5]:
                brand = imp.get('brand', 'Unknown')
                risk = imp.get('risk', 'UNKNOWN')
                reason = imp.get('reason', '')
                lines.append(f"│  🚨 {brand} - {risk}")
                if reason:
                    lines.append(f"│     {reason}")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # HTML Obfuscation
        html_obfuscation = advanced.get('html_obfuscation', {})
        risk_score = html_obfuscation.get('risk_score', 0)
        if risk_score > 0:
            content_issues_found = True
            lines.append("┌─ HTML OBFUSCATION ANALYSIS")
            lines.append(f"│  Risk Score: {risk_score}/100")
            
            if risk_score > 20:
                lines.append("│")
                techniques = html_obfuscation.get('techniques', {})
                if techniques.get('zero_size_fonts', 0) > 0:
                    lines.append(f"│  🚨 Zero-size fonts: {techniques['zero_size_fonts']} instances")
                if techniques.get('hidden_elements', 0) > 0:
                    lines.append(f"│  🚨 Hidden elements: {techniques['hidden_elements']} instances")
                if techniques.get('white_on_white', 0) > 0:
                    lines.append(f"│  🚨 White-on-white text: {techniques['white_on_white']} instances")
                if techniques.get('base64_content', 0) > 0:
                    lines.append(f"│  🚨 Base64 encoded content: {techniques['base64_content']} instances")
            else:
                lines.append("│  ✅ No significant obfuscation detected")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # QR Codes
        qr_detection = advanced.get('qr_detection', {})
        qr_codes = qr_detection.get('qr_codes', [])
        if qr_codes:
            content_issues_found = True
            lines.append("┌─ QR CODE DETECTION")
            lines.append(f"│  🚨 {len(qr_codes)} QR CODE(S) FOUND")
            for qr in qr_codes[:3]:
                lines.append(f"│  Location: {qr.get('location', 'Unknown')}")
                if qr.get('decoded_url'):
                    lines.append(f"│  Decoded URL: {qr.get('decoded_url')[:60]}")
            lines.append("│")
            lines.append("│  ⚠️  QR codes in emails are HIGH RISK - often bypass URL filters")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # If no content issues found, show that explicitly
        if not content_issues_found:
            lines.append("┌─ CONTENT ANALYSIS SUMMARY")
            lines.append("│  ✅ No brand impersonation detected")
            lines.append("│  ✅ No HTML obfuscation detected")
            lines.append("│  ✅ No QR codes detected")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 4: LINK ANALYSIS ====================
        lines.append(cls.SECTION_SEP)
        lines.append(" SECTION 4: LINK ANALYSIS")
        lines.append(cls.SECTION_SEP)
        lines.append("")
        
        link_issues_found = False
        
        # Show all URLs from email
        email_urls = email_data.get('urls', [])
        email_domains = email_data.get('domains', [])
        
        if email_urls or email_domains:
            lines.append(f"┌─ URL INVENTORY ({len(email_urls)} URLs, {len(email_domains)} domains)")
            for i, url in enumerate(email_urls[:10], 1):
                # Truncate long URLs
                display_url = url[:70] + "..." if len(url) > 70 else url
                lines.append(f"│  URL #{i}: {display_url}")
            
            if len(email_urls) > 10:
                lines.append(f"│  ... and {len(email_urls) - 10} more URLs")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # Link-Text Mismatches
        link_mismatches = advanced.get('link_mismatches', [])
        if link_mismatches:
            link_issues_found = True
            lines.append(f"┌─ LINK-TEXT MISMATCHES ({len(link_mismatches)} found)")
            for i, mismatch in enumerate(link_mismatches[:5], 1):
                displayed = mismatch.get('displayed_url', 'Unknown')
                actual = mismatch.get('actual_url', 'Unknown')
                lines.append(f"│")
                lines.append(f"│  URL #{i} - 🚨 MISMATCH")
                lines.append(f"│  ├─ Displayed : {displayed[:60]}")
                lines.append(f"│  └─ Actual    : {actual[:60]}")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # Lookalike Domains
        lookalike_domains = advanced.get('lookalike_domains', [])
        if lookalike_domains:
            link_issues_found = True
            lines.append(f"┌─ LOOKALIKE DOMAIN DETECTION ({len(lookalike_domains)} found)")
            for domain in lookalike_domains[:5]:
                domain_name = domain.get('domain', 'Unknown')
                legitimate = domain.get('legitimate', 'Unknown')
                similarity = domain.get('similarity', 0)
                technique = domain.get('technique', 'Unknown')
                
                # Handle similarity format
                if isinstance(similarity, str):
                    similarity_str = similarity
                elif isinstance(similarity, (int, float)):
                    similarity_str = f"{similarity:.0%}" if similarity <= 1 else f"{similarity}%"
                else:
                    similarity_str = str(similarity)
                
                lines.append(f"│")
                lines.append(f"│  DOMAIN: {domain_name}")
                lines.append(f"│  ├─ Impersonating    : {legitimate}")
                lines.append(f"│  ├─ Technique        : {technique}")
                lines.append(f"│  ├─ Visual Similarity: {similarity_str}")
                lines.append(f"│  └─ Risk Level       : CRITICAL")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # Summary if no link issues
        if not link_issues_found and not email_urls:
            lines.append("┌─ LINK ANALYSIS SUMMARY")
            lines.append("│  ✅ No URLs found in email")
            lines.append("│  ✅ No link-text mismatches detected")
            lines.append("│  ✅ No lookalike domains detected")
            lines.append("└" + "─" * 77)
            lines.append("")
        elif not link_issues_found:
            lines.append("┌─ LINK ANALYSIS SUMMARY")
            lines.append("│  ✅ No link-text mismatches detected")
            lines.append("│  ✅ No lookalike domains detected")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 5: ATTACHMENT ANALYSIS ====================
        attachment_analysis = result.get('attachment_analysis', {})
        attachments = attachment_analysis.get('attachments', [])
        
        if attachments:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 5: ATTACHMENT ANALYSIS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append(f"┌─ ATTACHMENT INVENTORY ({len(attachments)} files)")
            
            for att in attachments:
                filename = att.get('filename', 'Unknown')
                verdict = att.get('verdict', 'UNKNOWN')
                score = att.get('composite_score', 0)
                
                verdict_emoji = '🦠' if verdict == 'MALICIOUS' else '⚠️' if verdict == 'SUSPICIOUS' else '✅'
                
                lines.append(f"│")
                lines.append(f"│  📎 {filename}")
                lines.append(f"│  ┌" + "─" * 70)
                
                file_info = att.get('file_info', {})
                if file_info:
                    lines.append(f"│  │ Size: {file_info.get('size_bytes', 0):,} bytes")
                    lines.append(f"│  │ Type: {file_info.get('mime_type', 'Unknown')}")
                
                hashes = att.get('hashes', {})
                if hashes.get('sha256'):
                    lines.append(f"│  │ SHA256: {hashes.get('sha256', 'Unknown')[:32]}...")
                
                hash_score = att.get('hash_score', 0)
                if hash_score > 0:
                    lines.append(f"│  │ Hash Reputation: 🚨 {hash_score}/100")
                
                yara = att.get('yara_analysis', {})
                if yara and yara.get('matches'):
                    families = yara.get('interpretation', {}).get('malware_families', [])
                    if families:
                        lines.append(f"│  │ YARA: {', '.join(families)}")
                
                lines.append(f"│  │")
                lines.append(f"│  │ {verdict_emoji} VERDICT: {verdict} (Score: {score}/100)")
                lines.append(f"│  └" + "─" * 70)
            
            lines.append("│")
            mal_count = sum(1 for a in attachments if a.get('verdict') == 'MALICIOUS')
            sus_count = sum(1 for a in attachments if a.get('verdict') == 'SUSPICIOUS')
            lines.append(f"│  ┌─────────────────────────────────────────────┐")
            lines.append(f"│  │ ATTACHMENT SUMMARY                          │")
            lines.append(f"│  │ Total: {len(attachments)} │ Malicious: {mal_count} │ Suspicious: {sus_count}    │")
            lines.append(f"│  └─────────────────────────────────────────────┘")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 6: IOC ANALYSIS ====================
        ioc_analysis = result.get('ioc_analysis', {})
        ioc_results = ioc_analysis.get('results', [])  # This is a list, not a dict
        
        # Always show Section 6 header
        lines.append(cls.SECTION_SEP)
        lines.append(" SECTION 6: IOC EXTRACTION & THREAT INTELLIGENCE")
        lines.append(cls.SECTION_SEP)
        lines.append("")
        
        total = ioc_analysis.get('total_iocs', len(ioc_results))
        malicious = ioc_analysis.get('malicious_iocs', 0)
        suspicious = ioc_analysis.get('suspicious_iocs', 0)
        
        if total > 0 or email_data.get('urls') or email_data.get('domains') or email_data.get('ips'):
            lines.append(f"┌─ EXTRACTED IOCs (Total: {total})")
            lines.append("│")
            
            # Group results by type
            urls = [r for r in ioc_results if r.get('ioc_type') == 'url']
            domains = [r for r in ioc_results if r.get('ioc_type') == 'domain']
            ips = [r for r in ioc_results if r.get('ioc_type') in ['ipv4', 'ip']]
            
            # URLs
            if urls:
                mal_urls = [u for u in urls if u.get('verdict') == 'MALICIOUS']
                sus_urls = [u for u in urls if u.get('verdict') == 'SUSPICIOUS']
                lines.append(f"│  URLs ({len(urls)} investigated)")
                
                for url in mal_urls[:3]:
                    ioc = url.get('ioc', 'Unknown')[:60]
                    score = url.get('threat_score', 0)
                    lines.append(f"│  ├─ {ioc}...")
                    lines.append(f"│  │   Score: {score}/100 │ 🚨 MALICIOUS")
                
                for url in sus_urls[:2]:
                    ioc = url.get('ioc', 'Unknown')[:60]
                    score = url.get('threat_score', 0)
                    lines.append(f"│  ├─ {ioc}...")
                    lines.append(f"│  │   Score: {score}/100 │ ⚠️ SUSPICIOUS")
                
                # Show clean URLs count
                clean_urls = len(urls) - len(mal_urls) - len(sus_urls)
                if clean_urls > 0:
                    lines.append(f"│  └─ {clean_urls} URL(s) analyzed as clean")
                lines.append("│")
            
            # Domains
            if domains:
                mal_domains = [d for d in domains if d.get('verdict') == 'MALICIOUS']
                sus_domains = [d for d in domains if d.get('verdict') == 'SUSPICIOUS']
                lines.append(f"│  DOMAINS ({len(domains)} investigated)")
                
                for domain in mal_domains[:3]:
                    ioc = domain.get('ioc', 'Unknown')
                    score = domain.get('threat_score', 0)
                    lines.append(f"│  ├─ {ioc}")
                    lines.append(f"│  │   Score: {score}/100 │ 🚨 MALICIOUS")
                
                for domain in sus_domains[:2]:
                    ioc = domain.get('ioc', 'Unknown')
                    score = domain.get('threat_score', 0)
                    lines.append(f"│  ├─ {ioc}")
                    lines.append(f"│  │   Score: {score}/100 │ ⚠️ SUSPICIOUS")
                
                clean_domains = len(domains) - len(mal_domains) - len(sus_domains)
                if clean_domains > 0:
                    lines.append(f"│  └─ {clean_domains} domain(s) analyzed as clean")
                lines.append("│")
            
            # IPs
            if ips:
                mal_ips = [i for i in ips if i.get('verdict') == 'MALICIOUS']
                if mal_ips:
                    lines.append(f"│  IP ADDRESSES ({len(mal_ips)} malicious)")
                    for ip in mal_ips[:3]:
                        ioc = ip.get('ioc', 'Unknown')
                        score = ip.get('threat_score', 0)
                        lines.append(f"│  ├─ {ioc} │ Score: {score}/100 │ 🚨 MALICIOUS")
            
            lines.append("│")
            lines.append(f"│  ┌─────────────────────────────────────────────┐")
            lines.append(f"│  │ IOC SUMMARY                                 │")
            lines.append(f"│  │ Total: {total} │ Malicious: {malicious} │ Suspicious: {suspicious}   │")
            lines.append(f"│  └─────────────────────────────────────────────┘")
            lines.append("└" + "─" * 77)
            lines.append("")
        else:
            lines.append("┌─ IOC ANALYSIS SUMMARY")
            lines.append("│  ℹ️  No IOCs found in email")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 7: RECOMMENDATIONS ====================
        lines.append(cls.SECTION_SEP)
        lines.append(" SECTION 7: RECOMMENDATIONS & RESPONSE ACTIONS")
        lines.append(cls.SECTION_SEP)
        lines.append("")
        
        llm_analysis = result.get('llm_analysis', {})
        recommendations = llm_analysis.get('recommendations', [])
        
        if composite_score >= 60:
            lines.append("┌─ IMMEDIATE ACTIONS (P1 - Critical)")
            lines.append("│")
            lines.append("│  1. BLOCK sender domain at email gateway")
            if email_data.get('from_domain'):
                lines.append(f"│     └─ {email_data.get('from_domain')}")
            lines.append("│")
            lines.append("│  2. QUARANTINE email in all mailboxes")
            lines.append("│     └─ Search: Subject contains suspicious keywords")
            lines.append("│")
            lines.append("│  3. ALERT Security Operations Center")
            lines.append("│     └─ Priority: P1 - Critical")
            lines.append("│")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        if recommendations:
            lines.append("┌─ AI-GENERATED RECOMMENDATIONS")
            lines.append("│")
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"│  {i}. {rec}")
            lines.append("│")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 8: DETECTION RULES ====================
        detection_rules = result.get('detection_rules', {})
        if detection_rules:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 8: DETECTION RULES")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            if detection_rules.get('kql'):
                lines.append("┌─ KQL (Microsoft Defender / Sentinel)")
                for line in detection_rules['kql'].split('\n')[:12]:
                    lines.append(f"│  {line}")
                if len(detection_rules['kql'].split('\n')) > 12:
                    lines.append("│  ... (truncated)")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            if detection_rules.get('sigma'):
                lines.append("┌─ SIGMA Rule")
                for line in detection_rules['sigma'].split('\n')[:15]:
                    lines.append(f"│  {line}")
                if len(detection_rules['sigma'].split('\n')) > 15:
                    lines.append("│  ... (truncated)")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            if detection_rules.get('spl'):
                lines.append("┌─ SPL (Splunk)")
                for line in detection_rules['spl'].split('\n')[:10]:
                    lines.append(f"│  {line}")
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # ==================== SECTION 9: FORENSICS ANALYSIS ====================
        forensics = result.get('forensics', {})
        raw_output = result.get('raw_output', {})
        raw_forensics = raw_output.get('email_analysis', {}).get('forensics', {})
        
        if forensics or raw_forensics:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 9: DFIR-GRADE FORENSICS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            forensics_score = forensics.get('forensics_score', raw_forensics.get('forensics_score', 0))
            lines.append(f"┌─ FORENSICS SCORE: {forensics_score}/100")
            lines.append("│")
            
            # Timeline
            timeline = forensics.get('timeline', raw_forensics.get('timeline', []))
            if timeline:
                lines.append("│  EMAIL TIMELINE:")
                for entry in timeline[:5]:
                    lines.append(f"│    {entry.get('time', 'N/A')} - {entry.get('event', 'N/A')}")
            
            # Relay analysis
            relay = forensics.get('relay_analysis', raw_forensics.get('relay_analysis', {}))
            if relay:
                lines.append("│")
                lines.append("│  RELAY ANALYSIS:")
                lines.append(f"│    Total Hops: {relay.get('total_hops', 0)}")
                
                suspicious_hops = relay.get('suspicious_hops', [])
                if suspicious_hops:
                    lines.append("│    ⚠️ SUSPICIOUS HOPS:")
                    for hop in suspicious_hops[:3]:
                        lines.append(f"│      • {hop}")
                
                time_anomalies = relay.get('time_anomalies', [])
                if time_anomalies:
                    lines.append("│    ⚠️ TIME ANOMALIES:")
                    for anomaly in time_anomalies[:3]:
                        lines.append(f"│      • {anomaly}")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 10: RAW HEADER DATA ====================
        raw_headers = raw_output.get('email_analysis', {}).get('headers', {})
        if raw_headers:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 10: RAW HEADER DATA")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append("┌─ RECEIVED CHAIN (Full)")
            received_chain = raw_headers.get('received_chain', [])
            for i, hop in enumerate(received_chain[:10], 1):
                lines.append(f"│  Hop {i}: {str(hop)[:70]}")
            if len(received_chain) > 10:
                lines.append(f"│  ... and {len(received_chain) - 10} more hops")
            lines.append("└" + "─" * 77)
            lines.append("")
            
            x_headers = raw_headers.get('x_headers', {})
            if x_headers:
                lines.append("┌─ X-HEADERS")
                for header, value in list(x_headers.items())[:15]:
                    lines.append(f"│  {header}: {str(value)[:60]}")
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # ==================== SECTION 11: AUTHENTICATION RAW DATA ====================
        raw_auth = raw_output.get('email_analysis', {}).get('authentication', {})
        if raw_auth:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 11: AUTHENTICATION RAW DATA")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append("┌─ SPF RECORD")
            spf = raw_auth.get('spf', {})
            lines.append(f"│  Result: {spf.get('result', 'none')}")
            lines.append(f"│  Record: {spf.get('raw_record', 'N/A')}")
            lines.append(f"│  Check IP: {spf.get('check_ip', 'N/A')}")
            lines.append("└" + "─" * 77)
            lines.append("")
            
            lines.append("┌─ DKIM SIGNATURE")
            dkim = raw_auth.get('dkim', {})
            lines.append(f"│  Result: {dkim.get('result', 'none')}")
            lines.append(f"│  Selector: {dkim.get('selector', 'N/A')}")
            lines.append(f"│  Domain: {dkim.get('domain', 'N/A')}")
            lines.append("└" + "─" * 77)
            lines.append("")
            
            lines.append("┌─ DMARC POLICY")
            dmarc = raw_auth.get('dmarc', {})
            lines.append(f"│  Result: {dmarc.get('result', 'none')}")
            lines.append(f"│  Policy: {dmarc.get('policy', 'N/A')}")
            lines.append(f"│  Record: {dmarc.get('raw_record', 'N/A')}")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 12: SCORING BREAKDOWN ====================
      
        lines.append(cls.SECTION_SEP)
        lines.append(" SECTION 12: SCORING BREAKDOWN")
        lines.append(cls.SECTION_SEP)
        lines.append("")
        
        # Get values - prefer result-level values over scoring_details
        scoring = raw_output.get('scoring_details', {})
        final_score = result.get('composite_score', scoring.get('composite_score', 0))
        final_verdict = result.get('verdict', scoring.get('verdict', 'UNKNOWN'))
        base_score = result.get('base_phishing_score', scoring.get('base_score', 0))
        forensics_score = result.get('forensics', {}).get('forensics_score', 0)
        
        lines.append("┌─ COMPOSITE SCORE CALCULATION")
        lines.append(f"│  Final Score: {final_score}/100")
        lines.append(f"│  Verdict: {final_verdict}")
        lines.append("│")
        lines.append(f"│  Base Phishing Score: {base_score}/100")
        lines.append(f"│  Forensics Risk Score: {forensics_score}/100")
        lines.append("│")
        
        breakdown = scoring.get('breakdown', {})
        if breakdown:
            lines.append("│  BREAKDOWN:")
            for component, score in breakdown.items():
                bar_len = int(min(int(score) if isinstance(score, (int, float)) else 0, 100) / 5)
                bar = "█" * bar_len + "░" * (20 - bar_len)
                lines.append(f"│  {component:25s} [{bar}] {score}")
        
        lines.append("└" + "─" * 77)
        lines.append("")
        
        # ==================== SECTION 13: PIPELINE LOG ====================
        pipeline_steps = raw_output.get('pipeline_steps', [])
        if pipeline_steps:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 13: ANALYSIS PIPELINE LOG")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append("┌─ AUTOMATED ANALYSIS STEPS")
            for step in pipeline_steps:
                status_icon = "✅" if step.get('status') == 'completed' else "❌" if step.get('status') == 'failed' else "⏳"
                step_name = step.get('step', step.get('name', step.get('details', 'unknown')))
                lines.append(f"│  {status_icon} [{step.get('phase', 'unknown'):12s}] {step_name}")
            lines.append(f"│")
            lines.append(f"│  Total Steps: {len(pipeline_steps)}")
            lines.append(f"│  Completed: {sum(1 for s in pipeline_steps if s.get('status') == 'completed')}")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== FOOTER ====================
        lines.append(cls.SECTION_SEP)
        lines.append("")
        lines.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("Blue Team Assistant Version: 1.0.0")
        lines.append("")
        
        return '\n'.join(lines)
    
    @classmethod
    def format_file_report(cls, result: Dict, file_path: str) -> str:
        """
        Format comprehensive malware analysis report.
        """
        lines = []
        
        from pathlib import Path
        filename = Path(file_path).name
        
        # ==================== HEADER ====================
        lines.append(cls.BOX_TOP)
        lines.append(f"{cls.BOX_MID}  🔬 MALWARE ANALYSIS REPORT{' ' * 48}{cls.BOX_MID}")
        lines.append(f"{cls.BOX_MID}  File: {filename[:65]}{' ' * max(0, 65 - len(filename))}{cls.BOX_MID}")
        lines.append(cls.BOX_BOT)
        lines.append("")
        
        # ==================== VERDICT BOX ====================
        verdict = result.get('verdict', 'UNKNOWN')
        composite_score = result.get('composite_score', 0)
        hash_score = result.get('hash_score', 0)
        
        verdict_emoji = {'MALICIOUS': '🦠', 'SUSPICIOUS': '⚠️', 'CLEAN': '✅', 'UNKNOWN': '❓'}
        risk_level = "CRITICAL" if composite_score >= 85 else "HIGH" if composite_score >= 60 else "MEDIUM" if composite_score >= 30 else "LOW"
        
        lines.append(cls.BOX_SINGLE_TOP)
        lines.append(f"{cls.BOX_SINGLE_MID}  {verdict_emoji.get(verdict, '')} VERDICT: {verdict}{' ' * (60 - len(verdict))}{cls.BOX_SINGLE_MID}")
        lines.append(f"{cls.BOX_SINGLE_MID}  Composite Score: {composite_score}/100 ({risk_level}){' ' * (48 - len(str(composite_score)) - len(risk_level))}{cls.BOX_SINGLE_MID}")
        lines.append(f"{cls.BOX_SINGLE_MID}  Hash Score: {hash_score}/100{' ' * (57 - len(str(hash_score)))}{cls.BOX_SINGLE_MID}")
        
        # Malware family if detected
        yara_analysis = result.get('yara_analysis', {})
        interpretation = yara_analysis.get('interpretation', {})
        malware_families = interpretation.get('malware_families', [])
        if malware_families:
            family_str = ', '.join(malware_families[:2])
            lines.append(f"{cls.BOX_SINGLE_MID}  Malware Family: {family_str}{' ' * max(0, 54 - len(family_str))}{cls.BOX_SINGLE_MID}")
        
        lines.append(cls.BOX_SINGLE_BOT)
        lines.append("")
        
        # ==================== SECTION 1: FILE INFO ====================
        lines.append(cls.SECTION_SEP)
        lines.append(" SECTION 1: FILE INFORMATION")
        lines.append(cls.SECTION_SEP)
        lines.append("")
        
        file_info = result.get('file_info', {})
        hashes = result.get('hashes', {})
        
        lines.append(f"  File Name    : {file_info.get('name', filename)}")
        lines.append(f"  File Size    : {file_info.get('size', 0):,} bytes ({file_info.get('size_mb', 0)} MB)")
        lines.append(f"  File Type    : {file_info.get('extension', 'Unknown')}")
        lines.append("")
        lines.append("  HASHES:")
        lines.append(f"  ├─ MD5       : {hashes.get('md5', 'Unknown')}")
        lines.append(f"  ├─ SHA1      : {hashes.get('sha1', 'Unknown')}")
        lines.append(f"  └─ SHA256    : {hashes.get('sha256', 'Unknown')}")
        lines.append("")
        
        # ==================== SECTION 2: STATIC ANALYSIS ====================
        static = result.get('static_analysis', {})
        file_type = str(result.get('file_type', static.get('file_type', 'unknown'))).lower()
        
        # -------------------- SCRIPT ANALYSIS --------------------
        if file_type == 'script' or static.get('script_type'):
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 2: SCRIPT STATIC ANALYSIS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            # Script Info
            lines.append("┌─ SCRIPT INFORMATION")
            lines.append("│")
            lines.append(f"│  Script Type       : {static.get('script_type', 'Unknown').upper()}")
            lines.append(f"│  Size (bytes)      : {static.get('size', static.get('file_size', 0)):,}")
            lines.append(f"│  Threat Score      : {static.get('threat_score', 0)}/100")
            lines.append(f"│  Verdict           : {static.get('verdict', 'Unknown')}")
            lines.append("└" + "─" * 77)
            lines.append("")
            
            # Threat Indicators
            threat_indicators = static.get('threat_indicators', [])
            if threat_indicators:
                lines.append(f"┌─ THREAT INDICATORS ({len(threat_indicators)} found)")
                lines.append("│")
                for indicator in threat_indicators[:10]:
                    icon = "🚨" if any(x in indicator.lower() for x in ['execution', 'credential', 'obfuscated']) else "⚠️"
                    lines.append(f"│  {icon} {indicator}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Suspicious Patterns
            patterns = static.get('suspicious_patterns', {})
            categories = patterns.get('categories', {})
            if categories:
                total_matches = patterns.get('total_matches', sum(c.get('count', 0) for c in categories.values()))
                lines.append(f"┌─ SUSPICIOUS PATTERNS ({total_matches} matches)")
                lines.append("│")
                
                # Sort by count
                sorted_cats = sorted(categories.items(), key=lambda x: x[1].get('count', 0), reverse=True)
                for category, data in sorted_cats:
                    count = data.get('count', 0)
                    samples = data.get('samples', [])
                    
                    # Risk level icons
                    if category in ['execution', 'download', 'credential', 'evasion']:
                        icon = "🔴"
                    elif category in ['persistence', 'encoding', 'network']:
                        icon = "🟠"
                    else:
                        icon = "🟡"
                    
                    lines.append(f"│  {icon} {category.upper()}: {count} patterns")
                    for sample in samples[:3]:
                        lines.append(f"│     └─ {sample[:60]}")
                
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Obfuscation Detection
            obfuscation = static.get('obfuscation', {})
            if obfuscation.get('likely_obfuscated'):
                lines.append("┌─ OBFUSCATION DETECTED 🚨")
                lines.append("│")
                lines.append(f"│  Confidence: {obfuscation.get('confidence', 0)}%")
                techniques = obfuscation.get('techniques', [])
                if techniques:
                    lines.append(f"│  Techniques: {', '.join(techniques[:5])}")
                indicators = obfuscation.get('indicators', [])
                for ind in indicators[:5]:
                    lines.append(f"│  ├─ {ind}")
                lines.append("│")
                lines.append("│  ⚠️  Obfuscation is commonly used to evade detection")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Encoded Content
            encoded = static.get('encoded_content', [])
            if encoded:
                lines.append(f"┌─ ENCODED CONTENT ({len(encoded)} blocks)")
                lines.append("│")
                for enc in encoded[:5]:
                    enc_type = enc.get('type', 'unknown')
                    original = enc.get('encoded', '')[:50]
                    decoded = enc.get('decoded', '')[:50]
                    lines.append(f"│  [{enc_type.upper()}]")
                    lines.append(f"│  ├─ Encoded : {original}...")
                    if decoded:
                        lines.append(f"│  └─ Decoded : {decoded}...")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Network Indicators
            network = static.get('network_indicators', [])
            if network:
                lines.append(f"┌─ NETWORK INDICATORS ({len(network)} found)")
                lines.append("│")
                for net in network[:10]:
                    lines.append(f"│  🌐 {net}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # File Indicators
            file_ind = static.get('file_indicators', [])
            if file_ind:
                lines.append(f"┌─ FILE SYSTEM INDICATORS ({len(file_ind)} found)")
                lines.append("│")
                for f in file_ind[:10]:
                    lines.append(f"│  📁 {f}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Registry Indicators
            registry = static.get('registry_indicators', [])
            if registry:
                lines.append(f"┌─ REGISTRY INDICATORS ({len(registry)} found)")
                lines.append("│")
                for reg in registry[:10]:
                    lines.append(f"│  🔑 {reg}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # IOCs from Script
            iocs = static.get('iocs', {})
            if any(iocs.values()):
                total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
                lines.append(f"┌─ EXTRACTED IOCs ({total_iocs} found)")
                lines.append("│")
                if iocs.get('urls'):
                    lines.append(f"│  URLs ({len(iocs['urls'])}):")
                    for url in iocs['urls'][:5]:
                        lines.append(f"│  ├─ {url[:70]}")
                if iocs.get('ipv4'):
                    lines.append(f"│  IPs ({len(iocs['ipv4'])}):")
                    for ip in iocs['ipv4'][:5]:
                        lines.append(f"│  ├─ {ip}")
                if iocs.get('domains'):
                    lines.append(f"│  Domains ({len(iocs['domains'])}):")
                    for domain in iocs['domains'][:5]:
                        lines.append(f"│  ├─ {domain}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Analysis Tools Used
            tools = static.get('analysis_tools', [])
            if tools:
                lines.append(f"┌─ ANALYSIS TOOLS USED")
                lines.append("│")
                lines.append(f"│  {', '.join(tools)}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
          
            # Get entropy from multiple possible locations
            entropy_analysis = result.get('entropy_analysis', {})
            if not entropy_analysis:
                raw_output = result.get('raw_output', {})
                entropy_analysis = raw_output.get('file_analysis', {}).get('tool_outputs', {}).get('entropy', {})
            
            if entropy_analysis:
                # Handle both structures: with file_entropy wrapper or direct
                if 'file_entropy' in entropy_analysis:
                    file_entropy = entropy_analysis['file_entropy']
                    overall_entropy = file_entropy.get('overall_entropy', 0)
                    interpretation = file_entropy.get('interpretation', {})
                else:
                    # Direct structure from tool_outputs
                    overall_entropy = entropy_analysis.get('overall_entropy', 0)
                    interpretation = entropy_analysis.get('interpretation', {})
                
                category = interpretation.get('category', 'unknown')
                description = interpretation.get('description', '')
                
                lines.append("┌─ ENTROPY ANALYSIS")
                lines.append("│")
                lines.append(f"│  Overall File Entropy: {overall_entropy:.2f} / 8.00")
                lines.append("│")
                
                # Visual bar
                bar_filled = int(overall_entropy / 8.0 * 50)
                bar = "█" * bar_filled + "░" * (50 - bar_filled)
                pct = int(overall_entropy / 8.0 * 100)
                lines.append(f"│  ┌{'─' * 54}┐")
                lines.append(f"│  │ {bar} {pct:3d}% │")
                lines.append(f"│  └{'─' * 54}┘")
                lines.append("│")
                lines.append(f"│  Classification: {category.upper()}")
                if description:
                    lines.append(f"│  Interpretation: {description}")
                lines.append("│")
                
                # Chunk analysis if available
                chunk_analysis = entropy_analysis.get('chunk_analysis', {})
                if chunk_analysis:
                    lines.append(f"│  Chunk Analysis:")
                    lines.append(f"│    Average: {chunk_analysis.get('average', 0):.2f}")
                    lines.append(f"│    Max: {chunk_analysis.get('max', 0):.2f}")
                    lines.append(f"│    Min: {chunk_analysis.get('min', 0):.2f}")
                    lines.append("│")
                
                if overall_entropy > 7.0:
                    lines.append("│  🚨 HIGH ENTROPY - Likely PACKED or ENCRYPTED")
                elif overall_entropy > 6.5:
                    lines.append("│  ⚠️  ELEVATED ENTROPY - May contain compressed/encoded data")
                elif overall_entropy < 4.0:
                    lines.append("│  ℹ️  LOW ENTROPY - Plain text or low complexity data")
                
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # -------------------- PE ANALYSIS --------------------
        elif file_type == 'pe' or str(static.get('file_type', '')).lower() == 'pe':
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 2: PE STATIC ANALYSIS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
          
            pe_analysis = static.get('pe_analysis', {})
            headers = pe_analysis.get('headers', {})
            
            # Map machine code to architecture
            machine_map = {
                '0x14c': 'x86 (32-bit)',
                '0x8664': 'x64 (64-bit)',
                '0x1c0': 'ARM',
                '0xaa64': 'ARM64',
            }
            machine = headers.get('machine', 'Unknown')
            architecture = machine_map.get(machine, machine)
            
            # Determine PE type from characteristics
            characteristics = headers.get('characteristics', '')
            if '0x2000' in str(characteristics) or headers.get('is_dll'):
                pe_type = 'DLL'
            elif '0x2' in str(characteristics):
                pe_type = 'EXE'
            else:
                pe_type = 'EXE'  # Default
            
            # Format timestamp
            timestamp = headers.get('timestamp', 0)
            if timestamp:
                from datetime import datetime
                try:
                    compile_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    compile_time = str(timestamp)
            else:
                compile_time = 'Unknown'
            
            # Subsystem mapping
            subsystem_map = {
                1: 'Native', 2: 'Windows GUI', 3: 'Windows Console',
                5: 'OS/2 Console', 7: 'POSIX Console', 9: 'Windows CE',
                10: 'EFI Application', 14: 'Xbox'
            }
            subsystem = headers.get('subsystem', 0)
            subsystem_str = subsystem_map.get(subsystem, f'Unknown ({subsystem})')
            
            entry_point = headers.get('entry_point', 'Unknown')
            if entry_point != 'Unknown':
                entry_point = f"0x{entry_point:X}" if isinstance(entry_point, int) else entry_point
            
            lines.append("┌─ PE HEADER INFORMATION")
            lines.append("│")
            lines.append(f"│  Architecture      : {architecture}")
            lines.append(f"│  PE Type           : {pe_type}")
            lines.append(f"│  Compile Time      : {compile_time}")
            lines.append(f"│  Entry Point       : {entry_point}")
            lines.append(f"│  Subsystem         : {subsystem_str}")
            lines.append("│")
            
            # Security features
            aslr = "✅" if headers.get('aslr') else "❌"
            dep = "✅" if headers.get('dep') else "❌"
            cfg = "✅" if headers.get('cfg') else "❌"
            lines.append(f"│  ASLR: {aslr} | DEP: {dep} | CFG: {cfg}")
            lines.append("│")
            
            sig = static.get('signature', {})
            sig_status = "✅ Signed" if sig.get('signed') else "❌ Unsigned"
            lines.append(f"│  Digital Signature : {sig_status}")
            if sig.get('signed') and sig.get('signer'):
                lines.append(f"│    └─ Signer: {sig.get('signer')}")
            
            lines.append("└" + "─" * 77)
            lines.append("")
            
            # Entropy - v1.0.0: Get from result, not static
            entropy_analysis = result.get('entropy_analysis', {})
            # Fallback to raw_output if not in result
            if not entropy_analysis:
                raw_output = result.get('raw_output', {})
                entropy_analysis = raw_output.get('file_analysis', {}).get('tool_outputs', {}).get('entropy', {})
            
            if entropy_analysis:
                # Handle both structures: with file_entropy wrapper or direct
                if 'file_entropy' in entropy_analysis:
                    file_entropy = entropy_analysis['file_entropy']
                    overall_entropy = file_entropy.get('overall_entropy', 0)
                    interpretation = file_entropy.get('interpretation', {})
                else:
                    # Direct structure from tool_outputs
                    overall_entropy = entropy_analysis.get('overall_entropy', 0)
                    interpretation = entropy_analysis.get('interpretation', {})
                
                category = interpretation.get('category', 'unknown')
                description = interpretation.get('description', '')
                
                lines.append("┌─ ENTROPY ANALYSIS")
                lines.append("│")
                lines.append(f"│  Overall File Entropy: {overall_entropy:.2f} / 8.00")
                lines.append("│")
                
                # Visual bar
                bar_filled = int(overall_entropy / 8.0 * 50)
                bar = "█" * bar_filled + "░" * (50 - bar_filled)
                pct = int(overall_entropy / 8.0 * 100)
                lines.append(f"│  ┌{'─' * 54}┐")
                lines.append(f"│  │ {bar} {pct:3d}% │")
                lines.append(f"│  └{'─' * 54}┘")
                lines.append("│")
                lines.append(f"│  Classification: {category.upper()}")
                if description:
                    lines.append(f"│  Interpretation: {description}")
                lines.append("│")
                
                if overall_entropy > 7.0:
                    lines.append("│  🚨 HIGH ENTROPY - Likely PACKED or ENCRYPTED")
                
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Sections
            sections = static.get('sections', [])
            if sections:
                lines.append(f"┌─ SECTION ANALYSIS ({len(sections)} sections)")
                lines.append("│")
                lines.append("│  ┌─────────┬───────────┬───────────┬─────────┬──────────────────────────┐")
                lines.append("│  │ Section │ V.Size    │ Raw Size  │ Entropy │ Characteristics          │")
                lines.append("│  ├─────────┼───────────┼───────────┼─────────┼──────────────────────────┤")
                
                for section in sections[:10]:
                    name = section.get('name', 'Unknown')[:8]
                    vsize = section.get('virtual_size', 0)
                    rsize = section.get('raw_size', 0)
                    entropy = section.get('entropy', 0)
                    chars = section.get('characteristics', [])
                    suspicious = section.get('suspicious', False)
                    
                    char_str = '/'.join(chars[:3]) if chars else '-'
                    char_str = char_str[:24]
                    
                    flag = "🚨" if suspicious else "  "
                    
                    lines.append(f"│  │{flag}{name:8s}│ {vsize:9,} │ {rsize:9,} │ {entropy:7.2f} │ {char_str:24s}│")
                    
                    if suspicious and section.get('suspicion_reason'):
                        lines.append(f"│  │         └ ⚠️  {section.get('suspicion_reason')[:50]}")
                
                lines.append("│  └─────────┴───────────┴───────────┴─────────┴──────────────────────────┘")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Packer
            packer = static.get('packer_detection', {})
            if packer.get('packed'):
                lines.append("┌─ PACKER DETECTION")
                lines.append("│")
                lines.append(f"│  🚨 PACKER DETECTED: {packer.get('packer', 'Unknown')}")
                lines.append(f"│  Confidence: {packer.get('confidence', 'Unknown').upper()}")
                lines.append("│")
                indicators = packer.get('indicators', [])
                if indicators:
                    lines.append("│  INDICATORS:")
                    for ind in indicators[:5]:
                        lines.append(f"│  ├─ {ind}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Suspicious Imports
            imports = static.get('imports', [])
            suspicious_imports = [imp for imp in imports if imp.get('suspicious_count', 0) > 0]
            
            if suspicious_imports:
                total_sus = sum(imp.get('suspicious_count', 0) for imp in imports)
                lines.append(f"┌─ IMPORT ANALYSIS ({total_sus} suspicious APIs)")
                lines.append("│")
                
                for imp in suspicious_imports[:6]:
                    dll = imp.get('dll', 'Unknown')
                    sus_apis = imp.get('suspicious_apis', [])
                    lines.append(f"│  {dll}")
                    for api in sus_apis[:4]:
                        lines.append(f"│  ├─ 🚨 {api}")
                    if len(sus_apis) > 4:
                        lines.append(f"│  └─ ... {len(sus_apis) - 4} more")
                
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Anti-Analysis
            anti_analysis = static.get('anti_analysis', [])
            if anti_analysis:
                lines.append(f"┌─ ANTI-ANALYSIS TECHNIQUES ({len(anti_analysis)} detected)")
                lines.append("│")
                for technique in anti_analysis[:8]:
                    lines.append(f"│  🚨 {technique}")
                lines.append("│")
                lines.append("│  ⚠️  Multiple anti-analysis techniques indicate malicious intent")
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # ==================== SECTION 2.5: PROFESSIONAL TOOL ANALYSIS  ====================
        lines.extend(cls._format_professional_tools_section(result))
        
        # ==================== SECTION 3: STRING ANALYSIS ====================
        string_analysis = result.get('string_analysis', {})
        if string_analysis.get('total_strings', 0) > 0:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 3: STRING ANALYSIS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append(f"┌─ STRING STATISTICS")
            lines.append(f"│  Total Strings    : {string_analysis.get('total_strings', 0):,}")
            lines.append(f"│  ASCII Strings    : {string_analysis.get('ascii_strings', 0):,}")
            lines.append(f"│  Unicode Strings  : {string_analysis.get('unicode_strings', 0):,}")
            lines.append("└" + "─" * 77)
            lines.append("")
            
            # Suspicious Categories
            categories = string_analysis.get('suspicious_categories', {})
            if categories:
                lines.append("┌─ SUSPICIOUS STRING CATEGORIES")
                for cat, strings in list(categories.items())[:6]:
                    if strings:
                        count = len(strings) if isinstance(strings, list) else strings
                        lines.append(f"│  {cat}: {count} strings")
                        if isinstance(strings, list):
                            for s in strings[:3]:
                                lines.append(f"│    • {s[:60]}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Registry Keys
            registry_keys = string_analysis.get('registry_keys', [])
            if registry_keys:
                lines.append("┌─ REGISTRY KEYS")
                for key in registry_keys[:5]:
                    lines.append(f"│  • {key[:70]}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Interesting Strings
            interesting = string_analysis.get('interesting_strings', [])
            if interesting:
                lines.append("┌─ INTERESTING STRINGS (Top 10)")
                for s in interesting[:10]:
                    lines.append(f"│  • {s[:70]}")
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # ==================== SECTION 4: YARA ANALYSIS ====================
        yara_analysis = result.get('yara_analysis', {})
        matches = yara_analysis.get('matches', [])
        
        if matches:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 4: YARA ANALYSIS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append(f"┌─ YARA MATCHES ({len(matches)} rules)")
            
            for match in matches[:5]:
                rule = match.get('rule', 'Unknown')
                severity = match.get('meta', {}).get('severity', 'UNKNOWN')
                description = match.get('meta', {}).get('description', '')
                
                severity_emoji = "🚨" if severity in ['CRITICAL', 'HIGH'] else "⚠️"
                
                lines.append("│")
                lines.append(f"│  RULE: {rule}")
                lines.append(f"│  ├─ Severity    : {severity_emoji} {severity}")
                if description:
                    lines.append(f"│  └─ Description : {description[:50]}")
            
            lines.append("│")
            
            # Malware families
            if malware_families:
                lines.append("│  ┌─────────────────────────────────────────────┐")
                lines.append(f"│  │ 🦠 MALWARE FAMILY: {', '.join(malware_families[:2]):22s}│")
                lines.append("│  └─────────────────────────────────────────────┘")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 5: SANDBOX ANALYSIS ====================
        sandbox_analysis = result.get('sandbox_analysis', {})
        summary = sandbox_analysis.get('summary', {})
        
        if summary.get('available_reports', 0) > 0:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 5: SANDBOX ANALYSIS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            # VirusTotal
            vt = sandbox_analysis.get('virustotal_behavior', {})
            if vt and not vt.get('error'):
                lines.append("┌─ VirusTotal Behavior")
                if vt.get('found'):
                    lines.append("│  Status: ✅ REPORT FOUND")
                    behaviors = vt.get('behaviors', [])
                    if behaviors:
                        for b in behaviors[:3]:
                            lines.append(f"│  • {b}")
                    if vt.get('report_url'):
                        lines.append(f"│  🔗 {vt.get('report_url')}")
                else:
                    lines.append("│  Status: ⚠️ NO REPORT FOUND")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # ANY.RUN
            anyrun = sandbox_analysis.get('anyrun', {})
            if anyrun and not anyrun.get('error'):
                lines.append("┌─ ANY.RUN")
                if anyrun.get('found'):
                    lines.append("│  Status: ✅ SUBMISSION FOUND")
                    lines.append(f"│  Verdict: {anyrun.get('verdict', 'Unknown')}")
                    if anyrun.get('malware_family'):
                        lines.append(f"│  Family: {anyrun.get('malware_family')}")
                    if anyrun.get('report_url'):
                        lines.append(f"│  🔗 {anyrun.get('report_url')}")
                else:
                    lines.append("│  Status: ⚠️ NO SUBMISSION FOUND")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Aggregate behaviors
            behaviors = summary.get('behaviors', [])
            if behaviors:
                lines.append("┌─ AGGREGATE BEHAVIORS")
                for b in behaviors[:5]:
                    lines.append(f"│  • {b}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # MITRE (quick summary in sandbox)
            mitre = summary.get('mitre_techniques', [])
            if mitre:
                lines.append("┌─ MITRE ATT&CK Techniques")
                lines.append(f"│  {', '.join(mitre[:8])}")
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # ==================== SECTION 4: MITRE ATT&CK MAPPING (v1.0.0) ====================
        mitre_mapping = result.get('mitre_mapping', [])
        # Also check sandbox for MITRE if mitre_mapping is empty
        if not mitre_mapping:
            sandbox = result.get('sandbox_analysis', {})
            sandbox_summary = sandbox.get('summary', {})
            sandbox_mitre = sandbox_summary.get('mitre_techniques', [])
            if sandbox_mitre:
                mitre_mapping = [{'technique_id': t, 'source': 'sandbox'} for t in sandbox_mitre]
        
        if mitre_mapping:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 4: MITRE ATT&CK MAPPING")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            # Group by tactic/category
            tactics = {
                'T1059': ('Execution', 'Command and Scripting Interpreter'),
                'T1059.001': ('Execution', 'PowerShell'),
                'T1027': ('Defense Evasion', 'Obfuscated Files or Information'),
                'T1140': ('Defense Evasion', 'Deobfuscate/Decode Files'),
                'T1547': ('Persistence', 'Boot or Logon Autostart Execution'),
                'T1547.009': ('Persistence', 'Shortcut Modification'),
                'T1053': ('Persistence', 'Scheduled Task/Job'),
                'T1003': ('Credential Access', 'OS Credential Dumping'),
                'T1555': ('Credential Access', 'Credentials from Password Stores'),
                'T1082': ('Discovery', 'System Information Discovery'),
                'T1083': ('Discovery', 'File and Directory Discovery'),
                'T1012': ('Discovery', 'Query Registry'),
                'T1010': ('Discovery', 'Application Window Discovery'),
                'T1105': ('Command and Control', 'Ingress Tool Transfer'),
                'T1071': ('Command and Control', 'Application Layer Protocol'),
                'T1548': ('Privilege Escalation', 'Abuse Elevation Control'),
                'T1134': ('Privilege Escalation', 'Access Token Manipulation'),
                'T1562': ('Defense Evasion', 'Impair Defenses'),
                'T1070': ('Defense Evasion', 'Indicator Removal'),
                'T1112': ('Defense Evasion', 'Modify Registry'),
                'T1222': ('Defense Evasion', 'File and Directory Permissions Modification'),
                'T1560': ('Collection', 'Archive Collected Data'),
                'T1119': ('Collection', 'Automated Collection'),
                'T1115': ('Collection', 'Clipboard Data'),
                'T1041': ('Exfiltration', 'Exfiltration Over C2 Channel'),
                'T1529': ('Impact', 'System Shutdown/Reboot'),
                'T1129': ('Execution', 'Shared Modules'),
                'T1125': ('Collection', 'Video Capture'),
            }
            
            lines.append("┌─ DETECTED TECHNIQUES")
            lines.append("│")
            
            seen = set()
            for mapping in mitre_mapping:
                tech_id = mapping.get('technique_id', '')
                if tech_id in seen:
                    continue
                seen.add(tech_id)
                
                tactic_info = tactics.get(tech_id, ('Unknown', 'Unknown Technique'))
                source = mapping.get('source', 'analysis')
                confidence = mapping.get('confidence', 'medium')
                
                conf_icon = "🔴" if confidence == 'high' else "🟡" if confidence == 'medium' else "⚪"
                lines.append(f"│  {conf_icon} {tech_id}: {tactic_info[1]}")
                lines.append(f"│     └─ Tactic: {tactic_info[0]} | Source: {source}")
            
            lines.append("│")
            lines.append(f"│  Total Techniques: {len(seen)}")
            lines.append("└" + "─" * 77)
            lines.append("")
            
            # MITRE Navigator link
            tech_ids = [m.get('technique_id', '') for m in mitre_mapping if m.get('technique_id')]
            if tech_ids:
                lines.append("┌─ MITRE ATT&CK NAVIGATOR")
                lines.append(f"│  Techniques: {', '.join(list(seen)[:15])}")
                lines.append(f"│  🔗 https://mitre-attack.github.io/attack-navigator/")
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # ==================== SECTION 6: DETECTION RULES ====================
        detection_rules = result.get('detection_rules', {})
        if detection_rules:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 6: DETECTION RULES")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            if detection_rules.get('kql'):
                lines.append("┌─ KQL (Microsoft Defender / Sentinel)")
                for line in detection_rules['kql'].split('\n')[:12]:
                    lines.append(f"│  {line}")
                if len(detection_rules['kql'].split('\n')) > 12:
                    lines.append("│  ... (truncated)")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            if detection_rules.get('yara'):
                lines.append("┌─ YARA Rule")
                for line in detection_rules['yara'].split('\n')[:20]:
                    lines.append(f"│  {line}")
                if len(detection_rules['yara'].split('\n')) > 20:
                    lines.append("│  ... (truncated)")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            if detection_rules.get('sigma'):
                lines.append("┌─ SIGMA Rule")
                for line in detection_rules['sigma'].split('\n')[:18]:
                    lines.append(f"│  {line}")
                if len(detection_rules['sigma'].split('\n')) > 18:
                    lines.append("│  ... (truncated)")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            if detection_rules.get('spl'):
                lines.append("┌─ SPL (Splunk)")
                for line in detection_rules['spl'].split('\n')[:10]:
                    lines.append(f"│  {line}")
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # ==================== SECTION 7: AI ANALYSIS ====================
        llm = result.get('llm_analysis', {})
        if llm and llm.get('analysis'):
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 7: AI-POWERED ANALYSIS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append("┌─ LLM ANALYSIS")
            for line in llm.get('analysis', '').split('\n')[:15]:
                lines.append(f"│  {line}")
            lines.append("└" + "─" * 77)
            lines.append("")
            
            if llm.get('recommendations'):
                lines.append("┌─ AI RECOMMENDATIONS")
                for rec in llm.get('recommendations', [])[:5]:
                    lines.append(f"│  • {rec}")
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # ==================== SECTION 8: IOC ANALYSIS ====================
        ioc_analysis = result.get('ioc_analysis', {})
        if ioc_analysis.get('total_iocs', 0) > 0:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 8: EMBEDDED IOC ANALYSIS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append("┌─ IOC SUMMARY")
            lines.append(f"│  Total IOCs Found    : {ioc_analysis.get('total_iocs', 0)}")
            lines.append(f"│  Malicious IOCs      : {ioc_analysis.get('malicious_iocs', 0)}")
            lines.append(f"│  Suspicious IOCs     : {ioc_analysis.get('suspicious_iocs', 0)}")
            lines.append("│")
            
            for ioc_result in ioc_analysis.get('results', [])[:5]:
                ioc = ioc_result.get('ioc', 'Unknown')
                ioc_verdict = ioc_result.get('verdict', 'UNKNOWN')
                ioc_score = ioc_result.get('threat_score', 0)
                emoji = "🚨" if ioc_verdict == "MALICIOUS" else "⚠️" if ioc_verdict == "SUSPICIOUS" else "✅"
                lines.append(f"│  {emoji} {ioc[:50]}")
                lines.append(f"│     └─ Verdict: {ioc_verdict} | Score: {ioc_score}/100")
            
            if ioc_analysis.get('total_iocs', 0) > 5:
                lines.append(f"│  ... and {ioc_analysis.get('total_iocs', 0) - 5} more IOCs")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 9: STRING ANALYSIS DETAILS ====================
        string_analysis = result.get('string_analysis', {})
        raw_output = result.get('raw_output', {})
        raw_strings = raw_output.get('file_analysis', {}).get('strings', {})
        
        if string_analysis or raw_strings:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 9: STRING ANALYSIS DETAILS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append("┌─ STRING STATISTICS")
            lines.append(f"│  Total Strings      : {string_analysis.get('total_strings', raw_strings.get('total_count', 0))}")
            lines.append(f"│  ASCII Strings      : {string_analysis.get('ascii_strings', raw_strings.get('ascii_count', 0))}")
            lines.append(f"│  Unicode Strings    : {string_analysis.get('unicode_strings', raw_strings.get('unicode_count', 0))}")
            lines.append("└" + "─" * 77)
            lines.append("")
            
            # URLs found in strings
            urls = raw_strings.get('urls', []) or string_analysis.get('urls', [])
            if urls:
                lines.append("┌─ URLS EXTRACTED FROM STRINGS")
                for url in urls[:15]:
                    lines.append(f"│  • {url}")
                if len(urls) > 15:
                    lines.append(f"│  ... and {len(urls) - 15} more URLs")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # IPs found
            ips = raw_strings.get('ips', []) or string_analysis.get('ips', [])
            if ips:
                lines.append("┌─ IP ADDRESSES EXTRACTED")
                for ip in ips[:10]:
                    lines.append(f"│  • {ip}")
                if len(ips) > 10:
                    lines.append(f"│  ... and {len(ips) - 10} more IPs")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Registry keys
            registry_keys = string_analysis.get('registry_keys', []) or raw_strings.get('registry', [])
            if registry_keys:
                lines.append("┌─ REGISTRY KEYS FOUND")
                for reg in registry_keys[:10]:
                    lines.append(f"│  • {reg}")
                if len(registry_keys) > 10:
                    lines.append(f"│  ... and {len(registry_keys) - 10} more registry keys")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Mutexes
            mutexes = string_analysis.get('mutexes', []) or raw_strings.get('mutexes', [])
            if mutexes:
                lines.append("┌─ MUTEXES FOUND")
                for mutex in mutexes[:5]:
                    lines.append(f"│  • {mutex}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Suspicious string categories
            categories = string_analysis.get('suspicious_categories', {}) or raw_strings.get('categories', {})
            if categories:
                lines.append("┌─ SUSPICIOUS STRING CATEGORIES")
                for category, strings in categories.items():
                    if strings:
                        count = len(strings) if isinstance(strings, list) else strings
                        lines.append(f"│  ⚠️ {category.upper()}: {count} occurrences")
                        if isinstance(strings, list):
                            for s in strings[:3]:
                                lines.append(f"│     └─ {str(s)[:60]}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Interesting strings
            interesting = string_analysis.get('interesting_strings', []) or raw_strings.get('interesting', [])
            if interesting:
                lines.append("┌─ INTERESTING STRINGS (Quick Triage)")
                for s in interesting[:20]:
                    lines.append(f"│  • {str(s)[:70]}")
                if len(interesting) > 20:
                    lines.append(f"│  ... and {len(interesting) - 20} more")
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # ==================== SECTION 10: THREAT INTEL API RESPONSES ====================
        api_responses = raw_output.get('api_responses', {})
        if api_responses:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 10: THREAT INTEL API RESPONSES")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            for source, data in api_responses.items():
                response = data.get('response', {}) if isinstance(data, dict) else data
                status = data.get('status', 'unknown') if isinstance(data, dict) else 'unknown'
                
                emoji = "✅" if status == 'success' else "❌" if status == 'error' else "⚪"
                lines.append(f"┌─ {source.upper()} {emoji}")
                
                if isinstance(response, dict):
                    for key, value in list(response.items())[:8]:
                        if key not in ['error', 'raw']:
                            lines.append(f"│  {key}: {str(value)[:60]}")
                else:
                    lines.append(f"│  Response: {str(response)[:100]}")
                
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # ==================== SECTION 11: SANDBOX ANALYSIS ====================
        sandbox = result.get('sandbox_analysis', {})
        raw_sandbox = raw_output.get('file_analysis', {}).get('sandbox', {})
        
        if sandbox or raw_sandbox:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 11: SANDBOX ANALYSIS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            sha256 = result.get('hashes', {}).get('sha256', '')
            
            # VirusTotal
            vt = sandbox.get('virustotal_behavior', {}) or raw_sandbox.get('virustotal', {})
            if vt:
                lines.append("┌─ VIRUSTOTAL BEHAVIOR ANALYSIS")
                lines.append(f"│  Status: {'✅ Found' if vt.get('found') else '⚠️ Not Found'}")
                if vt.get('behaviors'):
                    lines.append("│  Behaviors:")
                    for b in vt.get('behaviors', [])[:5]:
                        lines.append(f"│    • {b}")
                lines.append(f"│  🔗 https://www.virustotal.com/gui/file/{sha256}/behavior")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # ANY.RUN
            anyrun = sandbox.get('anyrun', {}) or raw_sandbox.get('anyrun', {})
            if anyrun:
                lines.append("┌─ ANY.RUN ANALYSIS")
                lines.append(f"│  Status: {'✅ Found' if anyrun.get('found') else '⚠️ Not Found'}")
                if anyrun.get('verdict'):
                    lines.append(f"│  Verdict: {anyrun.get('verdict')}")
                lines.append(f"│  🔗 https://app.any.run/submissions/#filehash:{sha256}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            # Sandbox Links
            lines.append("┌─ SANDBOX QUICK LINKS")
            lines.append(f"│  VirusTotal    : https://www.virustotal.com/gui/file/{sha256}")
            lines.append(f"│  Hybrid Analysis: https://www.hybrid-analysis.com/search?query={sha256}")
            lines.append(f"│  ANY.RUN       : https://app.any.run/submissions/#filehash:{sha256}")
            lines.append(f"│  MalwareBazaar : https://bazaar.abuse.ch/sample/{sha256}/")
            lines.append(f"│  Joe Sandbox   : https://www.joesandbox.com/search?q={sha256}")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 12: SCORING BREAKDOWN ====================
        scoring = raw_output.get('scoring_details', {})
        if scoring:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 12: SCORING BREAKDOWN")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append("┌─ COMPOSITE SCORE CALCULATION")
            lines.append(f"│  Final Score: {scoring.get('composite_score', result.get('composite_score', 0))}/100")
            lines.append(f"│  Verdict: {scoring.get('verdict', result.get('verdict', 'UNKNOWN'))}")
            lines.append("│")
            
            breakdown = scoring.get('breakdown', {})
            if breakdown:
                lines.append("│  BREAKDOWN:")
                for component, score in breakdown.items():
                    bar_len = int(min(score, 100) / 5)
                    bar = "█" * bar_len + "░" * (20 - bar_len)
                    lines.append(f"│  {component:25s} [{bar}] {score}")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== SECTION 13: PIPELINE EXECUTION LOG ====================
        pipeline_steps = raw_output.get('pipeline_steps', [])
        if pipeline_steps:
            lines.append(cls.SECTION_SEP)
            lines.append(" SECTION 13: ANALYSIS PIPELINE LOG")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append("┌─ AUTOMATED ANALYSIS STEPS")
            for step in pipeline_steps:
                status_icon = "✅" if step.get('status') == 'completed' else "❌" if step.get('status') == 'failed' else "⏳"
                step_name = step.get('step', step.get('name', step.get('details', 'unknown')))
                lines.append(f"│  {status_icon} [{step.get('phase', 'unknown'):12s}] {step_name}")
            lines.append(f"│")
            lines.append(f"│  Total Steps: {len(pipeline_steps)}")
            lines.append(f"│  Completed: {sum(1 for s in pipeline_steps if s.get('status') == 'completed')}")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== FOOTER ====================
        lines.append(cls.SECTION_SEP)
        lines.append("")
        lines.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("Blue Team Assistant Version: 1.0.0")
        lines.append("")
        
        return '\n'.join(lines)
    
    @classmethod
    def format_ioc_report(cls, result: Dict, ioc: str) -> str:
        """
        Format comprehensive IOC investigation report.
        """
        lines = []
        
        # ==================== HEADER ====================
        lines.append(cls.BOX_TOP)
        lines.append(f"{cls.BOX_MID}  🔍 IOC INVESTIGATION REPORT{' ' * 48}{cls.BOX_MID}")
        lines.append(f"{cls.BOX_MID}  IOC: {ioc[:68]}{' ' * max(0, 68 - len(ioc))}{cls.BOX_MID}")
        lines.append(cls.BOX_BOT)
        lines.append("")
        
        # ==================== VERDICT BOX ====================
        verdict = result.get('verdict', 'UNKNOWN')
        threat_score = result.get('threat_score', 0)
        ioc_type = result.get('ioc_type', 'Unknown')
        
        verdict_emoji = {'MALICIOUS': '🚨', 'SUSPICIOUS': '⚠️', 'CLEAN': '✅', 'UNKNOWN': '❓'}
        risk_level = "CRITICAL" if threat_score >= 80 else "HIGH" if threat_score >= 60 else "MEDIUM" if threat_score >= 30 else "LOW"
        
        lines.append(cls.BOX_SINGLE_TOP)
        lines.append(f"{cls.BOX_SINGLE_MID}  {verdict_emoji.get(verdict, '')} VERDICT: {verdict}{' ' * (60 - len(verdict))}{cls.BOX_SINGLE_MID}")
        lines.append(f"{cls.BOX_SINGLE_MID}  Threat Score: {threat_score}/100 ({risk_level}){' ' * (50 - len(str(threat_score)) - len(risk_level))}{cls.BOX_SINGLE_MID}")
        lines.append(f"{cls.BOX_SINGLE_MID}  IOC Type: {ioc_type}{' ' * (60 - len(ioc_type))}{cls.BOX_SINGLE_MID}")
        lines.append(cls.BOX_SINGLE_BOT)
        lines.append("")
        
        # ==================== THREAT INTEL SOURCES ====================
        lines.append(cls.SECTION_SEP)
        lines.append(f" THREAT INTELLIGENCE SOURCES ({result.get('sources_checked', 0)} Checked, {result.get('sources_flagged', 0)} Flagged)")
        lines.append(cls.SECTION_SEP)
        lines.append("")
        
        # Try multiple possible key names for backward compatibility
        sources = (
            result.get('sources', {}) or 
            result.get('threat_intel_results', {}) or 
            result.get('threat_intelligence', {}).get('sources', {})
        )
        
        # Also get sources_checked/flagged with fallback
        sources_checked = (
            result.get('sources_checked', 0) or 
            result.get('threat_intelligence', {}).get('sources_checked', 0)
        )
        sources_flagged = (
            result.get('sources_flagged', 0) or 
            result.get('threat_intelligence', {}).get('sources_flagged', 0)
        )
        
        lines.append("┌─ SOURCE RESULTS")
        lines.append("│")
        lines.append("│  ┌──────────────────┬──────────┬─────────────────────────────────────────┐")
        lines.append("│  │ Source           │ Status   │ Details                                 │")
        lines.append("│  ├──────────────────┼──────────┼─────────────────────────────────────────┤")
        
        if not sources:
            lines.append("│  │ No sources data available                                              │")
        else:
            for source_name, source_data in sources.items():
                if not isinstance(source_data, dict):
                    continue
                    
                status = source_data.get('status', '⚠')
                
                # Determine status emoji based on various indicators
                is_flagged = (
                    status in ['✓', '✓ FLAGGED', 'FLAGGED'] or
                    source_data.get('malicious', False) or
                    source_data.get('flagged', False) or
                    (source_data.get('score', 0) or 0) > 30 or
                    (source_data.get('fraud_score', 0) or 0) > 50 or
                    (source_data.get('confidence', 0) or 0) > 50
                )
                
                is_clean = status == '✗' or source_data.get('clean', False)
                
                if is_flagged:
                    status_str = "🚨 FLAG"
                elif is_clean:
                    status_str = "✅ CLEAN"
                elif source_data.get('error'):
                    status_str = "❌ ERROR"
                else:
                    status_str = "⚪ N/A  "
                
                # Get details - comprehensive extraction
                details = ""
                if source_data.get('detections'):
                    details = f"{source_data.get('detections')} detections"
                elif source_data.get('fraud_score'):
                    details = f"Fraud score: {source_data.get('fraud_score')}%"
                elif source_data.get('confidence'):
                    details = f"Confidence: {source_data.get('confidence')}%"
                elif source_data.get('score') and source_data['score'] > 0:
                    details = f"Score: {source_data.get('score')}/100"
                elif source_data.get('threat'):
                    details = f"Threat: {source_data.get('threat')}"
                elif source_data.get('botnet'):
                    details = f"Botnet: {source_data.get('botnet')}"
                elif source_data.get('classification'):
                    details = f"Class: {source_data.get('classification')}"
                elif source_data.get('ports'):
                    ports = source_data.get('ports', [])
                    if isinstance(ports, list):
                        details = f"Ports: {', '.join(map(str, ports[:5]))}"
                elif source_data.get('vulns'):
                    vulns = source_data.get('vulns', [])
                    if isinstance(vulns, list):
                        details = f"{len(vulns)} vulnerabilities"
                elif source_data.get('reports') is not None:
                    details = f"{source_data.get('reports')} reports"
                elif source_data.get('listed'):
                    details = "Listed in blocklist"
                elif source_data.get('error'):
                    details = f"Error: {source_data.get('error')[:30]}"
                elif source_data.get('message'):
                    details = source_data.get('message')[:35]
                
                details = details[:40] if details else "Checked - No findings"
                
                lines.append(f"│  │ {source_name[:16]:16s} │ {status_str:8s} │ {details:40s}│")
        
        lines.append("│  └──────────────────┴──────────┴─────────────────────────────────────────┘")
        lines.append("│")
        lines.append(f"│  Summary: {sources_flagged}/{sources_checked} sources flagged this IOC")
        lines.append("└" + "─" * 77)
        lines.append("")
        
        # ==================== LLM ANALYSIS ====================
        llm_analysis = result.get('llm_analysis', {})
        if llm_analysis and llm_analysis.get('analysis'):
            lines.append(cls.SECTION_SEP)
            lines.append(" AI-POWERED ANALYSIS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            lines.append(llm_analysis.get('analysis', ''))
            lines.append("")
        
        # ==================== RECOMMENDATIONS ====================
        recommendations = llm_analysis.get('recommendations', [])
        if recommendations:
            lines.append(cls.SECTION_SEP)
            lines.append(" RECOMMENDATIONS")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"  {i}. {rec}")
            lines.append("")
        
        # ==================== DETECTION RULES ====================
        rules = result.get('detection_rules', {})
        if rules:
            lines.append(cls.SECTION_SEP)
            lines.append(" DETECTION RULES")
            lines.append(cls.SECTION_SEP)
            lines.append("")
            
            if rules.get('kql'):
                lines.append("┌─ KQL (Microsoft Defender / Sentinel)")
                for line in rules['kql'].split('\n')[:8]:
                    lines.append(f"│  {line}")
                lines.append("└" + "─" * 77)
                lines.append("")
            
            if rules.get('sigma'):
                lines.append("┌─ SIGMA Rule")
                for line in rules['sigma'].split('\n')[:10]:
                    lines.append(f"│  {line}")
                lines.append("└" + "─" * 77)
                lines.append("")
        
        # ==================== FOOTER ====================
        lines.append(cls.SECTION_SEP)
        lines.append("")
        lines.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("Blue Team Assistant Version: 1.0.0")
        lines.append("")
        
        return '\n'.join(lines)
    
    @classmethod
    def _format_professional_tools_section(cls, result: Dict) -> List[str]:
        """Format professional tools section."""
        lines = []
        
        # Check if we have any professional tool outputs
        capabilities = result.get('capabilities', {})
        obfuscated_strings = result.get('obfuscated_strings', {}) or result.get('strings', {})
        packer_info = result.get('packer_detection', {})
        embedded_files = result.get('embedded_files', {})
        analysis_tools = result.get('analysis_tools', [])
        
        # Skip if no professional tools were used
        has_capa = capabilities.get('success') or capabilities.get('capabilities')
        has_floss = obfuscated_strings.get('decoded_count', 0) > 0 or obfuscated_strings.get('stack_count', 0) > 0
        has_die = packer_info.get('packers') or packer_info.get('protectors') or packer_info.get('compilers')
        has_binwalk = embedded_files.get('embedded_files') or embedded_files.get('high_entropy_regions')
        
        if not (has_capa or has_floss or has_die or has_binwalk):
            return lines
        
        lines.append(cls.SECTION_SEP)
        lines.append(" SECTION 2.5: PROFESSIONAL TOOL ANALYSIS ")
        lines.append(cls.SECTION_SEP)
        lines.append("")
        
        if analysis_tools:
            lines.append(f"┌─ TOOLS USED: {', '.join(analysis_tools)}")
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== CAPA - CAPABILITY DETECTION ====================
        if has_capa:
            cap_list = capabilities.get('capabilities', [])
            lines.append("┌─ CAPA - CAPABILITY DETECTION (Mandiant)")
            lines.append(f"│  Total Capabilities: {len(cap_list)}")
            lines.append(f"│  Threat Score: {capabilities.get('threat_score', 0)}/100")
            lines.append("│")
            
            # Group by namespace
            namespaces = {}
            for cap in cap_list:
                if isinstance(cap, dict):
                    ns = cap.get('namespace', 'unknown').split('/')[0]
                    name = cap.get('name', 'unknown')
                else:
                    ns = 'unknown'
                    name = str(cap)
                if ns not in namespaces:
                    namespaces[ns] = []
                namespaces[ns].append(name)
            
            for ns, caps in sorted(namespaces.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
                lines.append(f"│  [{ns.upper()}] ({len(caps)} capabilities)")
                for cap in caps[:3]:
                    lines.append(f"│    • {cap}")
                if len(caps) > 3:
                    lines.append(f"│    ... and {len(caps)-3} more")
            
            # ATT&CK techniques
            attack_techniques = capabilities.get('attack_techniques', [])
            if attack_techniques:
                lines.append("│")
                lines.append("│  🎯 ATT&CK Techniques:")
                seen = set()
                for t in attack_techniques[:10]:
                    if isinstance(t, dict) and t.get('id') and t['id'] not in seen:
                        lines.append(f"│    [{t['id']}] {t.get('technique', 'Unknown')}")
                        seen.add(t['id'])
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== FLOSS - OBFUSCATED STRINGS ====================
        if has_floss:
            lines.append("┌─ FLOSS - OBFUSCATED STRING ANALYSIS (Mandiant)")
            lines.append(f"│  Static Strings  : {obfuscated_strings.get('static_count', 0)}")
            lines.append(f"│  Decoded Strings : {obfuscated_strings.get('decoded_count', 0)} ⚠️")
            lines.append(f"│  Stack Strings   : {obfuscated_strings.get('stack_count', 0)}")
            lines.append(f"│  Tight Strings   : {obfuscated_strings.get('tight_count', 0)}")
            lines.append(f"│  Threat Score    : {obfuscated_strings.get('threat_score', 0)}/100")
            
            urls = obfuscated_strings.get('urls', [])
            if urls:
                lines.append("│")
                lines.append("│  🔗 URLs from Decoded Strings:")
                for url in urls[:5]:
                    lines.append(f"│    • {url[:70]}")
            
            ips = obfuscated_strings.get('ips', [])
            if ips:
                lines.append("│")
                lines.append(f"│  🌐 IPs: {', '.join(ips[:10])}")
            
            suspicious = obfuscated_strings.get('suspicious_strings', [])
            if suspicious:
                lines.append("│")
                lines.append("│  🚨 Suspicious Decoded Strings:")
                for s in suspicious[:5]:
                    lines.append(f"│    • {s[:65]}...")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== DIE - PACKER DETECTION ====================
        if has_die:
            lines.append("┌─ DIE - PACKER/COMPILER DETECTION")
            lines.append(f"│  File Type: {packer_info.get('file_type', 'Unknown')}")
            
            compilers = packer_info.get('compilers', [])
            if compilers:
                lines.append(f"│  Compiler : {', '.join(compilers[:3])}")
            
            linkers = packer_info.get('linkers', [])
            if linkers:
                lines.append(f"│  Linker   : {', '.join(linkers[:3])}")
            
            packers = packer_info.get('packers', [])
            if packers:
                lines.append("│")
                lines.append(f"│  🚨 PACKER: {', '.join(packers)}")
            
            protectors = packer_info.get('protectors', [])
            if protectors:
                lines.append("│")
                lines.append(f"│  🚨 PROTECTOR: {', '.join(protectors)}")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        # ==================== BINWALK - EMBEDDED FILES ====================
        if has_binwalk:
            lines.append("┌─ BINWALK - EMBEDDED FILE ANALYSIS")
            
            embedded = embedded_files.get('embedded_files', [])
            if embedded:
                lines.append(f"│  Embedded Items: {len(embedded)}")
                for item in embedded[:5]:
                    offset = item.get('offset', 0)
                    desc = item.get('description', 'Unknown')[:60]
                    lines.append(f"│  @ 0x{offset:08X}: {desc}")
            
            high_entropy = embedded_files.get('high_entropy_regions', [])
            if high_entropy:
                lines.append("│")
                lines.append("│  🚨 High Entropy Regions:")
                for region in high_entropy[:3]:
                    offset = region.get('offset', 0)
                    entropy = region.get('entropy', 0)
                    lines.append(f"│    @ 0x{offset:08X}: {entropy:.3f}")
            
            lines.append("└" + "─" * 77)
            lines.append("")
        
        return lines
