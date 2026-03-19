"""
Author: Ugur AtesExecutive Summary Generator for Blue Team Assistant Reports."""

from typing import Dict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
class ExecutiveSummary:
    """Generate executive summaries for SOC reports."""
    
    @staticmethod
    def generate_file_summary(result: Dict) -> str:
        """
        Generate executive summary for file analysis.
        
        Args:
            result: File analysis result dict
        
        Returns:
            Formatted executive summary string
        """
        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('composite_score', 0)
        file_info = result.get('file_info', {})
        filename = file_info.get('name', 'Unknown')
        sha256 = result.get('hashes', {}).get('sha256', 'N/A')
        sha256_short = sha256[:16] + '...' if len(sha256) > 16 else sha256
        
        # Determine risk level and actions
        if score >= 70:
            risk_level = "🔴 CRITICAL"
            action = "IMMEDIATE ACTION REQUIRED"
            recommendation = "Block immediately, isolate affected systems, initiate incident response"
        elif score >= 50:
            risk_level = "🟠 HIGH"
            action = "URGENT REVIEW NEEDED"
            recommendation = "Quarantine file, investigate execution history, monitor for related activity"
        elif score >= 30:
            risk_level = "🟡 MEDIUM"
            action = "FURTHER ANALYSIS RECOMMENDED"
            recommendation = "Review in sandbox environment, check for false positive indicators"
        else:
            risk_level = "🟢 LOW"
            action = "ROUTINE MONITORING"
            recommendation = "Continue monitoring, no immediate action required"
        
        # Build key findings
        findings = []
        
        # Check YARA
        yara = result.get('yara_analysis', {})
        if yara.get('matches'):
            families = yara.get('interpretation', {}).get('malware_families', [])
            if families:
                findings.append(f"Malware family identified: {', '.join(families[:2])}")
            else:
                findings.append(f"YARA matches: {len(yara.get('matches', []))} rules triggered")
        
        # Check sandbox
        sandbox = result.get('sandbox_analysis', {})
        if sandbox:
            summary = sandbox.get('summary', {})
            if summary.get('behaviors'):
                findings.append(f"Suspicious behaviors: {', '.join(summary['behaviors'][:3])}")
        
        # Check IOCs
        iocs = result.get('ioc_analysis', {})
        if iocs.get('malicious_iocs', 0) > 0:
            findings.append(f"Malicious IOCs found: {iocs['malicious_iocs']} embedded indicators")
        
        # Check static analysis
        static = result.get('static_analysis', {})
        if static.get('signature', {}).get('signed') == False:
            findings.append("File is UNSIGNED - increased risk")
        
        # Check string categories
        string_analysis = result.get('string_analysis', {})
        categories = string_analysis.get('suspicious_categories', {})
        if categories:
            findings.append(f"Suspicious string categories: {', '.join(list(categories.keys())[:3])}")
        
        # Check threat intel
        threat_intel = result.get('threat_intel', {})
        if threat_intel.get('sources_flagged', 0) > 0:
            findings.append(f"Threat intel: {threat_intel['sources_flagged']}/{threat_intel.get('sources_checked', 0)} sources flagged")
        
        if not findings:
            findings.append("No critical indicators detected")
        
        findings_str = '\n'.join([f"│  • {f}" for f in findings[:5]])
        
        summary = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  EXECUTIVE SUMMARY - FILE ANALYSIS                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─ RISK ASSESSMENT
│
│  Risk Level    : {risk_level}
│  Threat Score  : {score}/100
│  Verdict       : {verdict}
│  Action        : {action}
│
└─────────────────────────────────────────────────────────────────────────────

┌─ QUICK FACTS
│
│  File          : {filename}
│  Size          : {file_info.get('size_human', 'Unknown')}
│  Type          : {file_info.get('type', 'Unknown')}
│  SHA256        : {sha256_short}
│  Detection     : {threat_intel.get('sources_flagged', 0)}/{threat_intel.get('sources_checked', 0)} sources flagged
│  YARA Matches  : {len(yara.get('matches', []))} rules
│
└─────────────────────────────────────────────────────────────────────────────

┌─ KEY FINDINGS
│
{findings_str}
│
└─────────────────────────────────────────────────────────────────────────────

┌─ RECOMMENDATION
│
│  {recommendation}
│
└─────────────────────────────────────────────────────────────────────────────
"""
        logger.info(f"[SUMMARY] Generated file summary: {verdict} ({score}/100)")
        return summary
    
    @staticmethod
    def generate_email_summary(result: Dict) -> str:
        """
        Generate executive summary for email analysis.
        
        Args:
            result: Email analysis result dict
        
        Returns:
            Formatted executive summary string
        """
        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('composite_score', 0)
        email_data = result.get('email_data', {})
        sender = email_data.get('from', 'Unknown')
        subject = email_data.get('subject', 'N/A')
        if len(subject) > 50:
            subject = subject[:47] + '...'
        
        # Determine risk level
        if verdict == 'PHISHING' or score >= 70:
            risk_level = "🔴 CRITICAL - PHISHING"
            action = "IMMEDIATE BLOCK & PURGE"
            recommendation = "Block sender, delete from all mailboxes, notify affected users"
        elif verdict == 'SPAM' or score >= 50:
            risk_level = "🟠 HIGH - LIKELY MALICIOUS"
            action = "BLOCK & INVESTIGATE"
            recommendation = "Quarantine emails, investigate sender reputation, check for user interaction"
        elif score >= 30:
            risk_level = "🟡 MEDIUM - SUSPICIOUS"
            action = "REVIEW REQUIRED"
            recommendation = "Review email content, verify sender legitimacy, monitor for similar messages"
        else:
            risk_level = "🟢 LOW - LIKELY LEGITIMATE"
            action = "ROUTINE MONITORING"
            recommendation = "No immediate action required"
        
        # Auth results
        spf = email_data.get('spf', 'unknown').upper()
        dkim = email_data.get('dkim', 'unknown').upper()
        dmarc = email_data.get('dmarc', 'unknown').upper()
        
        spf_icon = "✅" if spf == "PASS" else "❌" if spf == "FAIL" else "⚠️"
        dkim_icon = "✅" if dkim == "PASS" else "❌" if dkim == "FAIL" else "⚠️"
        dmarc_icon = "✅" if dmarc == "PASS" else "❌" if dmarc == "FAIL" else "⚠️"
        
        # Build key findings
        findings = []
        
        # Authentication failures
        auth_failures = []
        if spf == 'FAIL':
            auth_failures.append('SPF')
        if dkim == 'FAIL':
            auth_failures.append('DKIM')
        if dmarc == 'FAIL':
            auth_failures.append('DMARC')
        if auth_failures:
            findings.append(f"Authentication failures: {', '.join(auth_failures)}")
        
        # Advanced analysis
        advanced = result.get('advanced_analysis', {})
        if advanced.get('brand_impersonation'):
            findings.append(f"Brand impersonation detected: {advanced['brand_impersonation'].get('brand', 'Unknown')}")
        if advanced.get('lookalike_domains'):
            domains = advanced['lookalike_domains'][:2]
            findings.append(f"Lookalike domains: {', '.join([d.get('domain', '') for d in domains])}")
        if advanced.get('link_mismatches'):
            findings.append(f"Link-text mismatches: {len(advanced['link_mismatches'])} found")
        
        # Forensics
        forensics = result.get('forensics', {})
        if forensics.get('forensics_score', 0) >= 50:
            findings.append(f"Forensics risk score: {forensics['forensics_score']}/100")
        
        # IOCs
        iocs = result.get('ioc_analysis', {})
        if iocs.get('malicious_iocs', 0) > 0:
            findings.append(f"Malicious IOCs: {iocs['malicious_iocs']} indicators flagged")
        
        # Attachments
        attachments = result.get('attachment_analysis', {})
        if attachments.get('malicious_attachments', 0) > 0:
            findings.append(f"Malicious attachments: {attachments['malicious_attachments']} detected")
        
        if not findings:
            findings.append("No critical indicators detected")
        
        findings_str = '\n'.join([f"│  • {f}" for f in findings[:5]])
        
        summary = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  EXECUTIVE SUMMARY - EMAIL ANALYSIS                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─ RISK ASSESSMENT
│
│  Risk Level    : {risk_level}
│  Threat Score  : {score}/100
│  Verdict       : {verdict}
│  Action        : {action}
│
└─────────────────────────────────────────────────────────────────────────────

┌─ EMAIL DETAILS
│
│  From          : {sender}
│  Subject       : {subject}
│  URLs Found    : {len(email_data.get('urls', []))}
│  Attachments   : {len(email_data.get('attachments', []))}
│
└─────────────────────────────────────────────────────────────────────────────

┌─ AUTHENTICATION STATUS
│
│  SPF           : {spf_icon} {spf}
│  DKIM          : {dkim_icon} {dkim}
│  DMARC         : {dmarc_icon} {dmarc}
│
└─────────────────────────────────────────────────────────────────────────────

┌─ KEY FINDINGS
│
{findings_str}
│
└─────────────────────────────────────────────────────────────────────────────

┌─ RECOMMENDATION
│
│  {recommendation}
│
└─────────────────────────────────────────────────────────────────────────────
"""
        logger.info(f"[SUMMARY] Generated email summary: {verdict} ({score}/100)")
        return summary
    
    @staticmethod
    def generate_ioc_summary(result: Dict, ioc: str) -> str:
        """
        Generate executive summary for IOC analysis.
        
        Args:
            result: IOC analysis result dict
            ioc: The IOC value
        
        Returns:
            Formatted executive summary string
        """
        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('threat_score', 0)
        ioc_type = result.get('ioc_type', 'unknown')
        sources_checked = result.get('sources_checked', 0)
        sources_flagged = result.get('sources_flagged', 0)
        
        # Determine risk level
        if verdict == 'MALICIOUS' or score >= 70:
            risk_level = "🔴 CRITICAL - MALICIOUS"
            action = "IMMEDIATE BLOCK"
            recommendation = "Block at firewall/proxy, hunt for connections, isolate affected systems"
        elif verdict == 'SUSPICIOUS' or score >= 40:
            risk_level = "🟠 HIGH - SUSPICIOUS"
            action = "MONITOR & INVESTIGATE"
            recommendation = "Add to watchlist, review connection logs, correlate with other activity"
        elif score >= 20:
            risk_level = "🟡 MEDIUM - LOW RISK"
            action = "PASSIVE MONITORING"
            recommendation = "Document finding, continue monitoring, no immediate action required"
        else:
            risk_level = "🟢 LOW - CLEAN"
            action = "NO ACTION NEEDED"
            recommendation = "No threats detected, safe to proceed"
        
        summary = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  EXECUTIVE SUMMARY - IOC INVESTIGATION                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─ RISK ASSESSMENT
│
│  Risk Level    : {risk_level}
│  Threat Score  : {score}/100
│  Verdict       : {verdict}
│  Action        : {action}
│
└─────────────────────────────────────────────────────────────────────────────

┌─ IOC DETAILS
│
│  IOC           : {ioc}
│  Type          : {ioc_type.upper()}
│  Sources       : {sources_flagged}/{sources_checked} flagged
│
└─────────────────────────────────────────────────────────────────────────────

┌─ RECOMMENDATION
│
│  {recommendation}
│
└─────────────────────────────────────────────────────────────────────────────
"""
        logger.info(f"[SUMMARY] Generated IOC summary: {verdict} ({score}/100)")
        return summary
