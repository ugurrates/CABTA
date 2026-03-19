"""
Author: Ugur AtesDetection rule generator for multiple SIEM/EDR platforms."""

from typing import Dict, List
import logging

logger = logging.getLogger(__name__)
class RuleGenerator:
    """
    Generate detection rules for multiple platforms.
    
    Supports:
    - KQL (Microsoft Defender/Sentinel)
    - SPL (Splunk)
    - SIGMA (Universal)
    - XQL (Cortex XDR)
    - YARA (File signatures)
    """
    
    @staticmethod
    def generate_ioc_rules(ioc: str, ioc_type: str, context: Dict = None) -> Dict[str, str]:
        """
        Generate detection rules for IOC.
        
        Args:
            ioc: Indicator of Compromise
            ioc_type: Type (ipv4, domain, url, hash)
            context: Additional context (malware family, etc.)
        
        Returns:
            Dict with rules for each platform
        """
        rules = {
            'kql': RuleGenerator._generate_kql_ioc(ioc, ioc_type, context),
            'spl': RuleGenerator._generate_spl_ioc(ioc, ioc_type, context),
            'sigma': RuleGenerator._generate_sigma_ioc(ioc, ioc_type, context),
            'xql': RuleGenerator._generate_xql_ioc(ioc, ioc_type, context)
        }
        
        return rules
    
    @staticmethod
    def generate_file_rules(file_data: Dict) -> Dict[str, str]:
        """
        Generate detection rules for malicious file.
        
        Args:
            file_data: File analysis results
        
        Returns:
            Dict with rules for each platform
        """
        rules = {
            'kql': RuleGenerator._generate_kql_file(file_data),
            'spl': RuleGenerator._generate_spl_file(file_data),
            'yara': RuleGenerator._generate_yara_file(file_data),
            'sigma': RuleGenerator._generate_sigma_file(file_data)
        }
        
        return rules
    
    @staticmethod
    def _generate_kql_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate KQL rule for IOC."""
        if ioc_type == 'ipv4':
            return f"""// KQL - Hunt for IP: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "{ioc}" or InitiatingProcessFileName == "{ioc}"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| summarize count() by DeviceName, RemoteIP"""
        
        elif ioc_type == 'domain':
            return f"""// KQL - Hunt for Domain: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "{ioc}"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName
| summarize count() by DeviceName, RemoteUrl"""
        
        elif ioc_type == 'hash':
            return f"""// KQL - Hunt for Hash: {ioc}
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "{ioc}" or SHA1 == "{ioc}" or MD5 == "{ioc}"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| summarize count() by DeviceName, FileName"""
        
        elif ioc_type == 'url':
            return f"""// KQL - Hunt for URL: {ioc}
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl == "{ioc}"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName"""
        
        return "// KQL - IOC type not supported"
    
    @staticmethod
    def _generate_spl_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate SPL rule for IOC."""
        if ioc_type == 'ipv4':
            return f"""# SPL - Hunt for IP: {ioc}
index=* earliest=-30d
| search dest_ip="{ioc}" OR src_ip="{ioc}"
| stats count by host, dest_ip, src_ip, dest_port"""
        
        elif ioc_type == 'domain':
            return f"""# SPL - Hunt for Domain: {ioc}
index=* earliest=-30d
| search url="*{ioc}*" OR domain="*{ioc}*"
| stats count by host, url, domain"""
        
        elif ioc_type == 'hash':
            return f"""# SPL - Hunt for Hash: {ioc}
index=* earliest=-30d
| search hash="{ioc}" OR sha256="{ioc}" OR md5="{ioc}"
| stats count by host, file_name, file_path, hash"""
        
        return "# SPL - IOC type not supported"
    
    @staticmethod
    def _generate_sigma_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate complete SIGMA rule for IOC."""
        from datetime import datetime
        
        malware_family = context.get('malware_family', 'Unknown') if context else 'Unknown'
        verdict = context.get('verdict', 'Unknown') if context else 'Unknown'
        
        # Determine level based on verdict
        level = 'critical' if verdict == 'MALICIOUS' else 'high' if verdict == 'SUSPICIOUS' else 'medium'
        
        rule = f"""title: Detection of {malware_family} IOC - {ioc}
id: mcp-soc-{ioc_type}-{hash(ioc) % 10000:04d}
status: experimental
description: Detects network activity related to {verdict} IOC
author: Ugur Ates
date: {datetime.now().strftime('%Y/%m/%d')}
references:
    - https://github.com/ugur-ates/blue-team-assistant
tags:
    - attack.command_and_control
    - attack.t1071"""
        
        if ioc_type == 'ipv4':
            rule += f"""
logsource:
    category: firewall
detection:
    selection_dst:
        dst_ip: '{ioc}'
    selection_src:
        src_ip: '{ioc}'
    condition: selection_dst or selection_src
fields:
    - src_ip
    - dst_ip
    - dst_port
    - action"""
        
        elif ioc_type == 'domain':
            rule += f"""
logsource:
    category: dns
detection:
    selection:
        query|contains: '{ioc}'
    condition: selection
fields:
    - query
    - answer
    - src_ip"""
        
        elif ioc_type == 'url':
            rule += f"""
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '{ioc}'
    condition: selection
fields:
    - c-uri
    - cs-host
    - src_ip"""
        
        elif ioc_type in ['sha256', 'md5', 'sha1', 'hash']:
            rule += f"""
logsource:
    category: file_event
    product: windows
detection:
    selection:
        Hashes|contains: '{ioc}'
    condition: selection
fields:
    - TargetFilename
    - Hashes
    - User"""
        
        else:
            # Generic fallback
            rule += f"""
logsource:
    category: network_connection
detection:
    selection:
        - dst_ip: '{ioc}'
        - query: '{ioc}'
        - url|contains: '{ioc}'
    condition: selection"""
        
        rule += f"""
falsepositives:
    - Legitimate traffic to this destination
level: {level}
"""
        
        return rule
    
    @staticmethod
    def _generate_xql_ioc(ioc: str, ioc_type: str, context: Dict) -> str:
        """Generate XQL rule for IOC."""
        if ioc_type == 'ipv4':
            return f"""// XQL - Hunt for IP: {ioc}
dataset = xdr_data
| filter event_type = NETWORK_CONNECTION and remote_ip = "{ioc}"
| fields agent_hostname, remote_ip, remote_port, process_name
| limit 100"""
        
        elif ioc_type == 'domain':
            return f"""// XQL - Hunt for Domain: {ioc}
dataset = xdr_data
| filter event_type = DNS_QUERY and dns_query_name contains "{ioc}"
| fields agent_hostname, dns_query_name, process_name
| limit 100"""
        
        return "// XQL - IOC type not supported"
    
    @staticmethod
    def _generate_kql_file(file_data: Dict) -> str:
        """Generate KQL rule for file."""
        sha256 = file_data.get('sha256', '')
        filename = file_data.get('filename', '')
        
        return f"""// KQL - Hunt for Malicious File
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "{sha256}" or FileName == "{filename}"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
| summarize count() by DeviceName, FileName, FolderPath"""
    
    @staticmethod
    def _generate_spl_file(file_data: Dict) -> str:
        """Generate SPL rule for file."""
        sha256 = file_data.get('sha256', '')
        filename = file_data.get('filename', '')
        
        return f"""# SPL - Hunt for Malicious File
index=* earliest=-30d
| search (sha256="{sha256}" OR file_name="{filename}")
| stats count by host, file_name, file_path, sha256"""
    
    @staticmethod
    def _generate_yara_file(file_data: Dict) -> str:
        """Generate comprehensive YARA rule for file."""
        from datetime import datetime
        
        filename = file_data.get('filename', 'unknown')
        sha256 = file_data.get('sha256', '')
        md5 = file_data.get('md5', '')
        malware_family = file_data.get('malware_family', 'Unknown')
        
        # Clean filename for rule name
        rule_name = filename.replace('.', '_').replace('-', '_').replace(' ', '_')
        
        # Extract suspicious strings from analysis
        indicators = file_data.get('suspicious_indicators', [])
        iocs = file_data.get('iocs', [])
        
        rule = f"""rule BTA_{rule_name} {{
    meta:
        description = "Auto-generated rule for {filename}"
        author = "Blue Team Assistant"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        hash_sha256 = "{sha256}"
        hash_md5 = "{md5}"
        malware_family = "{malware_family}"
        severity = "high"
        reference = "https://github.com/ugur-ates/blue-team-assistant"
    
    strings:
        // File hashes
        $hash_sha256 = "{sha256}" ascii wide nocase
        $hash_md5 = "{md5}" ascii wide nocase
"""
        
        # Add suspicious strings
        for i, indicator in enumerate(indicators[:10]):
            # Escape special characters
            escaped = str(indicator).replace('\\', '\\\\').replace('"', '\\"')[:50]
            rule += f'        $sus_{i} = "{escaped}" ascii wide nocase\n'
        
        # Add IOCs
        for i, ioc in enumerate(iocs[:5]):
            escaped = str(ioc).replace('\\', '\\\\').replace('"', '\\"')[:50]
            rule += f'        $ioc_{i} = "{escaped}" ascii wide nocase\n'
        
        # Add common malicious patterns
        rule += """
        // Common malicious patterns
        $ps_encoded = /powershell.*-e(nc(odedcommand)?)?/i
        $ps_bypass = /powershell.*-ex(ec(utionpolicy)?)?.*bypass/i
        $ps_hidden = /powershell.*-w(indowstyle)?.*hidden/i
        $ps_download = /(downloadstring|downloadfile|invoke-webrequest)/i
        $vba_shell = /Shell\\s*\\(|WScript\\.Shell/i
        $vba_exec = /\\.Run\\s*\\(|\\.Exec\\s*\\(/i
    
    condition:
        (
            $hash_sha256 or $hash_md5
        ) or (
            2 of ($sus_*) and 1 of ($ioc_*)
        ) or (
            3 of ($ps_*)
        ) or (
            $vba_shell and $vba_exec
        )
}}
"""
        
        return rule
    
    @staticmethod
    def _generate_sigma_file(file_data: Dict) -> str:
        """Generate SIGMA rule for file detection."""
        from datetime import datetime
        
        filename = file_data.get('filename', 'unknown')
        sha256 = file_data.get('sha256', '')
        md5 = file_data.get('md5', '')
        malware_family = file_data.get('malware_family', 'Unknown')
        indicators = file_data.get('suspicious_indicators', [])
        
        rule = f"""title: Detection of {malware_family} - {filename}
id: mcp-soc-file-{hash(sha256) % 10000:04d}
status: experimental
description: Detects execution or presence of potentially malicious file
author: Ugur Ates
date: {datetime.now().strftime('%Y/%m/%d')}
references:
    - https://github.com/ugur-ates/blue-team-assistant
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059
    - attack.t1027

logsource:
    category: process_creation
    product: windows

detection:
    selection_hash:
        - Hashes|contains: '{sha256}'
        - Hashes|contains: '{md5}'
    selection_filename:
        - Image|endswith: '\\\\{filename}'
        - OriginalFileName: '{filename}'"""
        
        if indicators:
            rule += """
    selection_commandline:
        CommandLine|contains:"""
            for ind in indicators[:5]:
                escaped = str(ind)[:50].replace("'", "''")
                rule += f"\n            - '{escaped}'"
        
        rule += """
    
    condition: selection_hash or selection_filename"""
        
        if indicators:
            rule += " or selection_commandline"
        
        rule += f"""

falsepositives:
    - Legitimate administrative tools
    - Software updates

level: high
"""
        
        return rule
    
    @staticmethod
    def generate_email_rules(email_data: Dict) -> Dict[str, str]:
        """
        Generate comprehensive detection rules for phishing email.
        
        Args:
            email_data: Email analysis results
        
        Returns:
            Dict with rules for each platform (KQL, SPL, SIGMA, YARA)
        """
        from datetime import datetime
        
        sender = email_data.get('from', '')
        sender_domain = email_data.get('sender_domain', '')
        if not sender_domain and '@' in sender:
            sender_domain = sender.split('@')[-1].split('>')[0]
        subject = email_data.get('subject', '')[:50]
        urls = email_data.get('urls', [])
        malicious_iocs = email_data.get('malicious_iocs', [])
        
        # KQL Rule
        kql = f"""// KQL - Hunt for Phishing Campaign
// Sender-based detection
EmailEvents
| where Timestamp > ago(30d)
| where SenderFromAddress == "{sender}" 
    or SenderFromDomain == "{sender_domain}"
    or Subject contains "{subject}"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, NetworkMessageId
| summarize 
    Recipients = make_set(RecipientEmailAddress),
    Count = count() 
    by SenderFromAddress, Subject

// URL-based detection
let malicious_urls = dynamic([{', '.join([f'"{u[:50]}"' for u in urls[:5]])}]);
EmailUrlInfo
| where Timestamp > ago(30d)
| where Url has_any (malicious_urls)
| join kind=inner EmailEvents on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Url
"""

        # SIGMA Rule
        sigma = f"""title: Phishing Email Detection - {sender_domain}
id: mcp-soc-email-{hash(sender) % 10000:04d}
status: experimental
description: Detects emails from known phishing sender or containing malicious indicators
author: Ugur Ates
date: {datetime.now().strftime('%Y/%m/%d')}
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.t1566.002
logsource:
    category: email
    product: exchange
    service: messagetrace
detection:
    selection_sender:
        sender|endswith: '@{sender_domain}'
    selection_subject:
        subject|contains: '{subject[:30]}'"""

        if urls:
            sigma += """
    selection_url:
        url|contains:"""
            for u in urls[:3]:
                sigma += f"\n            - '{u[:50]}'"
        
        sigma += """
    condition: selection_sender or selection_subject"""
        if urls:
            sigma += " or selection_url"
        
        sigma += """
falsepositives:
    - Legitimate emails from similar domains
level: high
"""

        # SPL Rule
        spl = f"""# SPL - Hunt for Phishing Email
index=email earliest=-30d
| search sender="{sender}" OR sender_domain="{sender_domain}" OR subject="*{subject[:30]}*"
| stats count by recipient, sender, subject, src_ip
| where count > 1

# URL-based hunt
index=email earliest=-30d
| search url IN ("{('", "'.join(urls[:5]))}")
| stats count by recipient, sender, url
"""

        # YARA for attachments (if any IOCs)
        yara = ""
        if malicious_iocs:
            yara = f"""rule Phishing_Email_IOCs {{
    meta:
        description = "IOCs from phishing email analysis"
        author = "Blue Team Assistant"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        sender = "{sender}"
    strings:"""
            for i, ioc in enumerate(malicious_iocs[:10]):
                escaped = str(ioc).replace('\\', '\\\\').replace('"', '\\"')[:50]
                yara += f'\n        $ioc{i} = "{escaped}" ascii wide nocase'
            yara += """
    condition:
        any of them
}"""

        # ==================== EMAIL GATEWAY RULES ====================
        
        # FortiMail Content Filter
        fortimail = f"""# FortiMail Content Filter Rule
# Auto-generated by Blue Team Assistant - Block phishing campaign

config antispam profile
    edit "BTA-Block-{sender_domain[:20] if sender_domain else 'unknown'}"
        config spam-filtering
            set heuristic enable
        end
        config banned-word
            set status enable
            set entries "{subject[:30]}"
        end
    next
end

# Sender Domain Block
config domain
    edit "{sender_domain}"
        set spam on
        set virus on
        set banned-word on
    next
end

# URL Block Rule (if malicious URLs found)
"""
        if urls:
            fortimail += """config webfilter content
    edit "BTA-Blocked-URLs"
        config entries"""
            for url in urls[:10]:
                url_escaped = url[:60].replace('"', '\\"')
                fortimail += f'\n            edit "{url_escaped}"\n            next'
            fortimail += """
        end
    next
end
"""
        
        # Proofpoint Email Protection Rule
        proofpoint = f"""# Proofpoint Email Protection Rule
# Auto-generated by Blue Team Assistant

# Sender Block Rule (JSON format for API)
{{
    "rule_name": "BTA-Block-{sender_domain[:20] if sender_domain else 'unknown'}",
    "description": "Block phishing campaign from {sender_domain}",
    "enabled": true,
    "conditions": {{
        "from_header": {{
            "contains": ["{sender_domain}"]
        }},
        "subject": {{
            "contains": ["{subject[:30].replace('"', "'")}"]
        }}
    }},
    "actions": {{
        "quarantine": true,
        "add_header": "X-BTA-Blocked: phishing",
        "notify_admin": true,
        "log_action": true
    }}
}}

# URL Rewrite/Block Rule
{{
    "rule_name": "BTA-URL-Block-{hash(sender) % 1000:03d}",
    "description": "Block malicious URLs from phishing campaign",
    "enabled": true,
    "conditions": {{
        "url_in_body": {{
            "matches": [
"""
        for url in urls[:5]:
            url_escaped = url[:70].replace('"', '\\"')
            proofpoint += f'                "{url_escaped}",\n'
        proofpoint += """            ]
        }
    },
    "actions": {
        "rewrite_urls": true,
        "block_url_click": true,
        "quarantine": true,
        "sandbox_attachment": true
    }
}
"""
        
        # Mimecast Policy
        mimecast = f"""# Mimecast Content Examination Policy
# Auto-generated by Blue Team Assistant

Policy Name: BTA-Block-{sender_domain[:15] if sender_domain else 'unknown'}
Policy Type: Content Examination
Status: Enabled
Priority: High

Conditions:
- Header From Contains: {sender_domain}
- Subject Contains: {subject[:30]}
- Attachment Name Pattern: *.exe, *.js, *.vbs, *.ps1, *.hta

Actions:
- Hold Message for Review
- Admin Notification: Enabled
- Add X-Header: X-BTA-Flagged: true
- Send to Sandbox: Enabled

# Blocked Sender Entry
Type: Blocked Sender
Address: *@{sender_domain}
Reason: Phishing campaign detected by Blue Team Assistant
Duration: Permanent

# URL Protection Policy
URL Categories to Block:
"""
        for url in urls[:5]:
            mimecast += f"- {url[:50]}\n"
        
        # Microsoft 365 Defender / Exchange Online Protection
        microsoft365 = f"""# Microsoft 365 Defender / Exchange Online Protection
# PowerShell commands - Run in Exchange Online PowerShell

# 1. Create Transport Rule to block sender domain
New-TransportRule -Name "BTA-Block-{sender_domain[:20] if sender_domain else 'unknown'}" `
    -FromAddressMatchesPatterns "*@{sender_domain}" `
    -SubjectContainsWords "{subject[:30].replace('"', "'")}" `
    -DeleteMessage $true `
    -SetAuditSeverity "High" `
    -Comments "Auto-generated by Blue Team Assistant - Phishing campaign block"

# 2. Add sender to blocked senders list
Set-HostedContentFilterPolicy -Identity Default `
    -BlockedSenders @{{Add="{sender}"}} `
    -BlockedSenderDomains @{{Add="{sender_domain}"}}

# 3. Create anti-phishing policy
New-AntiPhishPolicy -Name "BTA-AntiPhish-{hash(sender) % 1000:03d}" `
    -Enabled $true `
    -EnableOrganizationDomainsProtection $true `
    -EnableMailboxIntelligence $true `
    -EnableMailboxIntelligenceProtection $true `
    -MailboxIntelligenceProtectionAction Quarantine

# 4. Create Safe Links block for malicious URLs
# Note: Requires Microsoft Defender for Office 365 P1/P2
$urls_to_block = @(
"""
        for url in urls[:10]:
            url_escaped = url[:70].replace('"', '`"')
            microsoft365 += f'    "{url_escaped}",\n'
        microsoft365 += """)
# Add to blocked URLs in Defender portal or via API

# 5. Create mail flow rule for URL blocking
New-TransportRule -Name "BTA-Block-URLs" `
    -HeaderContainsMessageHeader "Content-Type" `
    -HeaderContainsWords "text/html" `
    -SubjectOrBodyContainsWords $urls_to_block `
    -Quarantine $true

# 6. Alert rule for SOC
New-ProtectionAlert -Name "BTA-Phishing-Alert" `
    -Category ThreatManagement `
    -NotifyUser "soc@yourdomain.com" `
    -Operation "ThreatIntelligenceUrl"
"""

        return {
            'kql': kql,
            'sigma': sigma,
            'spl': spl,
            'yara': yara,
            'fortimail': fortimail,
            'proofpoint': proofpoint,
            'mimecast': mimecast,
            'microsoft365': microsoft365
        }
