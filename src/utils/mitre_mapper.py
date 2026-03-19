"""
Author: Ugur AtesMITRE ATT&CK Framework Mapper for Blue Team Assistant."""

from typing import Dict, List
import re
import logging

logger = logging.getLogger(__name__)
# Comprehensive MITRE ATT&CK Mapping
MITRE_MAPPING = {
    # ==================== Execution (TA0002) ====================
    'powershell': {'technique': 'T1059.001', 'tactic': 'Execution', 'name': 'PowerShell'},
    'cmd.exe': {'technique': 'T1059.003', 'tactic': 'Execution', 'name': 'Windows Command Shell'},
    'wscript': {'technique': 'T1059.005', 'tactic': 'Execution', 'name': 'Visual Basic'},
    'cscript': {'technique': 'T1059.005', 'tactic': 'Execution', 'name': 'Visual Basic'},
    'mshta': {'technique': 'T1218.005', 'tactic': 'Defense Evasion', 'name': 'Mshta'},
    'rundll32': {'technique': 'T1218.011', 'tactic': 'Defense Evasion', 'name': 'Rundll32'},
    'regsvr32': {'technique': 'T1218.010', 'tactic': 'Defense Evasion', 'name': 'Regsvr32'},
    'wmic': {'technique': 'T1047', 'tactic': 'Execution', 'name': 'Windows Management Instrumentation'},
    'invoke-expression': {'technique': 'T1059.001', 'tactic': 'Execution', 'name': 'PowerShell'},
    'iex': {'technique': 'T1059.001', 'tactic': 'Execution', 'name': 'PowerShell'},
    
    # ==================== Persistence (TA0003) ====================
    'schtasks': {'technique': 'T1053.005', 'tactic': 'Persistence', 'name': 'Scheduled Task'},
    'scheduled task': {'technique': 'T1053.005', 'tactic': 'Persistence', 'name': 'Scheduled Task'},
    'new-scheduledtask': {'technique': 'T1053.005', 'tactic': 'Persistence', 'name': 'Scheduled Task'},
    'currentversion\\run': {'technique': 'T1547.001', 'tactic': 'Persistence', 'name': 'Registry Run Keys'},
    'currentversion\\runonce': {'technique': 'T1547.001', 'tactic': 'Persistence', 'name': 'Registry Run Keys'},
    'startup folder': {'technique': 'T1547.001', 'tactic': 'Persistence', 'name': 'Registry Run Keys'},
    'new-service': {'technique': 'T1543.003', 'tactic': 'Persistence', 'name': 'Windows Service'},
    'sc create': {'technique': 'T1543.003', 'tactic': 'Persistence', 'name': 'Windows Service'},
    'userinit': {'technique': 'T1547.004', 'tactic': 'Persistence', 'name': 'Winlogon Helper DLL'},
    'winlogon': {'technique': 'T1547.004', 'tactic': 'Persistence', 'name': 'Winlogon Helper DLL'},
    
    # ==================== Defense Evasion (TA0005) ====================
    'encodedcommand': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files'},
    '-enc': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files'},
    '-e ': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files'},
    'base64': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files'},
    'set-mppreference': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'disablerealtimemonitoring': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'disablebehaviormonitoring': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'disableioavprotection': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'add-mppreference': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'exclusionpath': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'amsi': {'technique': 'T1562.001', 'tactic': 'Defense Evasion', 'name': 'Disable or Modify Tools'},
    'virtualalloc': {'technique': 'T1055', 'tactic': 'Defense Evasion', 'name': 'Process Injection'},
    'virtualprotect': {'technique': 'T1055', 'tactic': 'Defense Evasion', 'name': 'Process Injection'},
    'createremotethread': {'technique': 'T1055', 'tactic': 'Defense Evasion', 'name': 'Process Injection'},
    'writeprocessmemory': {'technique': 'T1055', 'tactic': 'Defense Evasion', 'name': 'Process Injection'},
    'ntcreatethreadex': {'technique': 'T1055', 'tactic': 'Defense Evasion', 'name': 'Process Injection'},
    
    # ==================== Credential Access (TA0006) ====================
    'mimikatz': {'technique': 'T1003.001', 'tactic': 'Credential Access', 'name': 'LSASS Memory'},
    'sekurlsa': {'technique': 'T1003.001', 'tactic': 'Credential Access', 'name': 'LSASS Memory'},
    'lsass': {'technique': 'T1003.001', 'tactic': 'Credential Access', 'name': 'LSASS Memory'},
    'procdump': {'technique': 'T1003.001', 'tactic': 'Credential Access', 'name': 'LSASS Memory'},
    'minidump': {'technique': 'T1003.001', 'tactic': 'Credential Access', 'name': 'LSASS Memory'},
    'get-credential': {'technique': 'T1056.002', 'tactic': 'Credential Access', 'name': 'GUI Input Capture'},
    'kerberos::': {'technique': 'T1558', 'tactic': 'Credential Access', 'name': 'Steal or Forge Kerberos'},
    'dpapi': {'technique': 'T1555.004', 'tactic': 'Credential Access', 'name': 'Windows Credential Manager'},
    
    # ==================== Discovery (TA0007) ====================
    'whoami': {'technique': 'T1033', 'tactic': 'Discovery', 'name': 'System Owner Discovery'},
    'systeminfo': {'technique': 'T1082', 'tactic': 'Discovery', 'name': 'System Information Discovery'},
    'ipconfig': {'technique': 'T1016', 'tactic': 'Discovery', 'name': 'System Network Config Discovery'},
    'net user': {'technique': 'T1087.001', 'tactic': 'Discovery', 'name': 'Local Account Discovery'},
    'net group': {'technique': 'T1069.001', 'tactic': 'Discovery', 'name': 'Local Groups Discovery'},
    'net localgroup': {'technique': 'T1069.001', 'tactic': 'Discovery', 'name': 'Local Groups Discovery'},
    'get-aduser': {'technique': 'T1087.002', 'tactic': 'Discovery', 'name': 'Domain Account Discovery'},
    'get-adcomputer': {'technique': 'T1018', 'tactic': 'Discovery', 'name': 'Remote System Discovery'},
    'get-adgroup': {'technique': 'T1069.002', 'tactic': 'Discovery', 'name': 'Domain Groups Discovery'},
    'get-wmiobject': {'technique': 'T1082', 'tactic': 'Discovery', 'name': 'System Information Discovery'},
    'tasklist': {'technique': 'T1057', 'tactic': 'Discovery', 'name': 'Process Discovery'},
    'get-process': {'technique': 'T1057', 'tactic': 'Discovery', 'name': 'Process Discovery'},
    
    # ==================== Lateral Movement (TA0008) ====================
    'psexec': {'technique': 'T1570', 'tactic': 'Lateral Movement', 'name': 'Lateral Tool Transfer'},
    'invoke-wmimethod': {'technique': 'T1047', 'tactic': 'Execution', 'name': 'WMI'},
    'invoke-command': {'technique': 'T1021.006', 'tactic': 'Lateral Movement', 'name': 'WinRM'},
    'enter-pssession': {'technique': 'T1021.006', 'tactic': 'Lateral Movement', 'name': 'WinRM'},
    
    # ==================== Collection (TA0009) ====================
    'clipboard': {'technique': 'T1115', 'tactic': 'Collection', 'name': 'Clipboard Data'},
    'screenshot': {'technique': 'T1113', 'tactic': 'Collection', 'name': 'Screen Capture'},
    'keylogger': {'technique': 'T1056.001', 'tactic': 'Collection', 'name': 'Keylogging'},
    
    # ==================== Command and Control (TA0011) ====================
    'downloadstring': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'downloadfile': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'downloaddata': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'invoke-webrequest': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'invoke-restmethod': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'webclient': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'start-bitstransfer': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'certutil': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    'bitsadmin': {'technique': 'T1105', 'tactic': 'Command and Control', 'name': 'Ingress Tool Transfer'},
    
    # ==================== Exfiltration (TA0010) ====================
    'compress-archive': {'technique': 'T1560.001', 'tactic': 'Exfiltration', 'name': 'Archive via Utility'},
    '7z': {'technique': 'T1560.001', 'tactic': 'Exfiltration', 'name': 'Archive via Utility'},
    'rar': {'technique': 'T1560.001', 'tactic': 'Exfiltration', 'name': 'Archive via Utility'},
    
    # ==================== Impact (TA0040) ====================
    'cipher /w': {'technique': 'T1485', 'tactic': 'Impact', 'name': 'Data Destruction'},
    'vssadmin delete': {'technique': 'T1490', 'tactic': 'Impact', 'name': 'Inhibit System Recovery'},
    'bcdedit': {'technique': 'T1490', 'tactic': 'Impact', 'name': 'Inhibit System Recovery'},
    'wbadmin delete': {'technique': 'T1490', 'tactic': 'Impact', 'name': 'Inhibit System Recovery'},
    
    # ==================== Initial Access (TA0001) - Email specific ====================
    'phishing': {'technique': 'T1566', 'tactic': 'Initial Access', 'name': 'Phishing'},
    'spearphishing': {'technique': 'T1566.001', 'tactic': 'Initial Access', 'name': 'Spearphishing Attachment'},
    'macro': {'technique': 'T1566.001', 'tactic': 'Initial Access', 'name': 'Spearphishing Attachment'},
}
class MITREMapper:
    """Map indicators to MITRE ATT&CK techniques."""
    
    @staticmethod
    def map_indicators(content: str) -> List[Dict]:
        """
        Map content to MITRE ATT&CK techniques.
        
        Args:
            content: String content to analyze (file content, command lines, etc.)
        
        Returns:
            List of detected MITRE techniques
        """
        if not content:
            return []
        
        content_lower = content.lower()
        techniques = []
        seen = set()
        
        for indicator, mapping in MITRE_MAPPING.items():
            if indicator in content_lower and mapping['technique'] not in seen:
                techniques.append({
                    'technique_id': mapping['technique'],
                    'technique_name': mapping['name'],
                    'tactic': mapping['tactic'],
                    'indicator': indicator
                })
                seen.add(mapping['technique'])
        
        # Sort by tactic order (roughly following kill chain)
        tactic_order = [
            'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Command and Control', 'Exfiltration', 'Impact'
        ]
        
        techniques.sort(key=lambda x: tactic_order.index(x['tactic']) if x['tactic'] in tactic_order else 99)
        
        logger.info(f"[MITRE] Mapped {len(techniques)} ATT&CK techniques")
        return techniques
    
    @staticmethod
    def map_from_categories(categories: List[str]) -> List[Dict]:
        """
        Map string categories to MITRE techniques.
        
        Args:
            categories: List of malware behavior categories
        
        Returns:
            List of MITRE techniques
        """
        techniques = []
        seen = set()
        
        category_mapping = {
            'network': {'technique': 'T1071', 'tactic': 'Command and Control', 'name': 'Application Layer Protocol'},
            'persistence': {'technique': 'T1547', 'tactic': 'Persistence', 'name': 'Boot or Logon Autostart Execution'},
            'evasion': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files or Information'},
            'obfuscation': {'technique': 'T1027', 'tactic': 'Defense Evasion', 'name': 'Obfuscated Files or Information'},
            'crypto': {'technique': 'T1486', 'tactic': 'Impact', 'name': 'Data Encrypted for Impact'},
            'execution': {'technique': 'T1059', 'tactic': 'Execution', 'name': 'Command and Scripting Interpreter'},
            'disable_security': {'technique': 'T1562', 'tactic': 'Defense Evasion', 'name': 'Impair Defenses'},
            'credential': {'technique': 'T1003', 'tactic': 'Credential Access', 'name': 'OS Credential Dumping'},
            'discovery': {'technique': 'T1082', 'tactic': 'Discovery', 'name': 'System Information Discovery'},
            'lateral': {'technique': 'T1021', 'tactic': 'Lateral Movement', 'name': 'Remote Services'},
            'exfiltration': {'technique': 'T1041', 'tactic': 'Exfiltration', 'name': 'Exfiltration Over C2 Channel'},
            'keylogger': {'technique': 'T1056', 'tactic': 'Collection', 'name': 'Input Capture'},
            'screenshot': {'technique': 'T1113', 'tactic': 'Collection', 'name': 'Screen Capture'},
        }
        
        for category in categories:
            cat_lower = category.lower()
            if cat_lower in category_mapping and category_mapping[cat_lower]['technique'] not in seen:
                mapping = category_mapping[cat_lower]
                techniques.append({
                    'technique_id': mapping['technique'],
                    'technique_name': mapping['name'],
                    'tactic': mapping['tactic'],
                    'indicator': category
                })
                seen.add(mapping['technique'])
        
        return techniques
    
    @staticmethod
    def render_mitre_table(techniques: List[Dict]) -> str:
        """
        Render MITRE techniques as formatted ASCII table.
        
        Args:
            techniques: List of MITRE technique dicts
        
        Returns:
            Formatted table string
        """
        if not techniques:
            return "No MITRE ATT&CK techniques detected."
        
        lines = []
        lines.append("┌─ MITRE ATT&CK MAPPING")
        lines.append("│")
        lines.append("│  ┌────────────┬─────────────────────────────┬──────────────────────┐")
        lines.append("│  │ Technique  │ Name                        │ Tactic               │")
        lines.append("│  ├────────────┼─────────────────────────────┼──────────────────────┤")
        
        for tech in techniques[:10]:
            tid = tech['technique_id'][:10].ljust(10)
            name = tech['technique_name'][:27].ljust(27)
            tactic = tech['tactic'][:20].ljust(20)
            lines.append(f"│  │ {tid} │ {name} │ {tactic} │")
        
        lines.append("│  └────────────┴─────────────────────────────┴──────────────────────┘")
        lines.append("│")
        lines.append(f"│  Total: {len(techniques)} techniques detected")
        lines.append("│  Reference: https://attack.mitre.org/")
        lines.append("└" + "─" * 77)
        
        return '\n'.join(lines)
    
    @staticmethod
    def render_mitre_html(techniques: List[Dict]) -> str:
        """
        Render MITRE techniques as HTML table.
        
        Args:
            techniques: List of MITRE technique dicts
        
        Returns:
            HTML table string
        """
        if not techniques:
            return "<p>No MITRE ATT&CK techniques detected.</p>"
        
        html = """
        <div class="card mb-4">
            <div class="card-header bg-dark text-white">
                <h5>🎯 MITRE ATT&CK Techniques</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped table-bordered">
                        <thead class="thead-dark">
                            <tr>
                                <th>Technique ID</th>
                                <th>Name</th>
                                <th>Tactic</th>
                                <th>Indicator</th>
                            </tr>
                        </thead>
                        <tbody>
        """
        
        for tech in techniques[:15]:
            tactic_class = 'text-danger' if tech['tactic'] in ['Execution', 'Impact', 'Credential Access'] else 'text-warning' if tech['tactic'] in ['Defense Evasion', 'Persistence'] else ''
            html += f"""
                            <tr>
                                <td><a href="https://attack.mitre.org/techniques/{tech['technique_id']}/" target="_blank">{tech['technique_id']}</a></td>
                                <td>{tech['technique_name']}</td>
                                <td class="{tactic_class}">{tech['tactic']}</td>
                                <td><code>{tech['indicator'][:30]}</code></td>
                            </tr>
            """
        
        html += f"""
                        </tbody>
                    </table>
                </div>
                <p class="text-muted">
                    <small>Total: {len(techniques)} techniques detected | 
                    <a href="https://attack.mitre.org/" target="_blank">MITRE ATT&CK Reference</a></small>
                </p>
            </div>
        </div>
        """
        
        return html
