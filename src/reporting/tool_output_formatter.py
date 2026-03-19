"""
Author: Ugur Ates
Tool Output Formatter - Araç çıktılarını SOC raporlarına dönüştürür.

Format Types:
1. Terminal output (colored, structured)
2. Markdown report
3. JSON export
4. LLM prompt generation
"""

import json
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
class ToolOutputFormatter:
    """Araç çıktılarını formatla."""
    
    @staticmethod
    def format_file_analysis(result: Dict, format_type: str = 'terminal') -> str:
        """
        File analizi için çıktı üret.
        
        Args:
            result: Analysis result dictionary
            format_type: 'terminal', 'markdown', 'json', 'llm'
        """
        if format_type == 'terminal':
            return ToolOutputFormatter._format_terminal(result)
        elif format_type == 'markdown':
            return ToolOutputFormatter._format_markdown(result)
        elif format_type == 'json':
            return ToolOutputFormatter._format_json(result)
        elif format_type == 'llm':
            return ToolOutputFormatter._format_for_llm(result)
        else:
            return ToolOutputFormatter._format_terminal(result)
    
    @staticmethod
    def _format_terminal(result: Dict) -> str:
        """Terminal output with sections."""
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append("FILE ANALYSIS REPORT - Blue Team Assistant")
        lines.append("=" * 80)
        lines.append(f"File: {result.get('file_path', 'Unknown')}")
        lines.append(f"Type: {result.get('file_type', 'Unknown')}")
        lines.append(f"Analysis Time: {datetime.now().isoformat()}")
        lines.append("")
        
        # Threat Score
        score = result.get('threat_score', 0)
        verdict = result.get('verdict', 'UNKNOWN')
        
        if score >= 70:
            icon = "[!!!]"
        elif score >= 40:
            icon = "[!!]"
        else:
            icon = "[OK]"
        
        lines.append(f"{icon} THREAT SCORE: {score}/100 - {verdict}")
        lines.append("")
        
        # Tools used
        tools = result.get('analysis_tools', [])
        if tools:
            lines.append(f"Tools Used: {', '.join(tools)}")
            lines.append("")
        
        # Threat Indicators
        indicators = result.get('threat_indicators', [])
        if indicators:
            lines.append("-" * 40)
            lines.append("THREAT INDICATORS:")
            lines.append("-" * 40)
            for ind in indicators[:10]:
                lines.append(f"  [!] {ind}")
            lines.append("")
        
        # Capabilities (capa)
        caps = result.get('capabilities', {})
        if caps.get('capabilities'):
            lines.append("-" * 40)
            lines.append("CAPABILITIES (capa):")
            lines.append("-" * 40)
            
            # Group by namespace
            namespaces = {}
            for c in caps['capabilities'][:20]:
                ns = c.get('namespace', 'other').split('/')[0]
                if ns not in namespaces:
                    namespaces[ns] = []
                namespaces[ns].append(c.get('name', 'unknown'))
            
            for ns, names in sorted(namespaces.items()):
                lines.append(f"  [{ns}]")
                for name in names[:5]:
                    lines.append(f"    - {name}")
            lines.append("")
        
        # Strings (FLOSS)
        strings = result.get('strings', {})
        if strings.get('decoded_count', 0) > 0 or strings.get('urls'):
            lines.append("-" * 40)
            lines.append("STRING ANALYSIS (FLOSS):")
            lines.append("-" * 40)
            lines.append(f"  Decoded strings: {strings.get('decoded_count', 0)}")
            lines.append(f"  Stack strings: {strings.get('stack_count', 0)}")
            
            if strings.get('urls'):
                lines.append(f"  URLs ({len(strings['urls'])}):")
                for url in strings['urls'][:5]:
                    lines.append(f"    - {url[:60]}")
            
            if strings.get('ips'):
                lines.append(f"  IPs: {', '.join(strings['ips'][:10])}")
            lines.append("")
        
        # Packer Detection (DIE)
        packer = result.get('packer_detection', {})
        if packer.get('packers') or packer.get('protectors'):
            lines.append("-" * 40)
            lines.append("PACKER DETECTION (DIE):")
            lines.append("-" * 40)
            if packer.get('packers'):
                lines.append(f"  Packer: {', '.join(packer['packers'])}")
            if packer.get('protectors'):
                lines.append(f"  Protector: {', '.join(packer['protectors'])}")
            if packer.get('compilers'):
                lines.append(f"  Compiler: {', '.join(packer['compilers'][:3])}")
            lines.append("")
        
        # Recommendations
        lines.append("-" * 40)
        lines.append("RECOMMENDATIONS:")
        lines.append("-" * 40)
        
        if score >= 70:
            lines.append("  [!!!] IMMEDIATE ACTIONS REQUIRED:")
            lines.append("    - Block file hash on all security controls")
            lines.append("    - Hunt for this file across endpoints")
            lines.append("    - Isolate affected systems")
            lines.append("    - Preserve evidence for forensics")
        elif score >= 40:
            lines.append("  [!!] INVESTIGATION REQUIRED:")
            lines.append("    - Submit to sandbox for dynamic analysis")
            lines.append("    - Review in isolated environment")
            lines.append("    - Monitor for behavioral indicators")
        else:
            lines.append("  [OK] ROUTINE MONITORING:")
            lines.append("    - Continue standard monitoring")
            lines.append("    - No immediate action required")
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        return '\n'.join(lines)
    
    @staticmethod
    def _format_markdown(result: Dict) -> str:
        """Markdown format."""
        lines = []
        
        lines.append("# File Analysis Report")
        lines.append(f"\n**Generated:** {datetime.now().isoformat()}")
        lines.append(f"\n**File:** `{result.get('file_path', 'Unknown')}`")
        lines.append(f"\n**Type:** {result.get('file_type', 'Unknown')}")
        
        score = result.get('threat_score', 0)
        verdict = result.get('verdict', 'UNKNOWN')
        
        lines.append(f"\n## Verdict: {verdict}")
        lines.append(f"\n**Threat Score:** {score}/100")
        
        # Threat Indicators
        indicators = result.get('threat_indicators', [])
        if indicators:
            lines.append("\n## Threat Indicators\n")
            for ind in indicators:
                lines.append(f"- ⚠️ {ind}")
        
        # Capabilities
        caps = result.get('capabilities', {})
        if caps.get('attack_techniques'):
            lines.append("\n## ATT&CK Techniques\n")
            lines.append("| ID | Technique | Tactic |")
            lines.append("|---|---|---|")
            seen = set()
            for t in caps['attack_techniques'][:10]:
                if t['id'] not in seen:
                    lines.append(f"| {t['id']} | {t.get('technique', '-')} | {t.get('tactic', '-')} |")
                    seen.add(t['id'])
        
        # IOCs
        strings = result.get('strings', {})
        if strings.get('urls') or strings.get('ips'):
            lines.append("\n## Extracted IOCs\n")
            if strings.get('urls'):
                lines.append("### URLs")
                for url in strings['urls'][:10]:
                    lines.append(f"- `{url}`")
            if strings.get('ips'):
                lines.append("\n### IP Addresses")
                for ip in strings['ips'][:10]:
                    lines.append(f"- `{ip}`")
        
        return '\n'.join(lines)
    
    @staticmethod
    def _format_json(result: Dict) -> str:
        """JSON export."""
        export = {
            'report_type': 'file_analysis',
            'generated_at': datetime.now().isoformat(),
            'file_path': result.get('file_path'),
            'file_type': result.get('file_type'),
            'threat_score': result.get('threat_score', 0),
            'verdict': result.get('verdict'),
            'threat_indicators': result.get('threat_indicators', []),
            'analysis_tools': result.get('analysis_tools', []),
            'capabilities': result.get('capabilities', {}),
            'strings': result.get('strings', {}),
            'packer_detection': result.get('packer_detection', {}),
        }
        return json.dumps(export, indent=2, default=str)
    
    @staticmethod
    def _format_for_llm(result: Dict) -> str:
        """LLM analizi için prompt hazırla."""
        lines = []
        
        lines.append("# Malware Analysis Summary for AI Review")
        lines.append(f"\n**File Type:** {result.get('file_type', 'Unknown')}")
        lines.append(f"**Threat Score:** {result.get('threat_score', 0)}/100")
        lines.append(f"**Preliminary Verdict:** {result.get('verdict', 'Unknown')}")
        
        # Key findings
        lines.append("\n## Key Findings")
        
        indicators = result.get('threat_indicators', [])
        if indicators:
            lines.append("\n### Threat Indicators:")
            for ind in indicators[:15]:
                lines.append(f"- {ind}")
        
        # Capabilities
        caps = result.get('capabilities', {})
        if caps.get('capabilities'):
            lines.append("\n### Detected Capabilities:")
            for c in caps['capabilities'][:10]:
                lines.append(f"- {c.get('name')}")
        
        if caps.get('attack_techniques'):
            lines.append("\n### ATT&CK Techniques:")
            seen = set()
            for t in caps['attack_techniques'][:10]:
                if t['id'] not in seen:
                    lines.append(f"- {t['id']}: {t.get('technique', 'Unknown')}")
                    seen.add(t['id'])
        
        # Strings
        strings = result.get('strings', {})
        if strings.get('suspicious_strings'):
            lines.append("\n### Suspicious Strings:")
            for s in strings['suspicious_strings'][:10]:
                lines.append(f"- `{s[:60]}`")
        
        # Packer
        packer = result.get('packer_detection', {})
        if packer.get('packers') or packer.get('protectors'):
            lines.append("\n### Packer/Protector Detection:")
            if packer.get('packers'):
                lines.append(f"- Packer: {', '.join(packer['packers'])}")
            if packer.get('protectors'):
                lines.append(f"- Protector: {', '.join(packer['protectors'])}")
        
        # Analysis request
        lines.append("\n## Analysis Request")
        lines.append("Based on these findings, provide:")
        lines.append("1. Likely malware family/type classification")
        lines.append("2. Primary attack vector and infection chain")
        lines.append("3. Recommended containment and remediation steps")
        lines.append("4. Detection rule suggestions (YARA/Sigma/KQL)")
        lines.append("5. Related threat actor or campaign if identifiable")
        
        return '\n'.join(lines)
    
    @staticmethod
    def format_email_analysis(result: Dict, format_type: str = 'terminal') -> str:
        """Email analizi için çıktı."""
        if format_type == 'terminal':
            return ToolOutputFormatter._format_email_terminal(result)
        elif format_type == 'markdown':
            return ToolOutputFormatter._format_email_markdown(result)
        else:
            return ToolOutputFormatter._format_email_terminal(result)
    
    @staticmethod
    def _format_email_terminal(result: Dict) -> str:
        """Email terminal output."""
        lines = []
        
        lines.append("=" * 80)
        lines.append("EMAIL ANALYSIS REPORT - Blue Team Assistant")
        lines.append("=" * 80)
        
        email_data = result.get('email_data', {})
        lines.append(f"From: {email_data.get('from', 'Unknown')}")
        lines.append(f"Subject: {email_data.get('subject', 'Unknown')}")
        lines.append(f"Date: {email_data.get('date', 'Unknown')}")
        lines.append("")
        
        # Verdict
        score = result.get('composite_score', 0)
        verdict = result.get('verdict', 'UNKNOWN')
        
        if score >= 70:
            icon = "[PHISHING]"
        elif score >= 40:
            icon = "[SUSPICIOUS]"
        else:
            icon = "[CLEAN]"
        
        lines.append(f"{icon} THREAT SCORE: {score}/100 - {verdict}")
        lines.append("")
        
        # Authentication
        auth = result.get('email_data', {})
        lines.append("-" * 40)
        lines.append("AUTHENTICATION:")
        lines.append("-" * 40)
        lines.append(f"  SPF:   {auth.get('spf', 'Unknown')}")
        lines.append(f"  DKIM:  {auth.get('dkim', 'Unknown')}")
        lines.append(f"  DMARC: {auth.get('dmarc', 'Unknown')}")
        lines.append("")
        
        # Advanced analysis
        adv = result.get('advanced_analysis', {})
        if adv.get('lookalike_domains'):
            lines.append("-" * 40)
            lines.append("LOOKALIKE DOMAINS DETECTED:")
            lines.append("-" * 40)
            for d in adv['lookalike_domains'][:5]:
                lines.append(f"  [!] {d.get('domain', 'Unknown')} -> {d.get('similar_to', '')} ({d.get('score', 0)}% match)")
            lines.append("")
        
        if adv.get('link_mismatches'):
            lines.append("-" * 40)
            lines.append("LINK-TEXT MISMATCHES:")
            lines.append("-" * 40)
            for m in adv['link_mismatches'][:5]:
                lines.append(f"  Text: {m.get('text', '')[:40]}")
                lines.append(f"  URL:  {m.get('url', '')[:60]}")
                lines.append("")
        
        lines.append("=" * 80)
        
        return '\n'.join(lines)
    
    @staticmethod
    def _format_email_markdown(result: Dict) -> str:
        """Email markdown output."""
        lines = []
        lines.append("# Email Analysis Report\n")
        
        email_data = result.get('email_data', {})
        lines.append(f"**From:** {email_data.get('from', 'Unknown')}")
        lines.append(f"\n**Subject:** {email_data.get('subject', 'Unknown')}")
        lines.append(f"\n**Verdict:** {result.get('verdict', 'Unknown')}")
        lines.append(f"\n**Score:** {result.get('composite_score', 0)}/100")
        
        return '\n'.join(lines)
