"""
Author: Ugur Ates
Executive Summary PDF Generator - Professional PDF reports for management.

v1.0.0 Features:
- One-page executive summary
- Threat level visualization
- Key findings highlights
- Recommendations section
- IOC table
- MITRE ATT&CK coverage chart
- Professional styling

Best Practice: Used for management briefings and incident documentation
"""

import io
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Check reportlab availability
REPORTLAB_AVAILABLE = False
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, HRFlowable
    )
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    REPORTLAB_AVAILABLE = True
except ImportError:
    logger.warning("[PDF] reportlab not available - pip install reportlab")
class ExecutivePDFGenerator:
    """
    Generate professional executive summary PDF reports.
    
    Features:
    - Clean, professional layout
    - Threat level indicator
    - Key findings and recommendations
    - IOC summary table
    - MITRE ATT&CK coverage
    - Suitable for non-technical stakeholders
    """
    
    # Color scheme
    COLORS = {
        'critical': colors.HexColor('#dc3545'),
        'high': colors.HexColor('#fd7e14'),
        'medium': colors.HexColor('#ffc107'),
        'low': colors.HexColor('#28a745'),
        'info': colors.HexColor('#17a2b8'),
        'primary': colors.HexColor('#0d6efd'),
        'dark': colors.HexColor('#343a40'),
        'light': colors.HexColor('#f8f9fa'),
        'white': colors.white,
        'black': colors.black,
    }
    
    def __init__(self, page_size=A4):
        """Initialize PDF generator."""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab is required for PDF generation")
        
        self.page_size = page_size
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=self.COLORS['dark'],
            alignment=1  # Center
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=self.COLORS['primary'],
            borderWidth=1,
            borderColor=self.COLORS['primary'],
            borderPadding=5
        ))
        
        # Verdict style
        self.styles.add(ParagraphStyle(
            name='Verdict',
            parent=self.styles['Normal'],
            fontSize=18,
            alignment=1,
            spaceAfter=10
        ))
        
        # Finding style
        self.styles.add(ParagraphStyle(
            name='Finding',
            parent=self.styles['Normal'],
            fontSize=10,
            leftIndent=20,
            bulletIndent=10,
            spaceBefore=5
        ))
        
        # Recommendation style
        self.styles.add(ParagraphStyle(
            name='Recommendation',
            parent=self.styles['Normal'],
            fontSize=10,
            leftIndent=20,
            textColor=self.COLORS['dark'],
            spaceBefore=5
        ))
    
    def generate_file_report(self, result: Dict, output_path: str) -> Optional[str]:
        """
        Generate executive PDF report for file analysis.
        
        Args:
            result: File analysis result dict
            output_path: Output PDF path
        
        Returns:
            Path to generated PDF or None on error
        """
        if not REPORTLAB_AVAILABLE:
            logger.error("[PDF] reportlab not available")
            return None
        
        try:
            doc = SimpleDocTemplate(
                output_path,
                pagesize=self.page_size,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            story = []
            
            # Title
            story.append(Paragraph(
                "🔬 MALWARE ANALYSIS EXECUTIVE SUMMARY",
                self.styles['ReportTitle']
            ))
            
            # Metadata
            file_info = result.get('file_info', {})
            hashes = result.get('hashes', {})
            
            story.append(Paragraph(
                f"<b>File:</b> {file_info.get('file_name', 'Unknown')}",
                self.styles['Normal']
            ))
            story.append(Paragraph(
                f"<b>Analysis Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                self.styles['Normal']
            ))
            story.append(Paragraph(
                f"<b>SHA256:</b> <font size=8>{hashes.get('sha256', 'N/A')}</font>",
                self.styles['Normal']
            ))
            
            story.append(Spacer(1, 20))
            
            # Threat Level Box
            story.append(self._create_threat_level_box(result))
            
            story.append(Spacer(1, 20))
            
            # Key Findings Section
            story.append(Paragraph("📋 KEY FINDINGS", self.styles['SectionHeader']))
            story.extend(self._create_findings_section(result))
            
            story.append(Spacer(1, 15))
            
            # IOC Summary Table
            story.append(Paragraph("🎯 INDICATORS OF COMPROMISE", self.styles['SectionHeader']))
            story.append(self._create_ioc_table(result))
            
            story.append(Spacer(1, 15))
            
            # MITRE ATT&CK Coverage
            story.append(Paragraph("⚔️ MITRE ATT&CK COVERAGE", self.styles['SectionHeader']))
            story.append(self._create_mitre_summary(result))
            
            story.append(Spacer(1, 15))
            
            # Recommendations
            story.append(Paragraph("✅ RECOMMENDATIONS", self.styles['SectionHeader']))
            story.extend(self._create_recommendations(result))
            
            # Footer
            story.append(Spacer(1, 30))
            story.append(HRFlowable(width="100%", thickness=1, color=self.COLORS['light']))
            story.append(Paragraph(
                f"<font size=8 color='gray'>Generated by Blue Team Assistant | "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
                f"Confidential</font>",
                self.styles['Normal']
            ))
            
            # Build PDF
            doc.build(story)
            
            logger.info(f"[PDF] Executive summary saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"[PDF] Generation failed: {e}", exc_info=True)
            return None
    
    def _create_threat_level_box(self, result: Dict) -> Table:
        """Create threat level indicator box."""
        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('composite_score', 0)
        
        # Determine color and icon
        if score >= 70 or verdict == 'MALICIOUS':
            bg_color = self.COLORS['critical']
            text = "🔴 MALICIOUS"
            level = "CRITICAL"
        elif score >= 40 or verdict == 'SUSPICIOUS':
            bg_color = self.COLORS['medium']
            text = "🟠 SUSPICIOUS"
            level = "MEDIUM"
        else:
            bg_color = self.COLORS['low']
            text = "🟢 CLEAN"
            level = "LOW"
        
        # Create table for the box
        data = [
            [Paragraph(f"<b>{text}</b>", self.styles['Verdict'])],
            [Paragraph(f"Threat Score: <b>{score}/100</b>", self.styles['Normal'])],
            [Paragraph(f"Risk Level: {level}", self.styles['Normal'])]
        ]
        
        table = Table(data, colWidths=[4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg_color),
            ('TEXTCOLOR', (0, 0), (-1, -1), self.COLORS['white']),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('BOX', (0, 0), (-1, -1), 2, self.COLORS['dark']),
        ]))
        
        return table
    
    def _create_findings_section(self, result: Dict) -> List:
        """Create key findings list."""
        elements = []
        
        # Collect findings from various sources
        findings = []
        
        # From contributing factors
        scoring = result.get('scoring', {})
        factors = scoring.get('contributing_factors', [])
        findings.extend(factors[:5])
        
        # From threat indicators
        static = result.get('static_analysis', {})
        indicators = static.get('threat_indicators', [])
        findings.extend(indicators[:5])
        
        # From capabilities
        caps = result.get('capabilities', {})
        if caps.get('capabilities'):
            cap_count = len(caps.get('capabilities', []))
            findings.append(f"Detected {cap_count} suspicious capabilities")
        
        # From sandbox
        sandbox = result.get('sandbox_analysis', {})
        behaviors = sandbox.get('behaviors', [])
        if behaviors:
            findings.append(f"Sandbox detected {len(behaviors)} behavioral indicators")
        
        # Deduplicate and limit
        findings = list(dict.fromkeys(findings))[:10]
        
        if not findings:
            findings = ["No significant findings detected"]
        
        # Create bullet points
        for finding in findings:
            elements.append(Paragraph(
                f"• {finding}",
                self.styles['Finding']
            ))
        
        return elements
    
    def _create_ioc_table(self, result: Dict) -> Table:
        """Create IOC summary table."""
        # Collect IOCs
        iocs = []
        
        # From strings
        string_analysis = result.get('string_analysis', {})
        
        # URLs
        urls = string_analysis.get('urls', [])
        if not urls:
            raw = result.get('raw_output', {}).get('file_analysis', {}).get('strings', {})
            urls = raw.get('urls', [])
        for url in urls[:5]:
            iocs.append(('URL', str(url)[:50]))
        
        # IPs
        ips = string_analysis.get('ips', [])
        if not ips:
            raw = result.get('raw_output', {}).get('file_analysis', {}).get('strings', {})
            ips = raw.get('ips', [])
        for ip in ips[:5]:
            iocs.append(('IP Address', str(ip)))
        
        # Registry
        registry = string_analysis.get('registry_keys', [])
        for reg in registry[:3]:
            iocs.append(('Registry', str(reg)[:50]))
        
        # Hashes
        hashes = result.get('hashes', {})
        if hashes.get('sha256'):
            iocs.append(('SHA256', hashes['sha256'][:32] + '...'))
        if hashes.get('md5'):
            iocs.append(('MD5', hashes['md5']))
        
        # Create table
        if not iocs:
            iocs = [('N/A', 'No IOCs extracted')]
        
        data = [['Type', 'Value']] + iocs
        
        table = Table(data, colWidths=[1.5*inch, 4.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.COLORS['white']),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), self.COLORS['light']),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['dark']),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        return table
    
    def _create_mitre_summary(self, result: Dict) -> Table:
        """Create MITRE ATT&CK summary."""
        # Collect techniques
        techniques = set()
        
        # From capabilities
        caps = result.get('capabilities', {})
        for att in caps.get('attack_techniques', []):
            tech_id = att.get('id', '')
            if tech_id:
                techniques.add(tech_id)
        
        # From sandbox
        sandbox = result.get('sandbox_analysis', {})
        for tech in sandbox.get('mitre_techniques', []):
            if tech.startswith('T'):
                techniques.add(tech)
        
        # From MITRE mapping
        mitre = result.get('mitre_mapping', {})
        for tech_id in mitre.keys():
            if tech_id.startswith('T'):
                techniques.add(tech_id)
        
        # Create summary
        if techniques:
            tech_list = ', '.join(sorted(techniques)[:15])
            summary = f"{len(techniques)} techniques mapped: {tech_list}"
            if len(techniques) > 15:
                summary += f"... (+{len(techniques)-15} more)"
        else:
            summary = "No MITRE ATT&CK techniques mapped"
        
        data = [
            ['Techniques Detected', str(len(techniques))],
            ['Coverage', summary[:80]],
        ]
        
        table = Table(data, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.COLORS['light']),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['dark']),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        
        return table
    
    def _create_recommendations(self, result: Dict) -> List:
        """Create recommendations based on analysis."""
        elements = []
        
        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('composite_score', 0)
        
        recommendations = []
        
        if score >= 70 or verdict == 'MALICIOUS':
            recommendations = [
                "🚨 IMMEDIATE: Block file hash on all security controls (EDR, Proxy, Firewall)",
                "🔍 HUNT: Search for this file across all endpoints using EDR",
                "🔒 ISOLATE: Quarantine any systems where this file was found",
                "📋 DOCUMENT: Preserve all evidence for incident response",
                "📢 NOTIFY: Alert security team and consider escalation",
            ]
        elif score >= 40 or verdict == 'SUSPICIOUS':
            recommendations = [
                "⚠️ INVESTIGATE: Submit to sandbox for dynamic analysis",
                "🔍 REVIEW: Analyze in isolated environment before allowing",
                "📊 MONITOR: Add detection rules to SIEM/EDR",
                "📋 DOCUMENT: Record findings for threat intelligence",
            ]
        else:
            recommendations = [
                "✅ ROUTINE: Continue standard security monitoring",
                "📊 BASELINE: Consider adding to known-good baseline",
                "📋 ARCHIVE: Store analysis results for future reference",
            ]
        
        # Add LLM recommendations if available
        llm = result.get('llm_analysis', {})
        llm_recs = llm.get('recommendations', [])
        if llm_recs:
            recommendations.extend([f"🤖 AI: {r}" for r in llm_recs[:3]])
        
        for rec in recommendations:
            elements.append(Paragraph(rec, self.styles['Recommendation']))
        
        return elements
    
    def generate_email_report(self, result: Dict, output_path: str) -> Optional[str]:
        """
        Generate executive PDF report for email analysis.
        
        Args:
            result: Email analysis result dict
            output_path: Output PDF path
        
        Returns:
            Path to generated PDF or None on error
        """
        if not REPORTLAB_AVAILABLE:
            logger.error("[PDF] reportlab not available")
            return None
        
        try:
            doc = SimpleDocTemplate(
                output_path,
                pagesize=self.page_size,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            story = []
            
            # Title
            story.append(Paragraph(
                "📧 EMAIL SECURITY ANALYSIS EXECUTIVE SUMMARY",
                self.styles['ReportTitle']
            ))
            
            # Email metadata
            email_data = result.get('email_data', {})
            
            story.append(Paragraph(
                f"<b>Subject:</b> {email_data.get('subject', 'Unknown')[:60]}",
                self.styles['Normal']
            ))
            story.append(Paragraph(
                f"<b>From:</b> {email_data.get('from', 'Unknown')}",
                self.styles['Normal']
            ))
            story.append(Paragraph(
                f"<b>Analysis Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                self.styles['Normal']
            ))
            
            story.append(Spacer(1, 20))
            
            # Threat Level
            story.append(self._create_threat_level_box(result))
            
            story.append(Spacer(1, 20))
            
            # Phishing Indicators
            story.append(Paragraph("🎣 PHISHING INDICATORS", self.styles['SectionHeader']))
            
            phishing = result.get('phishing_analysis', {})
            indicators = phishing.get('indicators', [])
            
            if indicators:
                for ind in indicators[:8]:
                    story.append(Paragraph(f"• {ind}", self.styles['Finding']))
            else:
                story.append(Paragraph("• No phishing indicators detected", self.styles['Finding']))
            
            story.append(Spacer(1, 15))
            
            # Authentication Results
            story.append(Paragraph("🔐 AUTHENTICATION", self.styles['SectionHeader']))
            
            auth = result.get('authentication', {})
            auth_data = [
                ['Check', 'Result'],
                ['SPF', '✅ Pass' if auth.get('spf_pass') else '❌ Fail'],
                ['DKIM', '✅ Pass' if auth.get('dkim_pass') else '❌ Fail'],
                ['DMARC', '✅ Pass' if auth.get('dmarc_pass') else '❌ Fail'],
            ]
            
            auth_table = Table(auth_data, colWidths=[2*inch, 3*inch])
            auth_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['primary']),
                ('TEXTCOLOR', (0, 0), (-1, 0), self.COLORS['white']),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, self.COLORS['dark']),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ]))
            story.append(auth_table)
            
            story.append(Spacer(1, 15))
            
            # Recommendations
            story.append(Paragraph("✅ RECOMMENDATIONS", self.styles['SectionHeader']))
            story.extend(self._create_email_recommendations(result))
            
            # Footer
            story.append(Spacer(1, 30))
            story.append(HRFlowable(width="100%", thickness=1, color=self.COLORS['light']))
            story.append(Paragraph(
                f"<font size=8 color='gray'>Generated by Blue Team Assistant | Confidential</font>",
                self.styles['Normal']
            ))
            
            doc.build(story)
            
            logger.info(f"[PDF] Email summary saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"[PDF] Generation failed: {e}", exc_info=True)
            return None
    
    def _create_email_recommendations(self, result: Dict) -> List:
        """Create email-specific recommendations."""
        elements = []
        
        verdict = result.get('verdict', 'UNKNOWN')
        score = result.get('composite_score', 0)
        
        if score >= 70 or verdict == 'MALICIOUS':
            recs = [
                "🚨 DELETE: Remove email from all user mailboxes immediately",
                "🔒 BLOCK: Add sender domain to blocklist",
                "📢 ALERT: Notify users who may have received this email",
                "🔍 HUNT: Search for similar emails in mail logs",
            ]
        elif score >= 40 or verdict == 'SUSPICIOUS':
            recs = [
                "⚠️ QUARANTINE: Move to spam/junk folder",
                "🔍 INVESTIGATE: Review URLs and attachments in sandbox",
                "📊 MONITOR: Track sender for future suspicious activity",
            ]
        else:
            recs = [
                "✅ ALLOW: Email appears legitimate",
                "📋 ARCHIVE: Store analysis for records",
            ]
        
        for rec in recs:
            elements.append(Paragraph(rec, self.styles['Recommendation']))
        
        return elements
# ==================== HELPER FUNCTIONS ====================

def generate_executive_pdf(result: Dict, output_path: str, 
                           report_type: str = 'file') -> Optional[str]:
    """
    Generate executive PDF report.
    
    Args:
        result: Analysis result dict
        output_path: Output PDF path
        report_type: 'file' or 'email'
    
    Returns:
        Path to generated PDF or None
    """
    if not REPORTLAB_AVAILABLE:
        logger.error("[PDF] reportlab not installed - pip install reportlab")
        return None
    
    generator = ExecutivePDFGenerator()
    
    if report_type == 'email':
        return generator.generate_email_report(result, output_path)
    else:
        return generator.generate_file_report(result, output_path)
