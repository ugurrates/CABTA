"""
Author: Ugur AtesHTML report generator for threat analysis."""

from typing import Dict
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)
class HTMLReportGenerator:
    """Generate professional HTML reports."""
    
    @staticmethod
    def generate_ioc_report(analysis_result: Dict) -> str:
        """
        Generate HTML report for IOC investigation.
        
        Args:
            analysis_result: IOC analysis results
        
        Returns:
            HTML report string
        """
        ioc = analysis_result.get('ioc', 'N/A')
        ioc_type = analysis_result.get('ioc_type', 'N/A')
        threat_score = analysis_result.get('threat_score', 0)
        verdict = analysis_result.get('verdict', 'UNKNOWN')
        
        # Determine verdict color
        verdict_color = {
            'CLEAN': '#28a745',
            'LOW_RISK': '#ffc107',
            'SUSPICIOUS': '#fd7e14',
            'MALICIOUS': '#dc3545'
        }.get(verdict, '#6c757d')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IOC Investigation Report - {ioc}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }}
        .header {{
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #2c3e50;
            font-size: 28px;
            margin-bottom: 10px;
        }}
        .header .timestamp {{
            color: #7f8c8d;
            font-size: 14px;
        }}
        .verdict-box {{
            background: {verdict_color};
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .verdict-box h2 {{
            font-size: 24px;
            margin-bottom: 10px;
        }}
        .verdict-box .score {{
            font-size: 48px;
            font-weight: bold;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        .section h3 {{
            color: #34495e;
            font-size: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #007bff;
            padding-left: 15px;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .info-card {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 3px solid #007bff;
        }}
        .info-card .label {{
            font-size: 12px;
            color: #7f8c8d;
            text-transform: uppercase;
            margin-bottom: 5px;
        }}
        .info-card .value {{
            font-size: 16px;
            color: #2c3e50;
            font-weight: 600;
        }}
        .source-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        .source-table th {{
            background: #007bff;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        .source-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #dee2e6;
        }}
        .source-table tr:hover {{
            background: #f8f9fa;
        }}
        .status-icon {{
            display: inline-block;
            width: 20px;
            height: 20px;
            text-align: center;
            font-weight: bold;
        }}
        .recommendations {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 6px;
        }}
        .recommendations ul {{
            list-style-position: inside;
            margin-left: 10px;
        }}
        .recommendations li {{
            margin: 8px 0;
            color: #856404;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #7f8c8d;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ IOC Investigation Report</h1>
            <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="verdict-box">
            <h2>VERDICT: {verdict}</h2>
            <div class="score">{threat_score}/100</div>
        </div>
        
        <div class="section">
            <h3>📋 IOC Information</h3>
            <div class="info-grid">
                <div class="info-card">
                    <div class="label">Indicator</div>
                    <div class="value">{ioc}</div>
                </div>
                <div class="info-card">
                    <div class="label">Type</div>
                    <div class="value">{ioc_type.upper()}</div>
                </div>
                <div class="info-card">
                    <div class="label">Sources Checked</div>
                    <div class="value">{analysis_result.get('sources_checked', 0)}</div>
                </div>
                <div class="info-card">
                    <div class="label">Detections</div>
                    <div class="value">{analysis_result.get('sources_flagged', 0)}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h3>🔍 Threat Intelligence Results</h3>
            <table class="source-table">
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Status</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        # Add source results
        sources = analysis_result.get('sources', {})
        for source_name, source_data in sources.items():
            status = source_data.get('status', '⚠')
            details = []
            
            if 'detections' in source_data:
                details.append(f"Detections: {source_data['detections']}")
            if 'confidence' in source_data:
                details.append(f"Confidence: {source_data['confidence']}%")
            if 'botnet' in source_data:
                details.append(f"Botnet: {source_data['botnet']}")
            if 'malware' in source_data:
                details.append(f"Malware: {source_data['malware']}")
            if 'error' in source_data:
                details.append(f"Error: {source_data['error']}")
            
            details_str = ', '.join(details) if details else 'N/A'
            
            html += f"""
                    <tr>
                        <td><strong>{source_name.replace('_', ' ').title()}</strong></td>
                        <td><span class="status-icon">{status}</span></td>
                        <td>{details_str}</td>
                    </tr>"""
        
        html += """
                </tbody>
            </table>
        </div>
"""
        
        # Add recommendations
        recommendations = analysis_result.get('recommendations', [])
        if recommendations:
            html += """
        <div class="section">
            <h3>💡 Recommendations</h3>
            <div class="recommendations">
                <ul>
"""
            for rec in recommendations:
                html += f"                    <li>{rec}</li>\n"
            
            html += """
                </ul>
            </div>
        </div>
"""
        
        html += """
        <div class="footer">
            Generated by Blue Team Assistant | Aviation Cybersecurity Toolkit
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    @staticmethod
    def save_report(html_content: str, output_path: str):
        """
        Save HTML report to file.
        
        Args:
            html_content: HTML string
            output_path: Output file path
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"[REPORT] Saved HTML report: {output_path}")
        except Exception as e:
            logger.error(f"[REPORT] Failed to save report: {e}")
