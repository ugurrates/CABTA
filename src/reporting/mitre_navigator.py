"""
Author: Ugur Ates
MITRE ATT&CK Navigator Export - Generate Navigator JSON for visualization.

v1.0.0 Features:
- Generate ATT&CK Navigator JSON layers
- Color-code by technique frequency
- Include comments from analysis
- Support Enterprise, Mobile, ICS matrices
- Multi-layer support for comparison
- Campaign timeline export

Best Practice: Used by SOC teams for threat visualization and briefings
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)
@dataclass
class NavigatorTechnique:
    """Single technique in Navigator layer."""
    techniqueID: str
    tactic: str = ""
    color: str = ""
    comment: str = ""
    enabled: bool = True
    metadata: List[Dict] = field(default_factory=list)
    links: List[Dict] = field(default_factory=list)
    showSubtechniques: bool = False
    score: int = 0
@dataclass
class NavigatorLayer:
    """ATT&CK Navigator Layer format."""
    name: str
    versions: Dict = field(default_factory=lambda: {
        "attack": "14",
        "navigator": "4.9.1",
        "layer": "4.5"
    })
    domain: str = "enterprise-attack"
    description: str = ""
    filters: Dict = field(default_factory=lambda: {
        "platforms": ["Windows", "Linux", "macOS"]
    })
    sorting: int = 0
    layout: Dict = field(default_factory=lambda: {
        "layout": "side",
        "aggregateFunction": "average",
        "showID": True,
        "showName": True,
        "showAggregateScores": True,
        "countUnscored": False
    })
    hideDisabled: bool = False
    techniques: List[Dict] = field(default_factory=list)
    gradient: Dict = field(default_factory=lambda: {
        "colors": ["#ffffff", "#66b1ff", "#ff6666"],
        "minValue": 0,
        "maxValue": 100
    })
    legendItems: List[Dict] = field(default_factory=list)
    metadata: List[Dict] = field(default_factory=list)
    links: List[Dict] = field(default_factory=list)
    showTacticRowBackground: bool = True
    tacticRowBackground: str = "#dddddd"
    selectTechniquesAcrossTactics: bool = True
    selectSubtechniquesWithParent: bool = False
class MITRENavigatorExporter:
    """
    Export analysis results to MITRE ATT&CK Navigator format.
    
    Navigator JSON can be imported at:
    https://mitre-attack.github.io/attack-navigator/
    
    Features:
    - Color-coded techniques by severity/frequency
    - Comments from analysis findings
    - Metadata with IOCs and timestamps
    - Multiple layer support for comparison
    """
    
    # Tactic to phase mapping
    TACTIC_ORDER = [
        'reconnaissance',
        'resource-development', 
        'initial-access',
        'execution',
        'persistence',
        'privilege-escalation',
        'defense-evasion',
        'credential-access',
        'discovery',
        'lateral-movement',
        'collection',
        'command-and-control',
        'exfiltration',
        'impact'
    ]
    
    # Severity colors
    SEVERITY_COLORS = {
        'critical': '#ff0000',
        'high': '#ff6666',
        'medium': '#ffcc00',
        'low': '#66b1ff',
        'info': '#00ff00',
    }
    
    # Common technique to tactic mapping
    TECHNIQUE_TACTICS = {
        'T1059': 'execution',
        'T1059.001': 'execution',  # PowerShell
        'T1059.003': 'execution',  # Windows Command Shell
        'T1059.005': 'execution',  # VBScript
        'T1059.007': 'execution',  # JavaScript
        'T1547': 'persistence',
        'T1547.001': 'persistence',  # Registry Run Keys
        'T1053': 'execution',
        'T1053.005': 'execution',  # Scheduled Task
        'T1027': 'defense-evasion',  # Obfuscated Files
        'T1027.001': 'defense-evasion',  # Binary Padding
        'T1140': 'defense-evasion',  # Deobfuscate/Decode Files
        'T1055': 'defense-evasion',  # Process Injection
        'T1055.001': 'defense-evasion',  # DLL Injection
        'T1055.012': 'defense-evasion',  # Process Hollowing
        'T1071': 'command-and-control',
        'T1071.001': 'command-and-control',  # Web Protocols
        'T1105': 'command-and-control',  # Ingress Tool Transfer
        'T1486': 'impact',  # Data Encrypted for Impact
        'T1490': 'impact',  # Inhibit System Recovery
        'T1003': 'credential-access',  # OS Credential Dumping
        'T1003.001': 'credential-access',  # LSASS Memory
        'T1082': 'discovery',  # System Information Discovery
        'T1083': 'discovery',  # File and Directory Discovery
        'T1012': 'discovery',  # Query Registry
        'T1112': 'defense-evasion',  # Modify Registry
        'T1562': 'defense-evasion',  # Impair Defenses
        'T1562.001': 'defense-evasion',  # Disable or Modify Tools
        'T1218': 'defense-evasion',  # System Binary Proxy Execution
        'T1218.011': 'defense-evasion',  # Rundll32
        'T1204': 'execution',  # User Execution
        'T1204.002': 'execution',  # Malicious File
        'T1566': 'initial-access',  # Phishing
        'T1566.001': 'initial-access',  # Spearphishing Attachment
        'T1566.002': 'initial-access',  # Spearphishing Link
    }
    
    def __init__(self):
        """Initialize exporter."""
        pass
    
    def create_layer_from_analysis(self, 
                                    analysis_result: Dict,
                                    layer_name: str = None,
                                    description: str = None) -> NavigatorLayer:
        """
        Create Navigator layer from file/email analysis result.
        
        Args:
            analysis_result: Analysis result dict with MITRE mapping
            layer_name: Layer name (default: auto-generated)
            description: Layer description
        
        Returns:
            NavigatorLayer object
        """
        # Extract MITRE data from various sources
        techniques = self._extract_techniques(analysis_result)
        
        # Create layer name
        if not layer_name:
            file_name = analysis_result.get('file_info', {}).get('file_name', 'Unknown')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            layer_name = f"Blue Team Assistant Analysis: {file_name} ({timestamp})"
        
        # Create description
        if not description:
            verdict = analysis_result.get('verdict', 'Unknown')
            score = analysis_result.get('composite_score', 0)
            description = f"Threat analysis - Verdict: {verdict}, Score: {score}/100"
        
        # Create layer
        layer = NavigatorLayer(
            name=layer_name,
            description=description,
            techniques=[asdict(t) for t in techniques],
            metadata=[
                {"name": "generated_by", "value": "Blue Team Assistant"},
                {"name": "analysis_date", "value": datetime.now().isoformat()},
                {"name": "verdict", "value": analysis_result.get('verdict', 'Unknown')},
                {"name": "score", "value": str(analysis_result.get('composite_score', 0))}
            ],
            legendItems=[
                {"label": "Critical", "color": self.SEVERITY_COLORS['critical']},
                {"label": "High", "color": self.SEVERITY_COLORS['high']},
                {"label": "Medium", "color": self.SEVERITY_COLORS['medium']},
                {"label": "Low", "color": self.SEVERITY_COLORS['low']},
            ]
        )
        
        return layer
    
    def _extract_techniques(self, analysis_result: Dict) -> List[NavigatorTechnique]:
        """Extract and deduplicate techniques from analysis."""
        techniques_dict = {}  # technique_id -> NavigatorTechnique
        
        # 1. From MITRE mapping in analysis
        mitre_mapping = analysis_result.get('mitre_mapping', {})
        for technique_id, data in mitre_mapping.items():
            if not technique_id.startswith('T'):
                continue
            
            techniques_dict[technique_id] = NavigatorTechnique(
                techniqueID=technique_id,
                tactic=data.get('tactic', self._get_tactic(technique_id)),
                color=self._get_color_by_confidence(data.get('confidence', 'medium')),
                comment=data.get('reason', ''),
                score=self._confidence_to_score(data.get('confidence', 'medium')),
                metadata=[{"name": "source", "value": "mitre_mapping"}]
            )
        
        # 2. From capabilities (capa results)
        capabilities = analysis_result.get('capabilities', {})
        attack_techniques = capabilities.get('attack_techniques', [])
        for att in attack_techniques:
            technique_id = att.get('id', '')
            if not technique_id or not technique_id.startswith('T'):
                continue
            
            if technique_id not in techniques_dict:
                techniques_dict[technique_id] = NavigatorTechnique(
                    techniqueID=technique_id,
                    tactic=att.get('tactic', self._get_tactic(technique_id)),
                    color=self.SEVERITY_COLORS['high'],
                    comment=f"capa: {att.get('capability', att.get('technique', ''))}",
                    score=75,
                    metadata=[{"name": "source", "value": "capa"}]
                )
            else:
                # Add to existing comment
                existing = techniques_dict[technique_id]
                existing.comment += f"\ncapa: {att.get('capability', '')}"
                existing.score = max(existing.score, 75)
        
        # 3. From sandbox behaviors
        sandbox = analysis_result.get('sandbox_analysis', {})
        sandbox_techniques = sandbox.get('mitre_techniques', [])
        for tech_id in sandbox_techniques:
            if not tech_id.startswith('T'):
                continue
            
            if tech_id not in techniques_dict:
                techniques_dict[tech_id] = NavigatorTechnique(
                    techniqueID=tech_id,
                    tactic=self._get_tactic(tech_id),
                    color=self.SEVERITY_COLORS['critical'],
                    comment="Observed in sandbox execution",
                    score=90,
                    metadata=[{"name": "source", "value": "sandbox"}]
                )
            else:
                existing = techniques_dict[tech_id]
                existing.comment += "\nObserved in sandbox"
                existing.score = max(existing.score, 90)
                existing.color = self.SEVERITY_COLORS['critical']
        
        # 4. From static analysis threat indicators
        static = analysis_result.get('static_analysis', {})
        threat_indicators = static.get('threat_indicators', [])
        for indicator in threat_indicators:
            technique_id = self._indicator_to_technique(indicator)
            if technique_id and technique_id not in techniques_dict:
                techniques_dict[technique_id] = NavigatorTechnique(
                    techniqueID=technique_id,
                    tactic=self._get_tactic(technique_id),
                    color=self.SEVERITY_COLORS['medium'],
                    comment=f"Static analysis: {indicator}",
                    score=50,
                    metadata=[{"name": "source", "value": "static_analysis"}]
                )
        
        # 5. From YARA matches
        yara = analysis_result.get('yara_analysis', {})
        yara_mitre = yara.get('interpretation', {}).get('mitre_techniques', [])
        for tech_id in yara_mitre:
            if tech_id not in techniques_dict:
                techniques_dict[tech_id] = NavigatorTechnique(
                    techniqueID=tech_id,
                    tactic=self._get_tactic(tech_id),
                    color=self.SEVERITY_COLORS['high'],
                    comment="YARA rule match",
                    score=70,
                    metadata=[{"name": "source", "value": "yara"}]
                )
        
        return list(techniques_dict.values())
    
    def _get_tactic(self, technique_id: str) -> str:
        """Get tactic for technique ID."""
        return self.TECHNIQUE_TACTICS.get(technique_id, 'execution')
    
    def _get_color_by_confidence(self, confidence: str) -> str:
        """Get color by confidence level."""
        mapping = {
            'critical': self.SEVERITY_COLORS['critical'],
            'high': self.SEVERITY_COLORS['high'],
            'medium': self.SEVERITY_COLORS['medium'],
            'low': self.SEVERITY_COLORS['low'],
            'info': self.SEVERITY_COLORS['info'],
        }
        return mapping.get(confidence.lower(), self.SEVERITY_COLORS['medium'])
    
    def _confidence_to_score(self, confidence: str) -> int:
        """Convert confidence to score (0-100)."""
        mapping = {
            'critical': 100,
            'high': 80,
            'medium': 60,
            'low': 40,
            'info': 20,
        }
        return mapping.get(confidence.lower(), 50)
    
    def _indicator_to_technique(self, indicator: str) -> Optional[str]:
        """Map indicator to technique ID."""
        indicator_lower = indicator.lower()
        
        # Common mappings
        mappings = {
            'powershell': 'T1059.001',
            'cmd': 'T1059.003',
            'vbscript': 'T1059.005',
            'javascript': 'T1059.007',
            'download': 'T1105',
            'registry': 'T1112',
            'persistence': 'T1547.001',
            'scheduled task': 'T1053.005',
            'injection': 'T1055',
            'obfuscate': 'T1027',
            'encoding': 'T1140',
            'base64': 'T1140',
            'credential': 'T1003',
            'lsass': 'T1003.001',
            'defender': 'T1562.001',
            'disable': 'T1562.001',
            'execution policy': 'T1059.001',
            'web request': 'T1071.001',
            'http': 'T1071.001',
            'encrypt': 'T1486',
            'ransom': 'T1486',
        }
        
        for keyword, technique in mappings.items():
            if keyword in indicator_lower:
                return technique
        
        return None
    
    def export_to_json(self, layer: NavigatorLayer, output_path: str) -> str:
        """
        Export layer to JSON file.
        
        Args:
            layer: NavigatorLayer object
            output_path: Output file path
        
        Returns:
            Path to created file
        """
        layer_dict = asdict(layer)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(layer_dict, f, indent=2)
        
        logger.info(f"[MITRE-NAV] Exported layer to: {output_path}")
        return output_path
    
    def create_comparison_layer(self,
                                 layers: List[NavigatorLayer],
                                 layer_name: str = "Comparison") -> NavigatorLayer:
        """
        Create comparison layer from multiple layers.
        
        Args:
            layers: List of NavigatorLayer objects
            layer_name: Name for comparison layer
        
        Returns:
            Combined NavigatorLayer
        """
        # Aggregate techniques
        technique_counts = {}
        technique_comments = {}
        
        for layer in layers:
            for tech in layer.techniques:
                tech_id = tech.get('techniqueID', '')
                if tech_id:
                    technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1
                    if tech_id not in technique_comments:
                        technique_comments[tech_id] = []
                    technique_comments[tech_id].append(layer.name)
        
        # Create combined techniques
        combined_techniques = []
        max_count = max(technique_counts.values()) if technique_counts else 1
        
        for tech_id, count in technique_counts.items():
            # Normalize score based on frequency
            score = int((count / max_count) * 100)
            
            combined_techniques.append({
                'techniqueID': tech_id,
                'tactic': self._get_tactic(tech_id),
                'score': score,
                'color': self._score_to_color(score),
                'comment': f"Found in {count} sample(s): {', '.join(technique_comments[tech_id][:5])}",
                'enabled': True,
                'showSubtechniques': False
            })
        
        return NavigatorLayer(
            name=layer_name,
            description=f"Comparison of {len(layers)} samples",
            techniques=combined_techniques,
            legendItems=[
                {"label": "Found in all samples", "color": self.SEVERITY_COLORS['critical']},
                {"label": "Found in most samples", "color": self.SEVERITY_COLORS['high']},
                {"label": "Found in some samples", "color": self.SEVERITY_COLORS['medium']},
                {"label": "Found in few samples", "color": self.SEVERITY_COLORS['low']},
            ]
        )
    
    def _score_to_color(self, score: int) -> str:
        """Convert score to color."""
        if score >= 80:
            return self.SEVERITY_COLORS['critical']
        elif score >= 60:
            return self.SEVERITY_COLORS['high']
        elif score >= 40:
            return self.SEVERITY_COLORS['medium']
        else:
            return self.SEVERITY_COLORS['low']
# ==================== HELPER FUNCTIONS ====================

def generate_navigator_layer(analysis_result: Dict, output_path: str = None) -> Dict:
    """
    Generate ATT&CK Navigator layer from analysis.
    
    Args:
        analysis_result: Analysis result dict
        output_path: Optional output path for JSON file
    
    Returns:
        Layer dict (and optionally saves to file)
    """
    exporter = MITRENavigatorExporter()
    layer = exporter.create_layer_from_analysis(analysis_result)
    
    if output_path:
        exporter.export_to_json(layer, output_path)
    
    return asdict(layer)
def create_campaign_layer(analysis_results: List[Dict], 
                          campaign_name: str,
                          output_path: str = None) -> Dict:
    """
    Create campaign layer from multiple analysis results.
    
    Args:
        analysis_results: List of analysis result dicts
        campaign_name: Campaign name
        output_path: Optional output path
    
    Returns:
        Combined layer dict
    """
    exporter = MITRENavigatorExporter()
    
    # Create individual layers
    layers = [
        exporter.create_layer_from_analysis(result)
        for result in analysis_results
    ]
    
    # Combine into comparison layer
    combined = exporter.create_comparison_layer(layers, campaign_name)
    
    if output_path:
        exporter.export_to_json(combined, output_path)
    
    return asdict(combined)
