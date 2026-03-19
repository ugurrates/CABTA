"""
Author: Ugur Ates
Capability Analyzer - Mandiant capa entegrasyonu.

capa, executable dosyalardaki davranışları (capabilities) tespit eder:
- ATT&CK tekniklerini mapping
- Malware davranışlarını kategorize etme
- Anti-analysis teknikleri
- Network/file/process operasyonları

https://github.com/mandiant/capa
"""

import json
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)
@dataclass
class Capability:
    """Tek bir capability."""
    name: str
    namespace: str
    attack_ids: List[str] = field(default_factory=list)
    mbc_ids: List[str] = field(default_factory=list)  # Malware Behavior Catalog
    scope: str = "function"  # function, basic block, file
    matches: int = 0
    description: str = ""
@dataclass
class CapaAnalysisResult:
    """capa analiz sonucu."""
    success: bool
    capabilities: List[Capability] = field(default_factory=list)
    attack_techniques: List[Dict] = field(default_factory=list)
    mbc_behaviors: List[Dict] = field(default_factory=list)
    threat_score: int = 0
    summary: str = ""
    raw_output: str = ""
    error_message: str = ""
class CapabilityAnalyzer:
    """Mandiant capa ile capability detection."""
    
    # Yüksek riskli capability namespace'leri
    HIGH_RISK_NAMESPACES = [
        'anti-analysis',
        'collection',
        'command-and-control', 
        'credential-access',
        'defense-evasion',
        'exfiltration',
        'impact',
        'lateral-movement',
        'persistence',
        'privilege-escalation',
        'execution',
        'discovery',
    ]
    
    # Kritik capability patterns (partial match)
    CRITICAL_CAPABILITIES = [
        'inject',
        'hook',
        'keylog',
        'screen capture',
        'encrypt',
        'ransom',
        'delete shadow',
        'disable security',
        'bypass uac',
        'packed',
        'anti-vm',
        'anti-debug',
        'anti-sandbox',
        'obfuscate',
        'download',
        'upload',
        'c2',
        'beacon',
        'backdoor',
        'rootkit',
        'credential',
        'password',
        'token',
        'privilege',
        'elevate',
        'persist',
        'autorun',
        'service',
        'scheduled task',
        'registry run',
        'startup',
        'dll injection',
        'process hollowing',
        'thread hijack',
        'shellcode',
        'reflective',
    ]
    
    # Namespace severity scores
    NAMESPACE_SCORES = {
        'anti-analysis': 15,
        'collection': 10,
        'command-and-control': 20,
        'credential-access': 20,
        'defense-evasion': 15,
        'exfiltration': 20,
        'impact': 25,
        'lateral-movement': 20,
        'persistence': 15,
        'privilege-escalation': 20,
        'execution': 10,
        'discovery': 5,
        'communication': 10,
        'data-manipulation': 10,
        'file-system': 5,
        'host-interaction': 5,
        'load-code': 10,
        'memory': 10,
        'process': 10,
    }
    
    def __init__(self):
        from ..tools.external_tool_runner import get_tool_runner
        self.tool_runner = get_tool_runner()
    
    def analyze(self, file_path: str) -> CapaAnalysisResult:
        """
        capa ile dosyayı analiz et.
        
        Args:
            file_path: Analiz edilecek dosya
            
        Returns:
            CapaAnalysisResult
        """
        logger.info(f"[CAPA] Analyzing: {file_path}")
        
        if not self.tool_runner.is_available('capa'):
            logger.warning("[CAPA] capa not installed")
            return CapaAnalysisResult(
                success=False,
                error_message="capa not available - install from https://github.com/mandiant/capa/releases"
            )
        
        # Run capa with JSON output
        result = self.tool_runner.run_capa(file_path, output_format='json')
        
        if not result.success:
            return CapaAnalysisResult(
                success=False,
                error_message=result.error_message or result.stderr[:500],
                raw_output=result.stderr
            )
        
        # Parse output
        return self._parse_capa_output(result.stdout, result.parsed_output)
    
    def _parse_capa_output(self, raw_output: str, parsed: Optional[Dict]) -> CapaAnalysisResult:
        """capa JSON çıktısını parse et."""
        capabilities = []
        attack_techniques = []
        mbc_behaviors = []
        
        try:
            data = parsed or json.loads(raw_output)
            
            # Parse rules/capabilities
            rules = data.get('rules', {})
            
            for rule_name, rule_data in rules.items():
                meta = rule_data.get('meta', {})
                
                # ATT&CK IDs
                attack_ids = []
                for attack in meta.get('attack', []):
                    attack_id = attack.get('id', '')
                    if attack_id:
                        attack_ids.append(attack_id)
                        attack_techniques.append({
                            'id': attack_id,
                            'tactic': attack.get('tactic', ''),
                            'technique': attack.get('technique', ''),
                            'subtechnique': attack.get('subtechnique', ''),
                            'capability': rule_name
                        })
                
                # MBC IDs (Malware Behavior Catalog)
                mbc_ids = []
                for mbc in meta.get('mbc', []):
                    mbc_id = mbc.get('id', '')
                    if mbc_id:
                        mbc_ids.append(mbc_id)
                        mbc_behaviors.append({
                            'id': mbc_id,
                            'objective': mbc.get('objective', ''),
                            'behavior': mbc.get('behavior', ''),
                            'method': mbc.get('method', ''),
                            'capability': rule_name
                        })
                
                # Create capability object
                cap = Capability(
                    name=rule_name,
                    namespace=meta.get('namespace', ''),
                    attack_ids=attack_ids,
                    mbc_ids=mbc_ids,
                    scope=meta.get('scope', 'function'),
                    matches=len(rule_data.get('matches', [])),
                    description=meta.get('description', '')
                )
                capabilities.append(cap)
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(capabilities)
            
            # Generate summary
            summary = self._generate_summary(capabilities, attack_techniques, mbc_behaviors)
            
            return CapaAnalysisResult(
                success=True,
                capabilities=capabilities,
                attack_techniques=attack_techniques,
                mbc_behaviors=mbc_behaviors,
                threat_score=threat_score,
                summary=summary,
                raw_output=raw_output[:100000]  # Limit size
            )
            
        except json.JSONDecodeError as e:
            logger.error(f"[CAPA] JSON parse error: {e}")
            return CapaAnalysisResult(
                success=False,
                error_message=f"JSON parse error: {e}",
                raw_output=raw_output[:5000]
            )
        except Exception as e:
            logger.error(f"[CAPA] Parse error: {e}")
            return CapaAnalysisResult(
                success=False,
                error_message=f"Parse error: {e}",
                raw_output=raw_output[:5000]
            )
    
    def _calculate_threat_score(self, capabilities: List[Capability]) -> int:
        """Capability'lere göre threat score hesapla."""
        score = 0
        seen_namespaces = set()
        
        for cap in capabilities:
            namespace_lower = cap.namespace.lower()
            
            # Namespace-based scoring (only count each namespace once at full value)
            base_namespace = namespace_lower.split('/')[0]
            
            if base_namespace not in seen_namespaces:
                # Get namespace score
                for ns, ns_score in self.NAMESPACE_SCORES.items():
                    if ns in base_namespace:
                        score += ns_score
                        seen_namespaces.add(base_namespace)
                        break
            else:
                # Reduced score for additional capabilities in same namespace
                for ns, ns_score in self.NAMESPACE_SCORES.items():
                    if ns in base_namespace:
                        score += ns_score // 3
                        break
            
            # Critical capability keyword check
            name_lower = cap.name.lower()
            for critical in self.CRITICAL_CAPABILITIES:
                if critical in name_lower:
                    score += 5
                    break
            
            # ATT&CK technique bonus
            score += len(cap.attack_ids) * 2
            
            # MBC behavior bonus  
            score += len(cap.mbc_ids) * 2
        
        return min(score, 100)
    
    def _generate_summary(self, capabilities: List[Capability], 
                          attack_techniques: List[Dict],
                          mbc_behaviors: List[Dict]) -> str:
        """Analiz özeti oluştur."""
        if not capabilities:
            return "No capabilities detected by capa"
        
        lines = [f"capa detected {len(capabilities)} capabilities:"]
        
        # Group by base namespace
        namespaces: Dict[str, int] = {}
        for cap in capabilities:
            ns = cap.namespace.split('/')[0] if '/' in cap.namespace else cap.namespace
            if not ns:
                ns = 'other'
            namespaces[ns] = namespaces.get(ns, 0) + 1
        
        # Sort by count descending
        sorted_ns = sorted(namespaces.items(), key=lambda x: x[1], reverse=True)
        
        for ns, count in sorted_ns[:8]:
            risk_indicator = "⚠️" if ns.lower() in [x.lower() for x in self.HIGH_RISK_NAMESPACES] else "•"
            lines.append(f"  {risk_indicator} {ns}: {count}")
        
        if len(sorted_ns) > 8:
            lines.append(f"  ... and {len(sorted_ns) - 8} more namespaces")
        
        # ATT&CK techniques summary
        if attack_techniques:
            unique_attacks = {}
            for t in attack_techniques:
                tid = t['id']
                if tid and tid not in unique_attacks:
                    unique_attacks[tid] = t
            
            lines.append(f"\nATT&CK Coverage: {len(unique_attacks)} techniques")
            
            # Group by tactic
            tactics: Dict[str, List[str]] = {}
            for tid, t in unique_attacks.items():
                tactic = t.get('tactic', 'unknown')
                if tactic not in tactics:
                    tactics[tactic] = []
                tactics[tactic].append(tid)
            
            for tactic, tids in sorted(tactics.items())[:5]:
                lines.append(f"  [{tactic}] {', '.join(tids[:5])}")
        
        # MBC summary
        if mbc_behaviors:
            unique_mbc = set(b['id'] for b in mbc_behaviors if b['id'])
            lines.append(f"\nMBC Behaviors: {len(unique_mbc)}")
        
        # Highlight critical findings
        critical_caps = [c for c in capabilities 
                        if any(crit in c.name.lower() for crit in self.CRITICAL_CAPABILITIES)]
        
        if critical_caps:
            lines.append("\n🚨 Critical Capabilities:")
            for cap in critical_caps[:5]:
                lines.append(f"  • {cap.name}")
        
        return '\n'.join(lines)
    
    def get_attack_matrix(self, capabilities: List[Capability]) -> Dict[str, List[str]]:
        """Get ATT&CK matrix coverage from capabilities."""
        matrix: Dict[str, List[str]] = {}
        
        for cap in capabilities:
            for attack_id in cap.attack_ids:
                # Extract tactic from capability namespace if available
                tactic = 'unknown'
                ns_lower = cap.namespace.lower()
                
                tactic_mapping = {
                    'execution': 'Execution',
                    'persistence': 'Persistence',
                    'privilege-escalation': 'Privilege Escalation',
                    'defense-evasion': 'Defense Evasion',
                    'credential-access': 'Credential Access',
                    'discovery': 'Discovery',
                    'lateral-movement': 'Lateral Movement',
                    'collection': 'Collection',
                    'command-and-control': 'Command and Control',
                    'exfiltration': 'Exfiltration',
                    'impact': 'Impact',
                }
                
                for key, value in tactic_mapping.items():
                    if key in ns_lower:
                        tactic = value
                        break
                
                if tactic not in matrix:
                    matrix[tactic] = []
                if attack_id not in matrix[tactic]:
                    matrix[tactic].append(attack_id)
        
        return matrix
