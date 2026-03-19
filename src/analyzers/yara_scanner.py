"""
Author: Ugur Ates
YARA Scanner Integration
Best Practice: YARA is industry standard for malware pattern matching
Reference: VirusTotal, CrowdStrike, MISP
"""

import os
import logging
from typing import Dict, List
import json

logger = logging.getLogger(__name__)

# Check YARA availability
YARA_AVAILABLE = False
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    logger.warning("[YARA] YARA not available - install with: pip install yara-python")
class YARAScanner:
    """
    YARA rule scanning engine.
    
    Features:
    - Multi-rule scanning
    - Rule compilation and caching
    - Custom rule support
    - Malware family identification
    - IOC extraction from matches
    - Rule performance tracking
    
    Best Practice: Used by enterprise SOCs worldwide
    """
    
    def __init__(self, rules_dir: str = None):
        """
        Initialize YARA scanner.
        
        Args:
            rules_dir: Directory containing YARA rules
        """
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'data', 'yara_rules')
        self.compiled_rules = {}
        self.rule_stats = {}
    
    def compile_rules(self) -> bool:
        """
        Compile all YARA rules in rules directory.

        Each rule file is compiled individually so that a single broken
        rule does not prevent the rest from loading.  Successfully compiled
        rules are merged via YARA's namespace mechanism.

        Returns:
            Success status (True if at least one rule file compiled)
        """
        if not YARA_AVAILABLE:
            logger.error("[YARA] YARA not available")
            return False

        try:
            if not os.path.exists(self.rules_dir):
                logger.warning(f"[YARA] Rules directory not found: {self.rules_dir}")
                return False

            rule_files = {}

            # Find all .yar and .yara files
            for root, dirs, files in os.walk(self.rules_dir):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        rule_path = os.path.join(root, file)
                        namespace = os.path.splitext(file)[0]
                        rule_files[namespace] = rule_path

            if not rule_files:
                logger.warning("[YARA] No rule files found")
                return False

            # --- Per-file compilation with error isolation ---
            valid_files = {}
            failed_files = {}

            for namespace, rule_path in rule_files.items():
                try:
                    # Test-compile each file individually
                    yara.compile(filepath=rule_path)
                    valid_files[namespace] = rule_path
                except yara.SyntaxError as e:
                    failed_files[namespace] = str(e)
                    logger.warning(
                        f"[YARA] Skipping rule file '{namespace}' "
                        f"({os.path.basename(rule_path)}): {e}"
                    )
                except Exception as e:
                    failed_files[namespace] = str(e)
                    logger.warning(
                        f"[YARA] Skipping rule file '{namespace}': {e}"
                    )

            if not valid_files:
                logger.error(
                    f"[YARA] All {len(rule_files)} rule files failed compilation"
                )
                self._compilation_status = {
                    'total': len(rule_files),
                    'compiled': 0,
                    'failed': failed_files,
                }
                return False

            # Compile all valid files together with namespaces
            self.compiled_rules = yara.compile(filepaths=valid_files)

            self._compilation_status = {
                'total': len(rule_files),
                'compiled': len(valid_files),
                'failed': failed_files,
            }

            if failed_files:
                logger.warning(
                    f"[YARA] Compiled {len(valid_files)}/{len(rule_files)} "
                    f"rule files ({len(failed_files)} skipped)"
                )
            else:
                logger.info(
                    f"[YARA] Compiled all {len(valid_files)} rule files"
                )
            return True

        except Exception as e:
            logger.error(f"[YARA] Rule compilation failed: {e}")
            return False

    def get_compilation_status(self) -> Dict:
        """Return per-file compilation status for diagnostics."""
        return getattr(self, '_compilation_status', {
            'total': 0, 'compiled': 0, 'failed': {},
        })
    
    def scan_file(self, file_path: str, timeout: int = 60) -> Dict:
        """
        Scan file with all YARA rules.
        
        Args:
            file_path: Path to file
            timeout: Scan timeout in seconds
        
        Returns:
            Scan results with matches
        """
        result = {
            'file_path': file_path,
            'yara_available': YARA_AVAILABLE,
            'matches': [],
            'match_count': 0,
            'malware_families': [],
            'threat_level': 'clean',
            'iocs': []
        }
        
        if not YARA_AVAILABLE:
            result['error'] = 'YARA not available'
            return result
        
        try:
            # Compile rules if not already done
            if not self.compiled_rules:
                if not self.compile_rules():
                    result['error'] = 'No rules compiled'
                    return result
            
            # Scan file
            matches = self.compiled_rules.match(file_path, timeout=timeout)
            
            result['match_count'] = len(matches)
            
            # Process matches
            for match in matches:
                match_info = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': list(match.tags) if match.tags else [],
                    'meta': dict(match.meta) if match.meta else {},
                    'strings': []
                }
                
                # Extract matched strings (YARA 4.x API)
                for string_match in match.strings[:10]:  # Limit to 10
                    identifier = getattr(string_match, 'identifier', str(string_match))
                    instances = getattr(string_match, 'instances', [])
                    for inst in instances[:3]:  # Limit instances per string
                        data = getattr(inst, 'matched_data', b'')
                        match_info['strings'].append({
                            'offset': getattr(inst, 'offset', 0),
                            'identifier': identifier,
                            'data': data[:100],
                        })
                
                result['matches'].append(match_info)
                
                # Extract malware family from metadata
                if 'family' in match.meta:
                    family = match.meta['family']
                    if family not in result['malware_families']:
                        result['malware_families'].append(family)
                
                # Track rule usage
                rule_name = match.rule
                self.rule_stats[rule_name] = self.rule_stats.get(rule_name, 0) + 1
            
            # Determine threat level
            if result['match_count'] > 0:
                result['threat_level'] = 'malicious'
                if result['match_count'] >= 5:
                    result['threat_level'] = 'highly_malicious'
            
            logger.info(f"[YARA] Scan complete - {result['match_count']} matches")
            
        except Exception as e:
            logger.error(f"[YARA] Scan failed: {e}")
            result['error'] = str(e)
        
        return result
    
    def scan_memory(self, pid: int, timeout: int = 60) -> Dict:
        """
        Scan process memory with YARA rules.
        
        Args:
            pid: Process ID
            timeout: Scan timeout
        
        Returns:
            Scan results
        """
        result = {
            'pid': pid,
            'yara_available': YARA_AVAILABLE,
            'matches': [],
            'match_count': 0
        }
        
        if not YARA_AVAILABLE:
            result['error'] = 'YARA not available'
            return result
        
        try:
            # Compile rules if needed
            if not self.compiled_rules:
                if not self.compile_rules():
                    result['error'] = 'No rules compiled'
                    return result
            
            # Scan process memory
            matches = self.compiled_rules.match(pid=pid, timeout=timeout)
            
            result['match_count'] = len(matches)
            
            for match in matches:
                result['matches'].append({
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': list(match.tags) if match.tags else []
                })
            
            logger.info(f"[YARA] Memory scan complete - {result['match_count']} matches")
            
        except Exception as e:
            logger.error(f"[YARA] Memory scan failed: {e}")
            result['error'] = str(e)
        
        return result
    
    def create_rule(self, rule_name: str, strings: List[str], 
                   condition: str = 'any of them', 
                   meta: Dict = None) -> str:
        """
        Create a YARA rule dynamically.
        
        Args:
            rule_name: Name for the rule
            strings: List of strings to match
            condition: YARA condition
            meta: Metadata dict
        
        Returns:
            YARA rule text
        """
        rule_text = f"rule {rule_name}\n{{\n"
        
        # Add metadata
        if meta:
            rule_text += "    meta:\n"
            for key, value in meta.items():
                rule_text += f'        {key} = "{value}"\n'
        
        # Add strings
        rule_text += "    strings:\n"
        for idx, string in enumerate(strings):
            # Escape special characters
            escaped = string.replace('\\', '\\\\').replace('"', '\\"')
            rule_text += f'        $str{idx} = "{escaped}"\n'
        
        # Add condition
        rule_text += f"    condition:\n        {condition}\n}}\n"
        
        return rule_text
    
    def get_rule_stats(self) -> Dict:
        """
        Get statistics on rule usage.
        
        Returns:
            Rule match statistics
        """
        return {
            'total_scans': sum(self.rule_stats.values()),
            'rules_matched': len(self.rule_stats),
            'top_rules': sorted(
                self.rule_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }
class YARARuleGenerator:
    """
    Automated YARA rule generation.
    
    Best Practice: yarGen-style rule creation
    """
    
    @staticmethod
    def generate_from_strings(strings: List[str], 
                             rule_name: str,
                             malware_family: str = None) -> str:
        """
        Generate YARA rule from extracted strings.
        
        Args:
            strings: Unique strings from malware
            rule_name: Name for rule
            malware_family: Optional family name
        
        Returns:
            YARA rule text
        """
        meta = {
            'description': f'Auto-generated rule for {rule_name}',
            'author': 'Blue Team Assistant',
            'date': '2026-01-06'
        }
        
        if malware_family:
            meta['family'] = malware_family
        
        # Filter strings (min length, uniqueness)
        filtered_strings = []
        for s in strings:
            if len(s) >= 8 and s not in filtered_strings:
                filtered_strings.append(s)
        
        # Limit to top 20 strings
        filtered_strings = filtered_strings[:20]
        
        # Create rule
        scanner = YARAScanner()
        rule = scanner.create_rule(
            rule_name=rule_name,
            strings=filtered_strings,
            condition='3 of them',  # At least 3 matches
            meta=meta
        )
        
        return rule
    
    @staticmethod
    def save_rule(rule_text: str, output_path: str) -> bool:
        """
        Save YARA rule to file.
        
        Args:
            rule_text: Rule content
            output_path: Output file path
        
        Returns:
            Success status
        """
        try:
            with open(output_path, 'w') as f:
                f.write(rule_text)
            
            logger.info(f"[YARA-GEN] Rule saved to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"[YARA-GEN] Save failed: {e}")
            return False
def scan_with_yara(file_path: str, rules_dir: str = None) -> Dict:
    """
    Main entry point for YARA scanning.
    
    Args:
        file_path: File to scan
        rules_dir: Optional rules directory
    
    Returns:
        Scan results
    """
    scanner = YARAScanner(rules_dir=rules_dir)
    return scanner.scan_file(file_path)
def generate_yara_rule(strings: List[str], rule_name: str, 
                       output_path: str = None) -> str:
    """
    Generate YARA rule from strings.
    
    Args:
        strings: Strings to include
        rule_name: Rule name
        output_path: Optional save path
    
    Returns:
        Rule text
    """
    rule = YARARuleGenerator.generate_from_strings(strings, rule_name)
    
    if output_path:
        YARARuleGenerator.save_rule(rule, output_path)
    
    return rule
