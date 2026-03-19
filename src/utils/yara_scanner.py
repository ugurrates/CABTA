"""
Author: Ugur AtesYARA rule scanning for malware detection."""

import logging
from typing import Dict, List
from pathlib import Path

logger = logging.getLogger(__name__)

# Check if yara-python is available
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("[YARA] yara-python not installed. YARA scanning disabled.")
class YaraScanner:
    """
    YARA rule scanner for malware detection.
    
    Features:
    - Scan files against YARA rules
    - Built-in common malware signatures
    - Custom rule support
    """
    
    # Built-in YARA rules for common malware families
    BUILTIN_RULES = """
rule Emotet_Strings
{
    meta:
        description = "Detects Emotet malware strings"
        author = "SOC Team"
    strings:
        $s1 = "InternetOpenUrlW" wide ascii
        $s2 = "InternetReadFile" wide ascii
        $s3 = "cmd.exe /c" wide ascii
        $s4 = "WScript.Shell" wide ascii
    condition:
        3 of them
}

rule QakBot_Network
{
    meta:
        description = "Detects QakBot network indicators"
    strings:
        $n1 = "/%d/%s.png" wide ascii
        $n2 = "/%d/%d/" wide ascii
        $n3 = "Cookie:" wide ascii
    condition:
        2 of them
}

rule Cobalt_Strike
{
    meta:
        description = "Detects Cobalt Strike beacon"
    strings:
        $s1 = "%c%c%c%c%c%c%c%c%cMSSE-" ascii
        $s2 = "StartBrowser" ascii
        $s3 = "runasadmin" ascii
        $s4 = "postex" ascii
    condition:
        2 of them
}

rule Metasploit_Meterpreter
{
    meta:
        description = "Detects Meterpreter payload"
    strings:
        $s1 = "metsrv.dll" ascii
        $s2 = "METERPRETER_TRANSPORT" ascii
        $s3 = "ext_server" ascii
    condition:
        any of them
}

rule Generic_Ransomware
{
    meta:
        description = "Detects generic ransomware indicators"
    strings:
        $r1 = ".locked" ascii
        $r2 = ".encrypted" ascii
        $r3 = "bitcoin" nocase
        $r4 = "ransom" nocase
        $r5 = "decrypt" nocase
        $r6 = "HOW_TO_RESTORE" ascii
    condition:
        3 of them
}

rule Suspicious_PowerShell
{
    meta:
        description = "Detects suspicious PowerShell patterns"
    strings:
        $p1 = "-EncodedCommand" nocase
        $p2 = "IEX" nocase
        $p3 = "Invoke-Expression" nocase
        $p4 = "DownloadString" nocase
        $p5 = "FromBase64String" nocase
    condition:
        2 of them
}

rule Packer_UPX
{
    meta:
        description = "Detects UPX packer"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
    condition:
        any of them
}

rule Anti_Debug
{
    meta:
        description = "Detects anti-debug techniques"
    strings:
        $a1 = "IsDebuggerPresent" ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "OutputDebugString" ascii
        $a4 = "NtQueryInformationProcess" ascii
    condition:
        2 of them
}

rule Code_Injection
{
    meta:
        description = "Detects code injection indicators"
    strings:
        $i1 = "CreateRemoteThread" ascii
        $i2 = "VirtualAllocEx" ascii
        $i3 = "WriteProcessMemory" ascii
        $i4 = "NtUnmapViewOfSection" ascii
    condition:
        2 of them
}
"""
    
    def __init__(self, rules_path: str = None):
        """
        Initialize YARA scanner.

        Args:
            rules_path: Path to a custom YARA rules file **or directory**.
                        When a directory is given, each ``.yar`` / ``.yara``
                        file is compiled individually so that one broken file
                        does not prevent the others from loading.
        """
        self.rules_path = rules_path
        self.rules = None
        self._compilation_status: Dict = {
            'total': 0, 'compiled': 0, 'failed': {},
        }

        if not YARA_AVAILABLE:
            logger.warning("[YARA] Scanner disabled - yara-python not installed")
            return

        try:
            rules_p = Path(rules_path) if rules_path else None

            if rules_p and rules_p.is_dir():
                # --- Directory of rule files: per-file isolation ---
                self.rules = self._compile_rules_dir(rules_p)
            elif rules_p and rules_p.is_file():
                # Single custom file
                self.rules = yara.compile(filepath=str(rules_p))
                self._compilation_status = {
                    'total': 1, 'compiled': 1, 'failed': {},
                }
                logger.info(f"[YARA] Loaded custom rules from {rules_path}")
            else:
                # Fallback: built-in rules
                self.rules = yara.compile(source=self.BUILTIN_RULES)
                logger.info("[YARA] Loaded built-in rules")
        except Exception as e:
            logger.error(f"[YARA] Failed to compile rules: {e}")

    def _compile_rules_dir(self, rules_dir: Path):
        """Compile all rule files in *rules_dir* with per-file error isolation."""
        rule_files: Dict[str, str] = {}
        for f in rules_dir.rglob('*'):
            if f.suffix in ('.yar', '.yara') and f.is_file():
                namespace = f.stem
                rule_files[namespace] = str(f)

        if not rule_files:
            logger.warning(f"[YARA] No rule files in {rules_dir}")
            return yara.compile(source=self.BUILTIN_RULES)

        valid: Dict[str, str] = {}
        failed: Dict[str, str] = {}

        for ns, path in rule_files.items():
            try:
                yara.compile(filepath=path)
                valid[ns] = path
            except yara.SyntaxError as e:
                failed[ns] = str(e)
                logger.warning(f"[YARA] Skipping '{ns}': {e}")
            except Exception as e:
                failed[ns] = str(e)
                logger.warning(f"[YARA] Skipping '{ns}': {e}")

        self._compilation_status = {
            'total': len(rule_files),
            'compiled': len(valid),
            'failed': failed,
        }

        if not valid:
            logger.error("[YARA] All rule files failed, falling back to built-in rules")
            return yara.compile(source=self.BUILTIN_RULES)

        if failed:
            logger.warning(
                f"[YARA] Compiled {len(valid)}/{len(rule_files)} files "
                f"({len(failed)} skipped)"
            )
        else:
            logger.info(f"[YARA] Compiled all {len(valid)} rule files")

        return yara.compile(filepaths=valid)

    def get_compilation_status(self) -> Dict:
        """Return per-file compilation status for diagnostics."""
        return self._compilation_status
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan file with YARA rules.
        
        Args:
            file_path: Path to file to scan
        
        Returns:
            List of matched rules with metadata
        """
        if not YARA_AVAILABLE or not self.rules:
            return []
        
        matches = []
        
        try:
            yara_matches = self.rules.match(file_path)
            
            for match in yara_matches:
                match_info = {
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }
                
                # Get matched strings (YARA 4.x API)
                for string_match in match.strings[:5]:
                    identifier = getattr(string_match, 'identifier', str(string_match))
                    instances = getattr(string_match, 'instances', [])
                    for inst in instances[:3]:
                        data = getattr(inst, 'matched_data', b'')
                        if isinstance(data, bytes):
                            data = data.decode('utf-8', errors='ignore')
                        match_info['strings'].append({
                            'offset': getattr(inst, 'offset', 0),
                            'identifier': identifier,
                            'data': data[:100],
                        })
                
                matches.append(match_info)
            
            if matches:
                logger.info(f"[YARA] Found {len(matches)} matches in {Path(file_path).name}")
            
        except Exception as e:
            logger.error(f"[YARA] Scan failed: {e}")
        
        return matches
    
    @staticmethod
    def interpret_matches(matches: List[Dict]) -> Dict:
        """
        Interpret YARA matches and provide analysis.
        
        Args:
            matches: List of YARA matches
        
        Returns:
            Analysis dict with severity and recommendations
        """
        if not matches:
            return {
                'severity': 'NONE',
                'malware_families': [],
                'techniques': [],
                'recommendations': []
            }
        
        analysis = {
            'severity': 'LOW',
            'malware_families': [],
            'techniques': [],
            'recommendations': []
        }
        
        # Categorize matches
        malware_rules = ['Emotet', 'QakBot', 'Cobalt', 'Meterpreter', 'Ransomware']
        technique_rules = ['Anti_Debug', 'Code_Injection', 'PowerShell']
        packer_rules = ['Packer']
        
        for match in matches:
            rule_name = match['rule']
            
            # Check malware families
            for malware in malware_rules:
                if malware.lower() in rule_name.lower():
                    analysis['malware_families'].append(malware)
                    analysis['severity'] = 'CRITICAL'
            
            # Check techniques
            for technique in technique_rules:
                if technique.lower() in rule_name.lower():
                    analysis['techniques'].append(rule_name)
                    if analysis['severity'] == 'LOW':
                        analysis['severity'] = 'MEDIUM'
            
            # Check packers
            for packer in packer_rules:
                if packer.lower() in rule_name.lower():
                    analysis['techniques'].append('Packed executable')
        
        # Generate recommendations
        if analysis['malware_families']:
            analysis['recommendations'].append('⚠️ CRITICAL: Known malware family detected')
            analysis['recommendations'].append('🚨 Isolate system immediately')
            analysis['recommendations'].append('🔍 Perform full incident response')
        
        if 'Anti_Debug' in analysis['techniques']:
            analysis['recommendations'].append('⚙️ File uses anti-debugging techniques')
        
        if 'Code_Injection' in analysis['techniques']:
            analysis['recommendations'].append('💉 File may perform code injection')
        
        return analysis
