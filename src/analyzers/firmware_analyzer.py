"""
Author: Ugur Ates
Firmware Analyzer - Binary Firmware Analizi.

Entegre Araçlar:
- binwalk: Signature scanning, entropy analysis, extraction
- strings: String extraction
- file: File type detection
"""

import logging
import re
import math
from typing import Dict, List
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)
@dataclass
class FirmwareAnalysisResult:
    """Firmware analiz sonucu."""
    success: bool = False
    file_path: str = ""
    file_size: int = 0
    overall_entropy: float = 0.0
    embedded_files: List[Dict] = field(default_factory=list)
    file_systems: List[str] = field(default_factory=list)
    compression_types: List[str] = field(default_factory=list)
    crypto_signatures: List[str] = field(default_factory=list)
    entropy_regions: List[Dict] = field(default_factory=list)
    high_entropy_regions: List[Dict] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    threat_indicators: List[str] = field(default_factory=list)
    threat_score: int = 0
    raw_outputs: Dict[str, str] = field(default_factory=dict)
class FirmwareAnalyzer:
    """Binary firmware analizi."""
    
    SUSPICIOUS_PATTERNS = [
        (r'busybox', 'Busybox shell'),
        (r'/bin/sh', 'Shell'),
        (r'telnetd', 'Telnet daemon'),
        (r'dropbear', 'SSH server'),
        (r'wget\s+http', 'Remote download'),
        (r'curl\s+http', 'Remote download'),
        (r'/etc/passwd', 'Password file'),
        (r'/etc/shadow', 'Shadow file'),
        (r'backdoor', 'Backdoor reference'),
        (r'rootkit', 'Rootkit reference'),
        (r'iptables', 'Firewall manipulation'),
        (r'nc\s+-', 'Netcat'),
    ]
    
    def __init__(self):
        from ..tools.external_tool_runner import get_tool_runner
        self.tool_runner = get_tool_runner()
    
    def analyze(self, file_path: str) -> FirmwareAnalysisResult:
        """Kapsamlı firmware analizi."""
        logger.info(f"[FIRMWARE] Analyzing: {Path(file_path).name}")
        result = FirmwareAnalysisResult(file_path=file_path)
        
        # File size
        try:
            result.file_size = Path(file_path).stat().st_size
        except:
            pass
        
        # Calculate entropy
        result.overall_entropy = self._calculate_entropy(file_path)
        
        # Binwalk signature scan
        if self.tool_runner.is_available('binwalk'):
            sig_out = self.tool_runner.run_binwalk_signature(file_path)
            if sig_out.success:
                self._parse_signature_output(sig_out.stdout, result)
                result.raw_outputs['signature'] = sig_out.stdout
            
            # Entropy analysis
            ent_out = self.tool_runner.run_binwalk_entropy(file_path)
            if ent_out.success:
                self._parse_entropy_output(ent_out.stdout, result)
                result.raw_outputs['entropy'] = ent_out.stdout
            
            result.success = True
        
        # Strings
        if self.tool_runner.is_available('strings'):
            strings_out = self.tool_runner.run_strings(file_path, min_length=6)
            if strings_out.success:
                self._analyze_strings(strings_out.stdout, result)
                result.raw_outputs['strings'] = strings_out.stdout[:50000]
        
        result.threat_score = self._calculate_score(result)
        return result
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0.0
            length = len(data)
            for count in byte_counts:
                if count > 0:
                    p = count / length
                    entropy -= p * math.log2(p)
            
            return round(entropy, 4)
        except Exception as e:
            logger.warning(f"[FIRMWARE] Entropy calculation failed: {e}")
            return 0.0
    
    def _parse_signature_output(self, output: str, result: FirmwareAnalysisResult):
        """Parse binwalk signature output."""
        fs_patterns = ['squashfs', 'cramfs', 'jffs2', 'ext2', 'ext4', 'ubifs', 'yaffs']
        comp_patterns = ['gzip', 'lzma', 'xz', 'bzip2', 'lz4', 'zstd']
        crypto_patterns = ['aes', 'des', 'rsa', 'sha256', 'md5', 'certificate', 'private key']
        
        for line in output.split('\n'):
            line_lower = line.lower()
            
            # Embedded files
            if re.match(r'\d+\s+0x[0-9A-Fa-f]+', line):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    try:
                        result.embedded_files.append({
                            'offset': int(parts[0]),
                            'hex_offset': parts[1],
                            'description': parts[2][:100]
                        })
                    except:
                        pass
            
            # File systems
            for fs in fs_patterns:
                if fs in line_lower:
                    if fs not in result.file_systems:
                        result.file_systems.append(fs)
            
            # Compression
            for comp in comp_patterns:
                if comp in line_lower:
                    if comp not in result.compression_types:
                        result.compression_types.append(comp)
            
            # Crypto
            for crypto in crypto_patterns:
                if crypto in line_lower:
                    if crypto not in result.crypto_signatures:
                        result.crypto_signatures.append(crypto)
    
    def _parse_entropy_output(self, output: str, result: FirmwareAnalysisResult):
        """Parse binwalk entropy output."""
        for line in output.split('\n'):
            # Format: OFFSET    ENTROPY
            match = re.match(r'(\d+)\s+([\d.]+)', line)
            if match:
                offset = int(match.group(1))
                entropy = float(match.group(2))
                
                region = {'offset': offset, 'entropy': entropy}
                result.entropy_regions.append(region)
                
                # High entropy (>0.9) indicates encryption/compression
                if entropy > 0.9:
                    result.high_entropy_regions.append(region)
    
    def _analyze_strings(self, output: str, result: FirmwareAnalysisResult):
        """Analyze extracted strings."""
        # URLs
        url_pattern = re.compile(r'https?://[^\s<>"\']+')
        for url in url_pattern.findall(output):
            if len(url) > 10 and url not in result.urls:
                result.urls.append(url[:200])
        
        # IPs
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        for ip in ip_pattern.findall(output):
            if ip not in result.ips and not ip.startswith('0.') and ip != '127.0.0.1':
                result.ips.append(ip)
        
        # Suspicious patterns
        for pattern, desc in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, output, re.I):
                if desc not in result.suspicious_strings:
                    result.suspicious_strings.append(desc)
    
    def _calculate_score(self, result: FirmwareAnalysisResult) -> int:
        """Calculate threat score."""
        score = 0
        
        # High entropy regions
        score += min(len(result.high_entropy_regions) * 5, 25)
        
        # Suspicious strings
        score += min(len(result.suspicious_strings) * 5, 30)
        
        # URLs/IPs
        score += min(len(result.urls) * 2, 10)
        score += min(len(result.ips) * 2, 10)
        
        # Overall high entropy (encrypted firmware)
        if result.overall_entropy > 7.5:
            score += 15
            result.threat_indicators.append("High overall entropy - possibly encrypted")
        
        # Crypto signatures
        if result.crypto_signatures:
            score += 10
        
        return min(score, 100)
