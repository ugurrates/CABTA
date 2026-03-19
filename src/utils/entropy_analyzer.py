"""
Author: Ugur AtesEntropy analysis utility for malware detection."""

import math
from collections import Counter
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)
class EntropyAnalyzer:
    """
    Comprehensive entropy analysis for malware detection.
    
    Features:
    - Overall file entropy calculation
    - Per-section entropy analysis
    - Byte frequency analysis
    - Entropy distribution interpretation
    - Packing vs encryption detection
    """
    
    # Entropy thresholds and interpretations
    ENTROPY_THRESHOLDS = {
        'plaintext': (0.0, 3.5),      # Text files, uncompressed data
        'low': (3.5, 5.0),             # Low complexity
        'medium': (5.0, 6.5),          # Normal executables
        'high': (6.5, 7.0),            # Compressed data
        'suspicious': (7.0, 7.5),      # Likely packed
        'packed': (7.5, 7.9),          # Definitely packed/encrypted
        'encrypted': (7.9, 8.0)        # Strong encryption/random data
    }
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Formula: H = -Σ(P(x) * log2(P(x)))
        
        Args:
            data: Bytes to analyze
        
        Returns:
            Entropy value (0.0 to 8.0)
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def interpret_entropy(entropy: float) -> Dict:
        """
        Interpret entropy value.
        
        Args:
            entropy: Entropy value (0.0 to 8.0)
        
        Returns:
            Interpretation dict
        """
        interpretation = {
            'value': round(entropy, 2),
            'category': 'unknown',
            'risk_level': 'NONE',
            'description': '',
            'indicators': []
        }
        
        # Determine category
        for category, (min_val, max_val) in EntropyAnalyzer.ENTROPY_THRESHOLDS.items():
            if min_val <= entropy < max_val:
                interpretation['category'] = category
                break
        
        # Set risk level and description
        if interpretation['category'] == 'plaintext':
            interpretation['risk_level'] = 'NONE'
            interpretation['description'] = 'Plain text or uncompressed data'
        
        elif interpretation['category'] == 'low':
            interpretation['risk_level'] = 'NONE'
            interpretation['description'] = 'Low complexity data'
        
        elif interpretation['category'] == 'medium':
            interpretation['risk_level'] = 'NONE'
            interpretation['description'] = 'Normal executable code'
        
        elif interpretation['category'] == 'high':
            interpretation['risk_level'] = 'LOW'
            interpretation['description'] = 'Compressed or complex data'
            interpretation['indicators'].append('High complexity data')
        
        elif interpretation['category'] == 'suspicious':
            interpretation['risk_level'] = 'MEDIUM'
            interpretation['description'] = 'Likely packed/obfuscated'
            interpretation['indicators'].append('Entropy in suspicious range')
            interpretation['indicators'].append('Possible packer/obfuscation')
        
        elif interpretation['category'] == 'packed':
            interpretation['risk_level'] = 'HIGH'
            interpretation['description'] = 'Definitely packed or encrypted'
            interpretation['indicators'].append('Very high entropy')
            interpretation['indicators'].append('Strong indicator of packing')
        
        elif interpretation['category'] == 'encrypted':
            interpretation['risk_level'] = 'CRITICAL'
            interpretation['description'] = 'Encrypted or random data'
            interpretation['indicators'].append('Near-maximum entropy')
            interpretation['indicators'].append('Strong encryption or randomization')
        
        return interpretation
    
    @staticmethod
    def analyze_file_entropy(file_path: str) -> Dict:
        """
        Comprehensive file entropy analysis.
        
        Args:
            file_path: Path to file
        
        Returns:
            Entropy analysis results
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Calculate overall entropy
            overall_entropy = EntropyAnalyzer.calculate_entropy(data)
            overall_interpretation = EntropyAnalyzer.interpret_entropy(overall_entropy)
            
            # Analyze entropy distribution (in chunks)
            chunk_size = 1024  # 1KB chunks
            chunk_entropies = []
            
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                if len(chunk) >= 256:  # Only analyze meaningful chunks
                    chunk_entropy = EntropyAnalyzer.calculate_entropy(chunk)
                    chunk_entropies.append(chunk_entropy)
            
            # Calculate statistics
            if chunk_entropies:
                avg_chunk_entropy = sum(chunk_entropies) / len(chunk_entropies)
                max_chunk_entropy = max(chunk_entropies)
                min_chunk_entropy = min(chunk_entropies)
                variance = sum((e - avg_chunk_entropy) ** 2 for e in chunk_entropies) / len(chunk_entropies)
                std_dev = math.sqrt(variance)
            else:
                avg_chunk_entropy = overall_entropy
                max_chunk_entropy = overall_entropy
                min_chunk_entropy = overall_entropy
                std_dev = 0.0
            
            # Byte frequency analysis
            byte_freq = EntropyAnalyzer._analyze_byte_frequency(data)
            
            result = {
                'overall_entropy': overall_entropy,
                'interpretation': overall_interpretation,
                'chunk_analysis': {
                    'average': round(avg_chunk_entropy, 2),
                    'max': round(max_chunk_entropy, 2),
                    'min': round(min_chunk_entropy, 2),
                    'std_dev': round(std_dev, 2),
                    'chunks_analyzed': len(chunk_entropies)
                },
                'byte_frequency': byte_freq,
                'file_size': len(data)
            }
            
            # Determine if suspicious based on distribution
            if std_dev > 0.5:
                result['interpretation']['indicators'].append('High entropy variance (mixed content)')
            
            if max_chunk_entropy > 7.5 and min_chunk_entropy < 5.0:
                result['interpretation']['indicators'].append('Contains both packed and unpacked sections')
            
            logger.info(f"[ENTROPY] File entropy: {overall_entropy:.2f} ({overall_interpretation['category']})")
            
            return result
        
        except Exception as e:
            logger.error(f"[ENTROPY] Analysis failed: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def _analyze_byte_frequency(data: bytes) -> Dict:
        """
        Analyze byte frequency distribution.
        
        Args:
            data: Bytes to analyze
        
        Returns:
            Frequency analysis results
        """
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Find most/least common bytes
        most_common = byte_counts.most_common(5)
        least_common = [(byte, count) for byte, count in byte_counts.items() if count == min(byte_counts.values())][:5]
        
        # Calculate statistics
        unique_bytes = len(byte_counts)
        
        result = {
            'unique_bytes': unique_bytes,
            'total_bytes': total_bytes,
            'most_common': [
                {
                    'byte': f'0x{byte:02x}',
                    'count': count,
                    'percentage': round(count / total_bytes * 100, 2)
                }
                for byte, count in most_common
            ],
            'least_common_count': len(least_common),
            'uniformity': round(unique_bytes / 256 * 100, 2)  # Percentage of all possible bytes used
        }
        
        # Interpretation
        if unique_bytes < 50:
            result['interpretation'] = 'Low diversity (possible simple encoding)'
        elif unique_bytes < 200:
            result['interpretation'] = 'Medium diversity (normal executable)'
        elif unique_bytes >= 250:
            result['interpretation'] = 'High diversity (encrypted/random data)'
        else:
            result['interpretation'] = 'High diversity (complex data)'
        
        return result
    
    @staticmethod
    def compare_section_entropies(sections: List[Dict]) -> Dict:
        """
        Compare entropy across PE sections.
        
        Args:
            sections: List of section dicts with entropy values
        
        Returns:
            Comparison analysis
        """
        if not sections:
            return {}
        
        section_entropies = [(s['name'], s['entropy']) for s in sections if 'entropy' in s]
        
        if not section_entropies:
            return {}
        
        # Find sections with anomalous entropy
        avg_entropy = sum(e for _, e in section_entropies) / len(section_entropies)
        
        high_entropy_sections = [
            {'name': name, 'entropy': entropy, 'deviation': round(entropy - avg_entropy, 2)}
            for name, entropy in section_entropies
            if entropy > 7.0
        ]
        
        low_entropy_sections = [
            {'name': name, 'entropy': entropy}
            for name, entropy in section_entropies
            if entropy < 3.0
        ]
        
        analysis = {
            'average_entropy': round(avg_entropy, 2),
            'max_entropy': round(max(e for _, e in section_entropies), 2),
            'min_entropy': round(min(e for _, e in section_entropies), 2),
            'high_entropy_sections': high_entropy_sections,
            'low_entropy_sections': low_entropy_sections,
            'suspicious': len(high_entropy_sections) > 0
        }
        
        # Generate warnings
        if analysis['suspicious']:
            analysis['warnings'] = [
                f"Section '{s['name']}' has high entropy ({s['entropy']:.2f})"
                for s in high_entropy_sections
            ]
        
        return analysis
