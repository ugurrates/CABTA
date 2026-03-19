"""
Author: Ugur AtesCommon helper functions for Blue Team Assistant."""

import hashlib
from pathlib import Path
from typing import Dict, Optional, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
def calculate_file_hashes(file_path: str) -> Dict[str, str]:
    """
    Calculate MD5, SHA1, SHA256 hashes of a file.
    
    Args:
        file_path: Path to file
    
    Returns:
        Dict with 'md5', 'sha1', 'sha256' keys
    
    Example:
        >>> hashes = calculate_file_hashes("/path/to/file.exe")
        >>> print(hashes['sha256'])
    """
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }
    except Exception as e:
        logger.error(f"[HASH] Failed to calculate hashes: {e}")
        return {'md5': '', 'sha1': '', 'sha256': ''}
def normalize_score(score: float, max_score: float = 100.0) -> int:
    """
    Normalize score to 0-100 range.
    
    Args:
        score: Input score
        max_score: Maximum possible score
    
    Returns:
        Normalized score (0-100)
    """
    try:
        normalized = (score / max_score) * 100.0
        return max(0, min(100, int(normalized)))
    except:
        return 0
def determine_verdict(score: int) -> str:
    """
    Determine verdict based on threat score.
    
    Args:
        score: Threat score (0-100)
    
    Returns:
        Verdict: 'CLEAN', 'LOW_RISK', 'SUSPICIOUS', 'MALICIOUS'
    
    Example:
        >>> verdict = determine_verdict(85)
        >>> print(verdict)
        'MALICIOUS'
    """
    if score >= 80:
        return 'MALICIOUS'
    elif score >= 60:
        return 'SUSPICIOUS'
    elif score >= 30:
        return 'LOW_RISK'
    else:
        return 'CLEAN'
def format_timestamp(timestamp: Optional[datetime] = None) -> str:
    """
    Format timestamp for reports.
    
    Args:
        timestamp: Datetime object. If None, uses current time.
    
    Returns:
        Formatted timestamp string
    """
    if timestamp is None:
        timestamp = datetime.now()
    
    return timestamp.strftime('%Y-%m-%d %H:%M:%S')
def get_file_info(file_path: str) -> Dict[str, any]:
    """
    Get basic file information.
    
    Args:
        file_path: Path to file
    
    Returns:
        Dict with file metadata
    """
    try:
        path = Path(file_path)
        
        if not path.exists():
            return {'error': 'File not found'}
        
        stat = path.stat()
        
        return {
            'name': path.name,
            'size': stat.st_size,
            'size_mb': round(stat.st_size / (1024 * 1024), 2),
            'extension': path.suffix,
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat()
        }
    except Exception as e:
        logger.error(f"[FILE] Failed to get file info: {e}")
        return {'error': str(e)}
def truncate_string(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate string to maximum length.
    
    Args:
        text: Input string
        max_length: Maximum length
        suffix: Suffix to add when truncated
    
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix
def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe filesystem operations.
    
    Args:
        filename: Original filename
    
    Returns:
        Sanitized filename
    """
    # Remove dangerous characters
    dangerous_chars = '<>:"|?*\\/\0'
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    
    # Limit length
    name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
    if len(name) > 200:
        name = name[:200]
    
    return f"{name}.{ext}" if ext else name
def format_bytes(size_bytes: int) -> str:
    """
    Format bytes to human-readable string.
    
    Args:
        size_bytes: Size in bytes
    
    Returns:
        Formatted string (e.g., '1.5 MB')
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"
def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL.
    
    Args:
        url: URL string
    
    Returns:
        Domain name or None
    
    Example:
        >>> domain = extract_domain_from_url("https://evil.com/malware.exe")
        >>> print(domain)
        'evil.com'
    """
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        return parsed.netloc or None
    except:
        return None
def is_valid_hash(hash_string: str, hash_type: str) -> bool:
    """
    Validate hash format.
    
    Args:
        hash_string: Hash to validate
        hash_type: 'md5', 'sha1', or 'sha256'
    
    Returns:
        True if valid hash format
    """
    import re
    
    patterns = {
        'md5': r'^[a-fA-F0-9]{32}$',
        'sha1': r'^[a-fA-F0-9]{40}$',
        'sha256': r'^[a-fA-F0-9]{64}$'
    }
    
    if hash_type not in patterns:
        return False
    
    return bool(re.match(patterns[hash_type], hash_string))
def merge_dicts(*dicts: Dict) -> Dict:
    """
    Deep merge multiple dictionaries.
    
    Args:
        *dicts: Variable number of dicts to merge
    
    Returns:
        Merged dictionary
    """
    result = {}
    for d in dicts:
        for key, value in d.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = merge_dicts(result[key], value)
            else:
                result[key] = value
    return result
