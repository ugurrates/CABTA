"""
Author: Ugur AtesAPI Key validator helper."""

from typing import Optional
def is_valid_api_key(key: Optional[str]) -> bool:
    """
    Check if API key is valid and usable.
    
    Args:
        key: API key string or None
    
    Returns:
        True if key is valid, False otherwise
    
    Examples:
        >>> is_valid_api_key("abc123")
        True
        >>> is_valid_api_key("")
        False
        >>> is_valid_api_key(None)
        False
        >>> is_valid_api_key("BURAYA_API_KEY")
        False
        >>> is_valid_api_key("YOUR_API_KEY")
        False
    """
    if not key:
        return False
    
    # Remove whitespace
    key = key.strip()
    
    # Check if empty after strip
    if not key:
        return False
    
    # Check for placeholder text
    placeholder_patterns = [
        'BURAYA_API_KEY',
        'YOUR_API_KEY',
        'API_KEY_HERE',
        'INSERT_KEY',
        'REPLACE_ME',
        'CHANGE_THIS',
        'XXX',
        'YYY',
        'ZZZ',
        'TEST',
        'EXAMPLE'
    ]
    
    key_upper = key.upper()
    for pattern in placeholder_patterns:
        if pattern in key_upper:
            return False
    
    # Check minimum length (most API keys are at least 10 chars)
    if len(key) < 10:
        return False
    
    return True
def get_valid_key(api_keys: dict, key_name: str) -> Optional[str]:
    """
    Get API key from dict if valid.
    
    Args:
        api_keys: Dictionary of API keys
        key_name: Name of the key to retrieve
    
    Returns:
        Valid API key or None
    
    Examples:
        >>> keys = {'virustotal': 'abc123def456ghi789'}
        >>> get_valid_key(keys, 'virustotal')
        'abc123def456ghi789'
        >>> get_valid_key(keys, 'shodan')
        None
    """
    key = api_keys.get(key_name)
    return key if is_valid_api_key(key) else None
