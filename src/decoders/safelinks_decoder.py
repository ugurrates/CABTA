"""
Author: Ugur Ates
Office SafeLinks URL Decoder
Integrated from Sooty
"""

import urllib.parse
import re
import logging

logger = logging.getLogger(__name__)
def decode_safelinks_url(url: str) -> dict:
    """
    Decode Microsoft Office SafeLinks URL.
    
    SafeLinks rewrites URLs in Office 365 emails for security.
    This decoder extracts the original URL.
    
    Args:
        url: SafeLinks-encoded URL
    
    Returns:
        Dict with original URL and decoding info
    
    Example:
        Input:  https://nam12.safelinks.protection.outlook.com/?url=http%3A%2F%2Fexample.com...
        Output: {'original_url': 'http://example.com', 'decoded': True}
    """
    result = {
        'original_url': url,
        'decoded': False,
        'safelinks': False
    }
    
    try:
        # Check if it's a SafeLinks URL
        if 'safelinks.protection.outlook.com' not in url.lower():
            return result
        
        result['safelinks'] = True
        
        # Extract URL parameter
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if 'url' in params:
            encoded_url = params['url'][0]
            decoded_url = urllib.parse.unquote(encoded_url)
            
            result['original_url'] = decoded_url
            result['decoded'] = True
            
            logger.info(f"[SAFELINKS] Decoded URL successfully")
        
    except Exception as e:
        logger.error(f"[SAFELINKS] Decoding failed: {e}")
        result['error'] = str(e)
    
    return result
def batch_decode_safelinks(urls: list) -> list:
    """
    Batch decode multiple SafeLinks URLs.
    
    Args:
        urls: List of URLs to decode
    
    Returns:
        List of decode results
    """
    results = []
    for url in urls:
        result = decode_safelinks_url(url)
        results.append(result)
    
    return results
