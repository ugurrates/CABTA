"""
Author: Ugur Ates
ProofPoint URL Decoder
Integrated from Sooty - Modified version of ProofPoint's code
"""

import re
import urllib.parse
import logging

logger = logging.getLogger(__name__)
def decode_proofpoint_url(url: str) -> dict:
    """
    Decode ProofPoint URL to reveal original URL.
    
    ProofPoint rewrites URLs for email security. This decoder
    extracts the original URL from the ProofPoint wrapper.
    
    Args:
        url: ProofPoint-encoded URL
    
    Returns:
        Dict with original URL and decoding info
    
    Example:
        Input:  https://urldefense.proofpoint.com/v2/url?u=http-3A__...
        Output: {'original_url': 'http://example.com', 'decoded': True}
    """
    result = {
        'original_url': url,
        'decoded': False,
        'proofpoint': False,
        'version': None
    }
    
    try:
        # Check if it's a ProofPoint URL
        if 'urldefense.proofpoint.com' not in url.lower() and 'urldefense.com' not in url.lower():
            return result
        
        result['proofpoint'] = True
        
        # Extract version (v1, v2, v3)
        version_match = re.search(r'/v([123])/', url)
        if version_match:
            result['version'] = f"v{version_match.group(1)}"
        
        # Extract URL parameter
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if 'u' in params:
            encoded_url = params['u'][0]
            
            # Decode based on version
            if result['version'] in ['v1', 'v2']:
                decoded = _decode_v2(encoded_url)
            elif result['version'] == 'v3':
                decoded = _decode_v3(encoded_url)
            else:
                decoded = encoded_url
            
            result['original_url'] = decoded
            result['decoded'] = True
            
            logger.info(f"[PROOFPOINT] Decoded URL successfully")
        
    except Exception as e:
        logger.error(f"[PROOFPOINT] Decoding failed: {e}")
        result['error'] = str(e)
    
    return result
def _decode_v2(encoded: str) -> str:
    """Decode ProofPoint v2 URL."""
    # Replace ProofPoint encoding
    decoded = encoded.replace('-3A', ':')
    decoded = decoded.replace('-2F', '/')
    decoded = decoded.replace('-2E', '.')
    decoded = decoded.replace('-5F', '_')
    decoded = decoded.replace('_', '/')
    
    return decoded
def _decode_v3(encoded: str) -> str:
    """Decode ProofPoint v3 URL."""
    # v3 uses different encoding
    try:
        decoded = urllib.parse.unquote(encoded)
        return decoded
    except:
        return encoded
def batch_decode_proofpoint(urls: list) -> list:
    """
    Batch decode multiple ProofPoint URLs.
    
    Args:
        urls: List of URLs to decode
    
    Returns:
        List of decode results
    """
    results = []
    for url in urls:
        result = decode_proofpoint_url(url)
        results.append(result)
    
    return results
