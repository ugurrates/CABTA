"""
Author: Ugur AtesConfiguration loader for Blue Team Assistant."""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)
def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to config.yaml file. If None, searches standard locations.
    
    Returns:
        Dict containing configuration
    
    Example:
        >>> config = load_config()
        >>> vt_key = config['api_keys']['virustotal']
    """
    # Standard config locations
    search_paths = [
        config_path,
        os.environ.get('BTA_CONFIG'),
        'config.yaml',
        Path.home() / '.blue-team-assistant' / 'config.yaml',
        Path(__file__).parent.parent.parent / 'config.yaml'
    ]
    
    config_file = None
    for path in search_paths:
        if path and Path(path).exists():
            config_file = Path(path)
            logger.info(f"[CONFIG] Loading from: {config_file}")
            break
    
    if not config_file:
        logger.warning("[CONFIG] No config file found, using defaults")
        return get_default_config()
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            return merge_with_defaults(config)
    except Exception as e:
        logger.error(f"[CONFIG] Failed to load config: {e}")
        return get_default_config()
def get_default_config() -> Dict[str, Any]:
    """
    Get default configuration with environment variable fallbacks.
    
    Returns:
        Default configuration dict
    """
    return {
        'api_keys': {
            # Core sources
            'virustotal': os.environ.get('VIRUSTOTAL_API_KEY', ''),
            'abuseipdb': os.environ.get('ABUSEIPDB_API_KEY', ''),
            'shodan': os.environ.get('SHODAN_API_KEY', ''),
            'alienvault': os.environ.get('ALIENVAULT_API_KEY', ''),
            
            # Extended sources
            'greynoise': os.environ.get('GREYNOISE_API_KEY', ''),
            'censys_id': os.environ.get('CENSYS_API_ID', ''),
            'censys_secret': os.environ.get('CENSYS_API_SECRET', ''),
            'pulsedive': os.environ.get('PULSEDIVE_API_KEY', ''),
            'criminalip': os.environ.get('CRIMINALIP_API_KEY', ''),
            'ipqualityscore': os.environ.get('IPQS_API_KEY', ''),
            'phishtank': os.environ.get('PHISHTANK_API_KEY', ''),
            
            # Sandbox sources
            'hybridanalysis': os.environ.get('HYBRID_API_KEY', ''),
            'anyrun': os.environ.get('ANYRUN_API_KEY', ''),
            'triage': os.environ.get('TRIAGE_API_KEY', ''),
            'threatzone': os.environ.get('THREATZONE_API_KEY', ''),
            'joesandbox': os.environ.get('JOESANDBOX_API_KEY', ''),
            
            # Legacy
            'ip2proxy': os.environ.get('IP2PROXY_API_KEY', ''),
            
            # LLM (optional)
            'anthropic': os.environ.get('ANTHROPIC_API_KEY', '')
        },
        'rate_limits': {
            'virustotal': {'requests_per_minute': 4},
            'abuseipdb': {'requests_per_day': 1000},
            'shodan': {'requests_per_month': 100},
            'concurrent_requests': 5
        },
        'timeouts': {
            'api_timeout': 30,
            'sandbox_timeout': 300
        },
        'scoring': {
            'clean_threshold': 5,
            'low_risk_threshold': 30,
            'suspicious_threshold': 60,
            'malicious_threshold': 80
        },
        'analysis': {
            'max_archive_depth': 3,
            'max_file_size_mb': 100,
            'enable_sandboxes': False,
            'enable_llm': True
        },
        'output': {
            'report_format': 'html',
            'save_reports': True,
            'reports_dir': './reports'
        },
        'cache': {
            'enabled': True,
            'db_dir': str(Path.home() / '.blue-team-assistant' / 'cache'),
            'ioc_ttl_hours': 24,
            'analysis_max_age_days': 30,
        },
        'web': {
            'host': '0.0.0.0',
            'port': 8080,
            'debug': False,
            'max_upload_mb': 100,
        },
        'logging': {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        }
    }
def merge_with_defaults(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge user config with defaults.
    
    Args:
        config: User configuration
    
    Returns:
        Merged configuration
    """
    defaults = get_default_config()
    
    def deep_merge(base: Dict, override: Dict) -> Dict:
        """Recursively merge two dicts."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    return deep_merge(defaults, config)
def get_api_key(config: Dict[str, Any], service: str) -> Optional[str]:
    """
    Get API key for a service.
    
    Args:
        config: Configuration dict
        service: Service name (virustotal, abuseipdb, etc.)
    
    Returns:
        API key or None if not configured
    """
    key = config.get('api_keys', {}).get(service, '')
    return key if key else None
def is_service_enabled(config: Dict[str, Any], service: str) -> bool:
    """
    Check if a service is enabled (has valid API key).
    
    Args:
        config: Configuration dict
        service: Service name
    
    Returns:
        True if service has API key configured
    """
    key = get_api_key(config, service)
    return key is not None and len(key) > 0
