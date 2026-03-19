"""
Author: Ugur Ates
Configuration and health check endpoints.
"""

import logging
import platform
import sys
from datetime import datetime, timezone

import aiohttp
from fastapi import APIRouter, Query, Request

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get('/health')
async def health():
    """Health check endpoint."""
    return {
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '2.0.0',
    }


@router.get('/info')
async def info():
    """System information."""
    return {
        'app': 'Blue Team Assistant',
        'version': '2.0.0',
        'python': sys.version,
        'platform': platform.platform(),
    }


@router.get('/tools')
async def tool_status():
    """Check status of external analysis tools."""
    tools = {}

    # Check yara
    try:
        import yara
        tools['yara'] = {'available': True, 'version': yara.YARA_VERSION}
    except ImportError:
        tools['yara'] = {'available': False}

    # Check pefile
    try:
        import pefile
        tools['pefile'] = {'available': True}
    except ImportError:
        tools['pefile'] = {'available': False}

    # Check oletools
    try:
        import oletools
        tools['oletools'] = {'available': True}
    except ImportError:
        tools['oletools'] = {'available': False}

    # Check ssdeep
    try:
        import ssdeep
        tools['ssdeep'] = {'available': True}
    except ImportError:
        tools['ssdeep'] = {'available': False}

    return {'tools': tools}


@router.get('/settings')
async def get_settings(request: Request):
    """Return current application settings."""
    from pathlib import Path
    import json

    project_root = Path(__file__).parent.parent.parent.parent
    config_file = project_root / 'config.yaml'

    config = {}
    try:
        import yaml
        if config_file.is_file():
            with open(config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
    except ImportError:
        pass
    except Exception:
        pass

    # Mask API keys for security
    safe_config = dict(config)
    if 'api_keys' in safe_config:
        masked = {}
        for k, v in safe_config['api_keys'].items():
            if v and isinstance(v, str) and len(v) > 8:
                masked[k] = v[:4] + '*' * (len(v) - 8) + v[-4:]
            else:
                masked[k] = v
        safe_config['api_keys'] = masked

    return safe_config


@router.post('/settings')
async def save_settings(request: Request):
    """Save application settings to config.yaml."""
    from pathlib import Path

    project_root = Path(__file__).parent.parent.parent.parent
    config_file = project_root / 'config.yaml'

    body = await request.json()

    # Load existing config to preserve keys that aren't being updated
    existing = {}
    try:
        import yaml
        if config_file.is_file():
            with open(config_file, 'r', encoding='utf-8') as f:
                existing = yaml.safe_load(f) or {}
    except ImportError:
        return {'error': 'PyYAML not installed'}, 500
    except Exception:
        pass

    # Merge sections
    for key in ('llm', 'agent', 'sandbox', 'mcp_servers'):
        if key in body:
            existing[key] = body[key]

    # Handle API keys - only update keys that are actually provided (not masked)
    if 'api_keys' in body:
        if 'api_keys' not in existing:
            existing['api_keys'] = {}
        for k, v in body['api_keys'].items():
            if v and '*' not in str(v):
                existing['api_keys'][k] = v

    try:
        import yaml
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(existing, f, default_flow_style=False, allow_unicode=True)
        logger.info("[CONFIG] Settings saved to %s", config_file)
        return {'status': 'saved', 'message': 'Settings saved. Restart the server for changes to take full effect.'}
    except Exception as exc:
        logger.error("[CONFIG] Failed to save settings: %s", exc)
        return {'error': str(exc)}


@router.get('/ollama-models')
async def list_ollama_models(
    endpoint: str = Query(default='http://localhost:11434'),
):
    """Proxy endpoint to list locally available Ollama models.

    Calls Ollama ``/api/tags`` and returns the model list so the frontend
    settings page can offer a dropdown selector without CORS issues.
    """
    base = endpoint.rstrip('/')
    try:
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f'{base}/api/tags') as resp:
                if resp.status != 200:
                    return {'models': [], 'error': f'Ollama returned HTTP {resp.status}'}
                data = await resp.json()
                return {'models': data.get('models', [])}
    except Exception as exc:
        logger.warning("[CONFIG] Failed to list Ollama models at %s: %s", base, exc)
        return {'models': [], 'error': str(exc)}


@router.get('/ollama-health')
async def ollama_health(
    endpoint: str = Query(default='http://localhost:11434'),
):
    """Check if Ollama is running and the configured model is available.

    Returns connectivity status, running model, and available models
    so the frontend can show a clear diagnostic message.
    """
    base = endpoint.rstrip('/')
    result = {
        'ollama_running': False,
        'endpoint': base,
        'configured_model': '',
        'model_available': False,
        'available_models': [],
        'error': None,
    }

    # Read configured model from config
    try:
        from pathlib import Path
        import yaml
        project_root = Path(__file__).parent.parent.parent.parent
        config_file = project_root / 'config.yaml'
        if config_file.is_file():
            with open(config_file, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f) or {}
            result['configured_model'] = cfg.get('llm', {}).get('ollama_model', 'llama3.1:8b')
        else:
            result['configured_model'] = 'llama3.1:8b'
    except Exception:
        result['configured_model'] = 'llama3.1:8b'

    # Check Ollama connectivity
    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f'{base}/api/tags') as resp:
                if resp.status == 200:
                    result['ollama_running'] = True
                    data = await resp.json()
                    models = data.get('models', [])
                    result['available_models'] = [
                        m.get('name', '') for m in models
                    ]
                    # Check if configured model is available
                    configured = result['configured_model']
                    for m in models:
                        name = m.get('name', '')
                        # Match with or without :tag suffix
                        if name == configured or name.startswith(configured.split(':')[0]):
                            result['model_available'] = True
                            break
                else:
                    result['error'] = f'Ollama returned HTTP {resp.status}'
    except Exception as exc:
        result['error'] = f'Cannot connect to Ollama: {exc}'

    return result
