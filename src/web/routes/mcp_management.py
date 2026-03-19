"""
Author: Ugur Ates
MCP Server management routes.
"""

import asyncio
import logging
import shutil
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Category metadata (Turkish + English labels) ─────────────────────────
CATEGORY_META: Dict[str, Dict[str, str]] = {
    'analysis': {
        'label': 'Analiz / Analysis',
        'icon': 'bi-search',
        'description_tr': 'Zararli yazilim ve dosya analiz araclari',
    },
    'reverse_engineering': {
        'label': 'Tersine Muhendislik / Reverse Engineering',
        'icon': 'bi-cpu',
        'description_tr': 'Ikili dosya analizi ve tersine muhendislik',
    },
    'sandbox': {
        'label': 'Sandbox',
        'icon': 'bi-box-seam',
        'description_tr': 'Izole ortamda zararli yazilim calistirma',
    },
    'threat_intel': {
        'label': 'Tehdit Istihbarati / Threat Intelligence',
        'icon': 'bi-globe2',
        'description_tr': 'IOC sorgulama ve tehdit istihbarati kaynaklari',
    },
    'detection': {
        'label': 'Tespit Muhendisligi / Detection Engineering',
        'icon': 'bi-shield-exclamation',
        'description_tr': 'Tespit kurali olusturma ve yonetimi',
    },
    'siem': {
        'label': 'SIEM',
        'icon': 'bi-bar-chart-line',
        'description_tr': 'Guvenlik bilgi ve olay yonetimi',
    },
    'edr': {
        'label': 'EDR / XDR',
        'icon': 'bi-pc-display',
        'description_tr': 'Uc nokta tespit ve mudahale',
    },
    'forensics': {
        'label': 'Adli Bilisim / Forensics',
        'icon': 'bi-fingerprint',
        'description_tr': 'Dijital adli bilisim ve olay mudahale',
    },
    'network': {
        'label': 'Ag Guvenligi / Network Security',
        'icon': 'bi-diagram-3',
        'description_tr': 'Ag trafigi analizi ve IDS/IPS',
    },
    'vulnerability': {
        'label': 'Zafiyet Tarama / Vulnerability',
        'icon': 'bi-bug',
        'description_tr': 'Zafiyet tarama ve degerlendirme',
    },
    'osint': {
        'label': 'OSINT',
        'icon': 'bi-binoculars',
        'description_tr': 'Acik kaynak istihbarat toplama',
    },
    'cloud': {
        'label': 'Bulut Guvenligi / Cloud Security',
        'icon': 'bi-cloud-check',
        'description_tr': 'Bulut ortami guvenlik denetimi',
    },
    'utility': {
        'label': 'Yardimci Araclar / Utility',
        'icon': 'bi-wrench-adjustable',
        'description_tr': 'Genel amacli MCP yardimci sunuculari',
    },
}


class MCPServerAdd(BaseModel):
    name: str
    transport: str  # stdio, sse, http
    command: Optional[str] = None
    args: Optional[List[str]] = None
    url: Optional[str] = None
    env: Optional[Dict[str, str]] = None
    token: Optional[str] = None
    description: str = ""


def _get_category_meta() -> Dict[str, Dict[str, str]]:
    """Return category metadata dict."""
    return CATEGORY_META


@router.get('/categories')
async def list_categories():
    """Return all MCP server category metadata."""
    return {"categories": CATEGORY_META}


@router.get('/servers')
async def list_servers(request: Request):
    """List all configured MCP servers.

    Merges pre-configured servers from config.yaml with any servers
    stored in the database, so users see all available servers and
    their connection status.
    """
    store = request.app.state.agent_store
    db_servers = store.list_mcp_connections() if store else []

    # Build a lookup of DB servers by name for quick merging
    db_lookup = {s['name']: s for s in db_servers}

    # Load pre-configured servers from config.yaml
    config = getattr(request.app.state, 'config', None) or {}
    config_servers = config.get('mcp_servers', []) if isinstance(config, dict) else []

    merged: List[dict] = []
    seen_names: set = set()

    # Pre-configured servers first (canonical order)
    for cfg in config_servers:
        name = cfg.get('name', '')
        if not name:
            continue
        entry = dict(cfg)
        # Overlay any DB-side data (e.g. user-modified fields)
        if name in db_lookup:
            db_entry = db_lookup[name]
            entry.update({k: v for k, v in db_entry.items() if v is not None})
        entry.setdefault('source', 'config')
        entry.setdefault('status', 'planned')
        merged.append(entry)
        seen_names.add(name)

    # Append any DB-only servers not in the config
    for s in db_servers:
        if s['name'] not in seen_names:
            s.setdefault('source', 'user')
            s.setdefault('status', 'requires_install')
            merged.append(s)

    # Add live status if MCP client is available
    if hasattr(request.app.state, 'mcp_client') and request.app.state.mcp_client:
        live_status = request.app.state.mcp_client.get_connection_status()
        for s in merged:
            s['live_status'] = live_status.get(s['name'], {})

    return {"servers": merged}


@router.post('/servers')
async def add_server(request: Request, body: MCPServerAdd):
    """Add a new MCP server configuration."""
    store = request.app.state.agent_store
    server_id = store.save_mcp_connection(body.name, body.transport, body.model_dump())
    return {"id": server_id, "name": body.name}


@router.delete('/servers/{server_name}')
async def remove_server(request: Request, server_name: str):
    """Remove an MCP server configuration."""
    store = request.app.state.agent_store
    store.delete_mcp_connection(server_name)
    return {"status": "deleted"}


@router.post('/servers/{server_name}/connect')
async def connect_server(request: Request, server_name: str):
    """Connect to an MCP server."""
    if not hasattr(request.app.state, 'mcp_client') or not request.app.state.mcp_client:
        raise HTTPException(503, "MCP client not available")
    mcp_client = request.app.state.mcp_client
    store = request.app.state.agent_store

    # Look up server config from BOTH config.yaml and DB
    config = None

    # 1) Check config.yaml first (pre-configured servers)
    app_config = getattr(request.app.state, 'config', None) or {}
    config_servers = app_config.get('mcp_servers', []) if isinstance(app_config, dict) else []
    for s in config_servers:
        if s.get('name') == server_name:
            config = dict(s)
            break

    # 2) Fall back to DB
    if not config and store:
        for s in store.list_mcp_connections():
            if s['name'] == server_name:
                config = s
                break

    if not config:
        raise HTTPException(404, "Server configuration not found")
    try:
        from src.agent.mcp_client import MCPServerConfig
        import json as _json
        cfg_data = config.get('config_json', config)
        if isinstance(cfg_data, str):
            cfg_data = _json.loads(cfg_data)
        if isinstance(cfg_data, dict):
            cfg_data.setdefault('name', server_name)
            cfg_data.setdefault('transport', config.get('transport', 'stdio'))
        server_cfg = MCPServerConfig.from_dict(cfg_data)
        success = await mcp_client.connect(server_cfg)
        if success:
            # Register MCP tools into the ToolRegistry so the LLM can see them
            tool_registry = getattr(request.app.state, 'tool_registry', None)
            if tool_registry:
                try:
                    tools = await mcp_client.list_tools(server_name)
                    if tools:
                        tool_registry.register_mcp_tools(server_name, tools)
                except Exception:
                    pass  # Non-critical - tools still callable via MCP direct
            return {"status": "connected", "name": server_name}
        else:
            raise HTTPException(500, "Connection failed - check server logs")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Connection failed: {str(e)}")


@router.post('/servers/{server_name}/disconnect')
async def disconnect_server(request: Request, server_name: str):
    """Disconnect from an MCP server."""
    if not hasattr(request.app.state, 'mcp_client') or not request.app.state.mcp_client:
        raise HTTPException(503, "MCP client not available")
    mcp_client = request.app.state.mcp_client
    try:
        await mcp_client.disconnect(server_name)
        # Remove MCP tools from ToolRegistry
        tool_registry = getattr(request.app.state, 'tool_registry', None)
        if tool_registry:
            tool_registry.unregister_server(server_name)
        return {"status": "disconnected", "name": server_name}
    except Exception as e:
        raise HTTPException(500, f"Disconnect failed: {str(e)}")


@router.get('/servers/{server_name}/tools')
async def list_server_tools(request: Request, server_name: str):
    """List tools available from an MCP server."""
    if not hasattr(request.app.state, 'mcp_client') or not request.app.state.mcp_client:
        raise HTTPException(503, "MCP client not available")
    mcp_client = request.app.state.mcp_client
    tools = await mcp_client.list_tools(server_name)
    return {"tools": tools}


@router.post('/servers/{server_name}/check')
async def check_server_availability(request: Request, server_name: str):
    """Check if an MCP server's command exists on PATH (stdio)
    or if its URL is reachable (http/sse).

    Returns a JSON object with:
      - available (bool)
      - message (str) - human-readable status
      - detail (str) - technical detail
    """
    # Find server config
    app_config = getattr(request.app.state, 'config', None) or {}
    config_servers = app_config.get('mcp_servers', []) if isinstance(app_config, dict) else []
    server_cfg = None

    for s in config_servers:
        if s.get('name') == server_name:
            server_cfg = s
            break

    # Also check DB
    if not server_cfg:
        store = request.app.state.agent_store
        if store:
            for s in store.list_mcp_connections():
                if s['name'] == server_name:
                    server_cfg = s
                    break

    if not server_cfg:
        raise HTTPException(404, f"Server '{server_name}' not found")

    transport = (server_cfg.get('transport') or 'stdio').lower()

    if transport == 'stdio':
        return await _check_stdio_server(server_cfg)
    else:
        return await _check_http_server(server_cfg)


async def _check_stdio_server(cfg: dict) -> dict:
    """Check if a stdio server's command binary exists on PATH."""
    command = cfg.get('command', '')
    if not command:
        return {
            "available": False,
            "message": "Komut tanimlanmamis / No command defined",
            "detail": "stdio server has no 'command' field",
        }

    # For npx/uvx commands, check the launcher itself
    base_cmd = command.split()[0] if ' ' in command else command
    found_path = shutil.which(base_cmd)

    if found_path:
        return {
            "available": True,
            "message": f"Komut bulundu / Command found: {base_cmd}",
            "detail": f"Resolved to: {found_path}",
        }
    else:
        install_cmd = cfg.get('install_command', '')
        install_hint = f" -- Kurulum / Install: {install_cmd}" if install_cmd else ""
        return {
            "available": False,
            "message": f"Komut bulunamadi / Command not found: {base_cmd}{install_hint}",
            "detail": f"'{base_cmd}' is not on PATH",
        }


async def _check_http_server(cfg: dict) -> dict:
    """Check if an HTTP/SSE server URL is reachable."""
    import urllib.request
    import urllib.error

    url = cfg.get('url', '')
    if not url:
        return {
            "available": False,
            "message": "URL tanimlanmamis / No URL defined",
            "detail": "http/sse server has no 'url' field",
        }

    try:
        loop = asyncio.get_event_loop()

        def _probe():
            req = urllib.request.Request(url, method='HEAD')
            req.add_header('User-Agent', 'BlueTeamAssistant/2.0')
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                return resp.status
            except urllib.error.HTTPError as he:
                # Even a 4xx/5xx means the server is reachable
                return he.code
            except Exception:
                raise

        status_code = await loop.run_in_executor(None, _probe)
        return {
            "available": True,
            "message": f"Sunucu erisilebilir / Server reachable (HTTP {status_code})",
            "detail": f"URL: {url} responded with status {status_code}",
        }
    except Exception as e:
        install_cmd = cfg.get('install_command', '')
        install_hint = f" -- Kurulum / Install: {install_cmd}" if install_cmd else ""
        return {
            "available": False,
            "message": f"Sunucu erisilemedi / Server unreachable{install_hint}",
            "detail": f"URL: {url} -- Error: {str(e)}",
        }
