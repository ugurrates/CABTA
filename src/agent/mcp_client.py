"""
MCP Client Manager - Connect to external MCP servers.
Supports stdio, SSE, and Streamable HTTP transports.

Each connected MCP server exposes tools that the Blue Team Agent can invoke
during autonomous investigations.  The manager gracefully handles servers
that are unavailable -- the agent continues to work with local tools.
"""

import asyncio
import json
import logging
import os
import sys
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration & connection data classes
# ---------------------------------------------------------------------------

@dataclass
class MCPServerConfig:
    """Configuration for a single MCP server connection."""
    name: str
    transport: str  # "stdio", "sse", "http"
    command: Optional[str] = None  # For stdio transport
    args: Optional[List[str]] = None  # For stdio transport
    url: Optional[str] = None  # For sse / http transport
    env: Optional[Dict[str, str]] = None  # Extra env vars for the subprocess
    token: Optional[str] = None  # Bearer token for http/sse auth
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialise config to a plain dict (safe for JSON / DB storage)."""
        return {
            "name": self.name,
            "transport": self.transport,
            "command": self.command,
            "args": self.args,
            "url": self.url,
            "env": self.env,
            "description": self.description,
            # Intentionally omit token for safety
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MCPServerConfig":
        """Deserialise from a plain dict."""
        return cls(
            name=data["name"],
            transport=data.get("transport", "stdio"),
            command=data.get("command"),
            args=data.get("args"),
            url=data.get("url"),
            env=data.get("env"),
            token=data.get("token"),
            description=data.get("description", ""),
        )


@dataclass
class MCPConnection:
    """Runtime state for a single MCP server connection."""
    config: MCPServerConfig
    client: Any = None  # MCP ClientSession or equivalent
    session: Any = None  # Context manager / transport handle
    read_stream: Any = None
    write_stream: Any = None
    process: Any = None  # For stdio transport (asyncio.subprocess.Process)
    tools: List[Dict] = field(default_factory=list)
    connected: bool = False
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class MCPClientManager:
    """
    Manages connections to multiple external MCP servers.

    Each server can provide tools that the agent can invoke via
    ``call_tool(server_name, tool_name, arguments)``.

    Design principles
    -----------------
    * **Graceful degradation** -- if a server is unreachable the agent keeps
      working with local tools.  Errors are logged but never propagated to
      crash the main loop.
    * **Async-safe** -- all mutation is serialised through ``self._lock``.
    * **Store integration** -- connection metadata is persisted via the
      ``AgentStore`` (SQLite) so the UI can show connection status.
    """

    def __init__(self, agent_store=None):
        self._connections: Dict[str, MCPConnection] = {}
        self._lock = asyncio.Lock()
        self.store = agent_store

    # ------------------------------------------------------------------ #
    #  Connect / disconnect
    # ------------------------------------------------------------------ #

    async def connect(self, config: MCPServerConfig) -> bool:
        """
        Connect to an MCP server and discover its tools.

        Returns ``True`` on success, ``False`` on failure.  Failures are
        logged but never raised -- the agent must keep running.
        """
        async with self._lock:
            # If already connected, disconnect first
            if config.name in self._connections and self._connections[config.name].connected:
                await self._disconnect_unlocked(config.name)

            connection = MCPConnection(config=config)

            try:
                if config.transport == "stdio":
                    await self._connect_stdio(connection)
                elif config.transport == "sse":
                    await self._connect_sse(connection)
                elif config.transport == "http":
                    await self._connect_http(connection)
                else:
                    raise ValueError(f"Unknown transport: {config.transport}")

                # Discover tools
                if connection.connected:
                    connection.tools = await self._discover_tools(connection)
                    logger.info(
                        "[MCP] Connected to %s (%s) -- %d tools available",
                        config.name, config.transport, len(connection.tools),
                    )

                self._connections[config.name] = connection

                # Persist to store
                self._persist_connection(config.name, connection)

                return connection.connected

            except Exception as exc:
                connection.error = str(exc)
                connection.connected = False
                self._connections[config.name] = connection
                self._persist_connection(config.name, connection)

                logger.warning(
                    "[MCP] Failed to connect to %s: %s", config.name, exc,
                )
                return False

    async def disconnect(self, server_name: str) -> None:
        """Disconnect from an MCP server by name."""
        async with self._lock:
            await self._disconnect_unlocked(server_name)

    async def _disconnect_unlocked(self, server_name: str) -> None:
        """Internal disconnect (caller must hold ``_lock``)."""
        conn = self._connections.get(server_name)
        if conn is None:
            return

        try:
            # Close subprocess for stdio
            if conn.process is not None:
                try:
                    conn.process.terminate()
                    await asyncio.wait_for(conn.process.wait(), timeout=5)
                except Exception:
                    try:
                        conn.process.kill()
                    except Exception:
                        pass

            # Close MCP client session if it has a close method
            if conn.client is not None and hasattr(conn.client, "__aexit__"):
                try:
                    await conn.client.__aexit__(None, None, None)
                except Exception:
                    pass
            elif conn.client is not None and hasattr(conn.client, "close"):
                try:
                    await conn.client.close()
                except Exception:
                    pass

            # Close session context if applicable
            if conn.session is not None and hasattr(conn.session, "__aexit__"):
                try:
                    await conn.session.__aexit__(None, None, None)
                except (Exception, BaseException):
                    pass

            # Kill subprocess if still running
            if conn.process is not None:
                try:
                    conn.process.terminate()
                except Exception:
                    pass

        except (Exception, BaseException) as exc:
            logger.debug("[MCP] Cleanup error for %s: %s", server_name, exc)

        conn.connected = False
        conn.client = None
        conn.session = None
        conn.process = None

        self._persist_connection(server_name, conn)
        logger.info("[MCP] Disconnected from %s", server_name)

    async def connect_all(self, configs: List[MCPServerConfig]) -> Dict[str, bool]:
        """
        Connect to all configured MCP servers.

        Returns a dict mapping server name -> success boolean.
        """
        results: Dict[str, bool] = {}
        for cfg in configs:
            results[cfg.name] = await self.connect(cfg)
        return results

    async def disconnect_all(self) -> None:
        """Disconnect from every connected server."""
        names = list(self._connections.keys())
        for name in names:
            await self.disconnect(name)

    async def reconnect(self, server_name: str) -> bool:
        """Reconnect to a server using its stored config."""
        conn = self._connections.get(server_name)
        if conn is None:
            logger.warning("[MCP] Cannot reconnect -- %s not registered", server_name)
            return False
        return await self.connect(conn.config)

    # ------------------------------------------------------------------ #
    #  Transport helpers
    # ------------------------------------------------------------------ #

    async def _connect_stdio(self, connection: MCPConnection) -> None:
        """Connect to an MCP server via stdio (subprocess)."""
        cfg = connection.config
        if not cfg.command:
            raise ValueError(f"stdio transport requires 'command' for server {cfg.name}")

        # Build environment
        env = os.environ.copy()
        if cfg.env:
            env.update(cfg.env)

        cmd_args = cfg.args or []

        try:
            # Try the MCP SDK client path first
            from mcp.client.session import ClientSession
            from mcp.client.stdio import StdioServerParameters, stdio_client

            params = StdioServerParameters(
                command=cfg.command,
                args=cmd_args,
                env=cfg.env,
            )

            # Use SDK's stdio_client context manager
            transport = stdio_client(params)
            read_s, write_s = await transport.__aenter__()
            connection.session = transport

            session = ClientSession(read_s, write_s)
            await session.__aenter__()
            connection.client = session

            # Initialise the session
            await session.initialize()
            connection.connected = True

        except ImportError:
            # Fallback: launch subprocess and use raw JSON-RPC
            logger.info(
                "[MCP] mcp.client SDK not available -- using raw JSON-RPC for %s",
                cfg.name,
            )
            proc = await asyncio.create_subprocess_exec(
                cfg.command, *cmd_args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            connection.process = proc
            connection.client = _RawJsonRpcClient(proc)
            await connection.client.initialize()
            connection.connected = True

        except FileNotFoundError:
            raise ConnectionError(
                f"Command not found: {cfg.command}. "
                f"Make sure the MCP server is installed."
            )
        except Exception as exc:
            raise ConnectionError(f"stdio connect failed for {cfg.name}: {exc}") from exc

    async def _connect_sse(self, connection: MCPConnection) -> None:
        """Connect to an MCP server via Server-Sent Events."""
        cfg = connection.config
        if not cfg.url:
            raise ValueError(f"SSE transport requires 'url' for server {cfg.name}")

        try:
            from mcp.client.session import ClientSession
            from mcp.client.sse import sse_client

            headers = {}
            if cfg.token:
                headers["Authorization"] = f"Bearer {cfg.token}"

            transport = sse_client(cfg.url, headers=headers)
            read_s, write_s = await transport.__aenter__()
            connection.session = transport

            session = ClientSession(read_s, write_s)
            await session.__aenter__()
            connection.client = session

            await session.initialize()
            connection.connected = True

        except ImportError:
            # Fallback: use aiohttp for raw HTTP JSON-RPC
            logger.info(
                "[MCP] mcp.client.sse not available -- using raw HTTP for %s",
                cfg.name,
            )
            await self._connect_http_fallback(connection)

        except Exception as exc:
            raise ConnectionError(f"SSE connect failed for {cfg.name}: {exc}") from exc

    async def _connect_http(self, connection: MCPConnection) -> None:
        """Connect to an MCP server via Streamable HTTP."""
        cfg = connection.config
        if not cfg.url:
            raise ValueError(f"HTTP transport requires 'url' for server {cfg.name}")

        try:
            from mcp.client.session import ClientSession
            from mcp.client.streamable_http import streamablehttp_client

            headers = {}
            if cfg.token:
                headers["Authorization"] = f"Bearer {cfg.token}"

            transport = streamablehttp_client(cfg.url, headers=headers)
            read_s, write_s, _ = await transport.__aenter__()
            connection.session = transport

            session = ClientSession(read_s, write_s)
            await session.__aenter__()
            connection.client = session

            await session.initialize()
            connection.connected = True

        except ImportError:
            # Fallback: use aiohttp
            logger.info(
                "[MCP] mcp.client.streamable_http not available -- using raw HTTP for %s",
                cfg.name,
            )
            await self._connect_http_fallback(connection)

        except Exception as exc:
            raise ConnectionError(f"HTTP connect failed for {cfg.name}: {exc}") from exc

    async def _connect_http_fallback(self, connection: MCPConnection) -> None:
        """
        Fallback HTTP/SSE connection using aiohttp + raw JSON-RPC.

        This is used when the ``mcp`` SDK client modules are not installed.
        """
        cfg = connection.config
        try:
            import aiohttp

            headers = {"Content-Type": "application/json"}
            if cfg.token:
                headers["Authorization"] = f"Bearer {cfg.token}"

            http_session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            )
            connection.session = http_session
            connection.client = _HttpJsonRpcClient(http_session, cfg.url)

            await connection.client.initialize()
            connection.connected = True

        except Exception as exc:
            raise ConnectionError(
                f"HTTP fallback connect failed for {cfg.name}: {exc}"
            ) from exc

    # ------------------------------------------------------------------ #
    #  Tool discovery & invocation
    # ------------------------------------------------------------------ #

    async def _discover_tools(self, connection: MCPConnection) -> List[Dict]:
        """Ask the connected server for its list of tools."""
        try:
            client = connection.client

            # MCP SDK path
            if hasattr(client, "list_tools"):
                result = await client.list_tools()
                tools_raw = result.tools if hasattr(result, "tools") else result
                tools = []
                for t in tools_raw:
                    if hasattr(t, "name"):
                        tools.append({
                            "name": t.name,
                            "description": getattr(t, "description", ""),
                            "inputSchema": getattr(t, "inputSchema", {}),
                        })
                    elif isinstance(t, dict):
                        tools.append({
                            "name": t.get("name", ""),
                            "description": t.get("description", ""),
                            "inputSchema": t.get("inputSchema", {}),
                        })
                return tools

            # Fallback JSON-RPC path
            if hasattr(client, "request"):
                resp = await client.request("tools/list", {})
                return resp.get("tools", [])

            return []

        except Exception as exc:
            logger.warning(
                "[MCP] Tool discovery failed for %s: %s",
                connection.config.name, exc,
            )
            return []

    async def call_tool(
        self, server_name: str, tool_name: str, arguments: Dict
    ) -> Dict:
        """
        Call a tool on a connected MCP server.

        Returns the parsed result dict.  On any error returns a dict with
        an ``"error"`` key so callers never need to catch exceptions.
        """
        conn = self._connections.get(server_name)
        if conn is None:
            return {"error": f"Server '{server_name}' is not registered"}
        if not conn.connected:
            return {"error": f"Server '{server_name}' is not connected"}

        try:
            client = conn.client

            # MCP SDK path
            if hasattr(client, "call_tool"):
                result = await asyncio.wait_for(
                    client.call_tool(tool_name, arguments),
                    timeout=60,  # 60s timeout for MCP tool calls
                )

                # Parse result -- SDK returns CallToolResult with content list
                if hasattr(result, "content"):
                    parts = []
                    for item in result.content:
                        if hasattr(item, "text"):
                            # Try to parse JSON text
                            try:
                                parts.append(json.loads(item.text))
                            except (json.JSONDecodeError, TypeError):
                                parts.append({"text": item.text})
                        elif isinstance(item, dict) and "text" in item:
                            try:
                                parts.append(json.loads(item["text"]))
                            except (json.JSONDecodeError, TypeError):
                                parts.append(item)
                        else:
                            parts.append({"raw": str(item)})

                    if len(parts) == 1:
                        return {"result": parts[0], "server": server_name, "tool": tool_name}
                    return {"result": parts, "server": server_name, "tool": tool_name}

                # Plain dict
                if isinstance(result, dict):
                    return {"result": result, "server": server_name, "tool": tool_name}

                return {"result": str(result), "server": server_name, "tool": tool_name}

            # Fallback JSON-RPC path
            if hasattr(client, "request"):
                resp = await asyncio.wait_for(
                    client.request("tools/call", {
                        "name": tool_name,
                        "arguments": arguments,
                    }),
                    timeout=60,
                )
                return {"result": resp, "server": server_name, "tool": tool_name}

            return {"error": f"Client for '{server_name}' has no call interface"}

        except Exception as exc:
            logger.error(
                "[MCP] Tool call %s/%s failed: %s", server_name, tool_name, exc,
            )
            return {
                "error": str(exc),
                "server": server_name,
                "tool": tool_name,
            }

    # ------------------------------------------------------------------ #
    #  Listing helpers
    # ------------------------------------------------------------------ #

    async def list_tools(self, server_name: str) -> List[Dict]:
        """List available tools from a specific server."""
        conn = self._connections.get(server_name)
        if conn is None or not conn.connected:
            return []
        return list(conn.tools)

    async def list_all_tools(self) -> Dict[str, List[Dict]]:
        """List tools from all connected servers."""
        result: Dict[str, List[Dict]] = {}
        for name, conn in self._connections.items():
            if conn.connected:
                result[name] = list(conn.tools)
        return result

    def get_connection_status(self) -> Dict[str, Dict]:
        """Get status of all registered connections."""
        status: Dict[str, Dict] = {}
        for name, conn in self._connections.items():
            status[name] = {
                "connected": conn.connected,
                "transport": conn.config.transport,
                "description": conn.config.description,
                "tool_count": len(conn.tools),
                "tools": [t.get("name", "") for t in conn.tools],
                "error": conn.error,
            }
        return status

    def is_connected(self, server_name: str) -> bool:
        """Quick check if a server is connected."""
        conn = self._connections.get(server_name)
        return conn is not None and conn.connected

    # ------------------------------------------------------------------ #
    #  Persistence
    # ------------------------------------------------------------------ #

    def _persist_connection(self, name: str, connection: MCPConnection) -> None:
        """Save connection metadata to the AgentStore if available."""
        if self.store is None:
            return

        try:
            status = "connected" if connection.connected else "disconnected"
            if connection.error:
                status = f"error: {connection.error[:120]}"

            self.store.save_mcp_connection(
                name=name,
                transport=connection.config.transport,
                config=connection.config.to_dict(),
            )
            self.store.update_mcp_status(
                name=name,
                status=status,
                tools=connection.tools if connection.connected else None,
            )
        except Exception as exc:
            logger.debug("[MCP] Store persistence failed for %s: %s", name, exc)


# ---------------------------------------------------------------------------
# Fallback JSON-RPC clients (when mcp SDK client modules are unavailable)
# ---------------------------------------------------------------------------

class _RawJsonRpcClient:
    """
    Minimal JSON-RPC 2.0 client over an asyncio subprocess (stdin/stdout).

    Used as a fallback when ``mcp.client`` is not importable.
    """

    def __init__(self, proc):
        self._proc = proc
        self._id = 0

    async def initialize(self) -> None:
        """Send the MCP initialize handshake."""
        resp = await self.request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "blue-team-agent", "version": "1.0.0"},
        })
        # Send initialized notification
        await self._send_notification("notifications/initialized", {})
        return resp

    async def request(self, method: str, params: Dict) -> Any:
        """Send a JSON-RPC request and wait for the response."""
        self._id += 1
        msg = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
            "params": params,
        }
        line = json.dumps(msg) + "\n"

        self._proc.stdin.write(line.encode())
        await self._proc.stdin.drain()

        # Read response line
        raw = await asyncio.wait_for(
            self._proc.stdout.readline(), timeout=30,
        )
        if not raw:
            raise ConnectionError("Server closed stdout")

        resp = json.loads(raw.decode())
        if "error" in resp:
            raise RuntimeError(
                f"JSON-RPC error {resp['error'].get('code')}: "
                f"{resp['error'].get('message')}"
            )
        return resp.get("result", {})

    async def _send_notification(self, method: str, params: Dict) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        msg = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        line = json.dumps(msg) + "\n"
        self._proc.stdin.write(line.encode())
        await self._proc.stdin.drain()

    async def close(self) -> None:
        """Terminate the subprocess."""
        try:
            self._proc.terminate()
        except Exception:
            pass


class _HttpJsonRpcClient:
    """
    Minimal JSON-RPC 2.0 client over HTTP using aiohttp.

    Used as a fallback when the ``mcp`` SDK client modules are unavailable.
    """

    def __init__(self, session, url: str):
        self._session = session
        self._url = url.rstrip("/")
        self._id = 0

    async def initialize(self) -> None:
        """Send the MCP initialize handshake via HTTP POST."""
        resp = await self.request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "blue-team-agent", "version": "1.0.0"},
        })
        return resp

    async def request(self, method: str, params: Dict) -> Any:
        """Send a JSON-RPC request over HTTP and parse the response."""
        self._id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
            "params": params,
        }

        async with self._session.post(self._url, json=payload) as resp:
            resp.raise_for_status()
            data = await resp.json()

        if "error" in data:
            raise RuntimeError(
                f"JSON-RPC error {data['error'].get('code')}: "
                f"{data['error'].get('message')}"
            )
        return data.get("result", {})

    async def close(self) -> None:
        """Close the underlying aiohttp session."""
        try:
            await self._session.close()
        except Exception:
            pass
