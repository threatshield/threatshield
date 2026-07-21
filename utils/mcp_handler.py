"""
MCP (Model Context Protocol) client — HTTP transport only.

Uses JSON-RPC 2.0 POST to communicate with MCP servers.
Configs are persisted in settings.json under the 'mcpServers' key.
"""

import json
import logging
import os

_STORAGE_DIR = os.environ.get('STORAGE_PATH', 'storage')
import uuid
import datetime

import requests as _requests

logger = logging.getLogger(__name__)

SETTINGS_PATH = os.path.join(_STORAGE_DIR, 'data', 'settings', 'settings.json')


# ---------------------------------------------------------------------------
# Settings helpers
# ---------------------------------------------------------------------------

def _load_settings() -> dict:
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_settings(settings: dict) -> None:
    os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
    with open(SETTINGS_PATH, 'w') as f:
        json.dump(settings, f, indent=2)


# ---------------------------------------------------------------------------
# CRUD for MCP server configs
# ---------------------------------------------------------------------------

def list_mcp_servers() -> list:
    return _load_settings().get('mcpServers', [])


def get_mcp_server(server_id: str) -> dict | None:
    return next((s for s in list_mcp_servers() if s['id'] == server_id), None)


def add_mcp_server(config: dict) -> dict:
    settings = _load_settings()
    servers = settings.get('mcpServers', [])
    config['id'] = str(uuid.uuid4())
    config['transport'] = 'http'
    config.setdefault('enabled', True)
    config.setdefault('tools', [])
    config['createdAt'] = datetime.datetime.utcnow().isoformat()
    servers.append(config)
    settings['mcpServers'] = servers
    _save_settings(settings)
    return config


def update_mcp_server(server_id: str, updates: dict) -> dict | None:
    settings = _load_settings()
    servers = settings.get('mcpServers', [])
    for i, server in enumerate(servers):
        if server['id'] == server_id:
            servers[i].update(updates)
            settings['mcpServers'] = servers
            _save_settings(settings)
            return servers[i]
    return None


def delete_mcp_server(server_id: str) -> None:
    settings = _load_settings()
    servers = settings.get('mcpServers', [])
    settings['mcpServers'] = [s for s in servers if s['id'] != server_id]
    _save_settings(settings)


# ---------------------------------------------------------------------------
# HTTP JSON-RPC transport
# ---------------------------------------------------------------------------

def _rpc(url: str, method: str, params: dict = None, timeout: int = 15,
         session_id: str = None, _session_out: dict = None,
         extra_headers: dict = None) -> dict:
    """Single JSON-RPC 2.0 POST. Returns the result dict or raises RuntimeError."""
    payload: dict = {"jsonrpc": "2.0", "method": method, "id": str(uuid.uuid4())}
    if params is not None:
        payload["params"] = params
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["mcp-session-id"] = session_id
    if extra_headers:
        headers.update(extra_headers)
    try:
        resp = _requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=timeout,
        )
        resp.raise_for_status()
        if _session_out is not None:
            _session_out["session_id"] = resp.headers.get("mcp-session-id")

        # streamable-http may respond with SSE (text/event-stream) instead of JSON
        content_type = resp.headers.get("Content-Type", "")
        if "text/event-stream" in content_type:
            data = _parse_sse_response(resp.text)
        elif resp.content:
            data = resp.json()
        else:
            data = {}

        if "error" in data:
            raise RuntimeError(f"MCP error: {data['error']}")
        return data.get("result", {})
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f"HTTP call failed ({url} › {method}): {exc}") from exc


def _parse_sse_response(text: str) -> dict:
    """Extract the first JSON-RPC object from an SSE response body."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[5:].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict) and ("result" in parsed or "error" in parsed or "id" in parsed):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                continue
    return {}


def _list_tools(url: str, auth_token: str = None) -> list:
    """Initialize the MCP session and return the tools list."""
    extra_headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else None
    session_info: dict = {}
    try:
        _rpc(url, "initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "ThreatShield", "version": "1.0.0"},
        }, _session_out=session_info, extra_headers=extra_headers)
    except Exception:
        pass  # some servers omit initialize; continue to tools/list
    session_id = session_info.get("session_id")
    result = _rpc(url, "tools/list", session_id=session_id, extra_headers=extra_headers)
    return result.get("tools", [])


def _call_tool(url: str, tool_name: str, arguments: dict, timeout: int = 30,
               session_id: str = None, extra_headers: dict = None) -> str:
    """Call a tool and return its text output."""
    result = _rpc(url, "tools/call", {"name": tool_name, "arguments": arguments},
                  timeout=timeout, session_id=session_id, extra_headers=extra_headers)
    content = result.get("content", [])
    if isinstance(content, list):
        parts = [item.get("text", "") for item in content if isinstance(item, dict) and item.get("type") == "text"]
        return "\n".join(parts)
    return str(result)


# ---------------------------------------------------------------------------
# Public: test + discovery
# ---------------------------------------------------------------------------

def test_mcp_server(server_id: str) -> dict:
    """
    Connect to the MCP server, run initialize + tools/list, persist the
    discovered tools back into settings.json, and return a status dict.
    """
    server = get_mcp_server(server_id)
    if not server:
        return {"success": False, "error": "Server not found"}

    url = server.get("url", "").strip()
    if not url:
        return {"success": False, "error": "Server URL is required"}

    try:
        auth_token = server.get("authToken", "").strip() or None
        tools_raw = _list_tools(url, auth_token=auth_token)

        # Preserve existing per-tool enabled flags
        existing = {t["name"]: t for t in server.get("tools", [])}
        tools = [
            {
                "name": t.get("name", ""),
                "description": t.get("description", ""),
                "inputSchema": t.get("inputSchema", {}),
                "enabled": existing.get(t.get("name", ""), {}).get("enabled", True),
            }
            for t in tools_raw
        ]

        update_mcp_server(server_id, {
            "tools": tools,
            "lastTested": datetime.datetime.utcnow().isoformat(),
        })
        return {"success": True, "tools": tools}

    except Exception as exc:
        logger.error(f"MCP test failed for {server_id}: {exc}")
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Threat model context collection
# ---------------------------------------------------------------------------

def _build_arguments(tool: dict, product_name: str, description: str) -> dict | None:
    """
    Build call arguments from the tool's inputSchema, mapping well-known
    parameter names to the product context. Returns None if required params
    cannot be satisfied.
    """
    schema = tool.get("inputSchema", {})
    props = schema.get("properties", {})
    if not props:
        return {}

    context = f"Product: {product_name}\n{description}"
    args: dict = {}
    for name in props:
        lower = name.lower()
        if lower in ("query", "input", "text", "prompt", "context", "message"):
            args[name] = context
        elif lower in ("product_name", "product", "name", "title"):
            args[name] = product_name
        elif lower in ("description", "desc", "summary"):
            args[name] = description

    required = schema.get("required", [])
    if required and not all(r in args for r in required):
        return None  # can't satisfy required params

    return args


def _collect_server_results(server: dict, product_name: str, description: str) -> str | None:
    """Call all enabled tools on a single server. Returns formatted block or None."""
    url = server.get("url", "").strip()
    if not url:
        return None
    server_name = server.get("name", server["id"])
    enabled_tools = [t for t in server.get("tools", []) if t.get("enabled", True)]
    if not enabled_tools:
        return None

    # Establish a session for all tool calls on this server
    auth_token = server.get("authToken", "").strip() or None
    extra_headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else None
    session_info: dict = {}
    try:
        _rpc(url, "initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "ThreatShield", "version": "1.0.0"},
        }, _session_out=session_info, extra_headers=extra_headers)
    except Exception:
        pass
    session_id = session_info.get("session_id")

    tool_results: list[str] = []
    for tool in enabled_tools:
        args = _build_arguments(tool, product_name, description)
        if args is None:
            logger.info(f"[MCP] Skipping {tool['name']} on {server_name} — required params not satisfiable")
            continue
        try:
            text = _call_tool(url, tool["name"], args, session_id=session_id, extra_headers=extra_headers)
            if text:
                tool_results.append(f"[{tool['name']}]\n{text}")
        except Exception as exc:
            logger.warning(f"[MCP] {tool['name']} on {server_name} failed: {exc}")

    if not tool_results:
        return None
    return f"### {server_name}\n" + "\n\n".join(tool_results)


def run_mcp_tools_for_threat_model(product_name: str, description: str) -> str:
    """
    Call all enabled tools on all enabled MCP servers and return a formatted
    string for injection into the threat model prompt. Returns "" if nothing
    is configured or all calls fail.
    """
    enabled_servers = [s for s in list_mcp_servers() if s.get("enabled")]
    if not enabled_servers:
        return ""

    sections = [
        block
        for server in enabled_servers
        for block in [_collect_server_results(server, product_name, description)]
        if block
    ]

    if not sections:
        return ""
    return "MCP SECURITY INTELLIGENCE (from connected MCP servers):\n\n" + "\n\n---\n\n".join(sections)
