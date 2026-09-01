import argparse
import copy
import http.client
import json
import os
import re
import sys
import threading
import time
import traceback
import uuid
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import (
        EXTERNAL_BASE_HEADER,
        McpHttpRequestHandler,
        McpServer,
        get_current_request_external_base_url,
    )
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse
else:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import (
        EXTERNAL_BASE_HEADER,
        McpHttpRequestHandler,
        McpServer,
        get_current_request_external_base_url,
    )
    from zeromcp.jsonrpc import JsonRpcRequest, JsonRpcResponse

    sys.path.pop(0)

try:
    from .installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        set_ida_rpc,
    )
except ImportError:
    from installer import (
        list_available_clients,
        print_mcp_config,
        run_install_command,
        set_ida_rpc,
    )

try:
    from .ida_mcp.discovery import assign_instance_ids, discover_instances, probe_instance
except ImportError:
    try:
        from ida_mcp.discovery import assign_instance_ids, discover_instances, probe_instance
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
        from discovery import assign_instance_ids, discover_instances, probe_instance

        sys.path.pop(0)

DEFAULT_IDA_HOST = "127.0.0.1"
DEFAULT_IDA_PORT = 13337
IDA_HOST = DEFAULT_IDA_HOST
IDA_PORT = DEFAULT_IDA_PORT

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch

_OUTPUT_PATH_RE = re.compile(r"^/output/([a-f0-9-]+)\.(\w+)$")

# Identifies this proxy process to IDA when the client transport has no session
# of its own (stdio).
_PROXY_SESSION_ID = f"proxy-{uuid.uuid4()}"

INSTANCE_ARG = "instance"
INSTANCE_ARG_SCHEMA = {
    "type": "string",
    "description": "Short id of the target IDA instance, from list_instances.",
}
INSTANCE_REQUIRED_ERROR = (
    "instance is required. Pass instance=<id> with every tool call. "
    "Enumerate running IDA instances with list_instances."
)

# Tools the proxy answers itself; they are never forwarded to an instance.
LOCAL_TOOLS = {"list_instances"}

# Discovery touches the filesystem and TCP-probes every registration, so results
# are reused briefly. Anything that looks stale forces a rescan instead.
_INSTANCE_CACHE_TTL = 2.0
_instances_lock = threading.Lock()
_instances: dict[str, dict] = {}
_instances_at = 0.0

# True once --ida-rpc pins a single target: no discovery, no instance argument.
_pinned = False


def _refresh_instances(force: bool = False) -> dict[str, dict]:
    """Short id -> instance registration for every running IDA."""
    global _instances, _instances_at
    with _instances_lock:
        fresh = time.monotonic() - _instances_at < _INSTANCE_CACHE_TTL
        if not force and _instances and fresh:
            return _instances
        _instances = assign_instance_ids(discover_instances())
        _instances_at = time.monotonic()
        return _instances


def _describe_instances(instances: dict[str, dict]) -> str:
    if not instances:
        return "none are running"
    return ", ".join(
        f"{iid} ({os.path.basename(info.get('binary') or '?')})"
        for iid, info in instances.items()
    )


def _resolve_instance(instance: str) -> tuple[str, int]:
    """Map a short id to its host and port, rescanning once before giving up."""
    instances = _refresh_instances()
    info = instances.get(instance)
    if info is None:
        instances = _refresh_instances(force=True)
        info = instances.get(instance)
    if info is None:
        raise LookupError(
            f"Unknown instance {instance!r}. Running IDA instances: "
            f"{_describe_instances(instances)}. Use list_instances for details."
        )
    return info["host"], int(info["port"])


def _default_target() -> tuple[str, int]:
    """Target for methods with no argument to carry an instance (resources, prompts).

    discover_instances() sorts by start time, so this is the oldest IDA.
    """
    if _pinned:
        return IDA_HOST, IDA_PORT
    for info in _refresh_instances().values():
        return info["host"], int(info["port"])
    return IDA_HOST, IDA_PORT


@mcp.tool
def list_instances() -> list[dict]:
    """List the running IDA Pro instances.

    Every other tool requires the `instance` id returned here. Ids are derived
    from the open database, so they stay the same if IDA is restarted on it.
    """
    return [
        {
            "instance": iid,
            "binary": os.path.basename(info.get("binary") or ""),
            "idb_path": info.get("idb_path", ""),
            "host": info.get("host", ""),
            "port": info.get("port"),
            "pid": info.get("pid"),
            "backend": info.get("backend", "gui"),
        }
        for iid, info in _refresh_instances(force=True).items()
    ]


def _get_proxy_request_path() -> str:
    """Build the proxied MCP path, preserving enabled extensions."""
    enabled = sorted(getattr(mcp._enabled_extensions, "data", set()))
    if enabled:
        return f"/mcp?ext={','.join(enabled)}"
    return "/mcp"


def _get_proxy_session_id() -> str:
    """Session identity to present to IDA, which requires one on every request.

    HTTP/SSE clients own their session; stdio clients get this process' id, so
    concurrent proxies stay distinguishable on the IDA side.
    """
    transport_session_id = mcp.get_current_transport_session_id()
    if transport_session_id and ":" in transport_session_id:
        transport, session_id = transport_session_id.split(":", 1)
        if transport in ("http", "sse") and session_id and session_id != "anonymous":
            return session_id
    return _PROXY_SESSION_ID


def _get_proxy_request_headers() -> dict[str, str]:
    """Build proxy request headers, preserving HTTP MCP session identity."""
    headers = {
        "Content-Type": "application/json",
        "Mcp-Session-Id": _get_proxy_session_id(),
    }
    external_base_url = get_current_request_external_base_url()
    if external_base_url:
        headers[EXTERNAL_BASE_HEADER] = external_base_url
    return headers


def _proxy_to_ida(
    payload: bytes | str | dict, host: str | None = None, port: int | None = None
) -> dict:
    """Send a JSON-RPC request to an IDA instance and return the response."""
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    conn = http.client.HTTPConnection(host or IDA_HOST, port or IDA_PORT, timeout=30)
    try:
        conn.request(
            "POST",
            _get_proxy_request_path(),
            payload,
            _get_proxy_request_headers(),
        )
        response = conn.getresponse()
        raw_data = response.read().decode()
        if response.status >= 400:
            raise RuntimeError(
                f"HTTP {response.status} {response.reason}: {raw_data}"
            )
        return json.loads(raw_data)
    finally:
        conn.close()


def _proxy_output_download(
    path: str, host: str | None = None, port: int | None = None
) -> tuple[int, str, list[tuple[str, str]], bytes]:
    """Proxy a raw output download from one IDA instance."""
    conn = http.client.HTTPConnection(host or IDA_HOST, port or IDA_PORT, timeout=30)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.reason, response.getheaders(), response.read()
    finally:
        conn.close()


def _proxy_output_download_any(path: str) -> tuple[int, str, list[tuple[str, str]], bytes]:
    """An output lives on the instance that produced it, which the URL does not say."""
    targets = [(IDA_HOST, IDA_PORT)]
    if not _pinned:
        discovered = [
            (info["host"], int(info["port"])) for info in _refresh_instances().values()
        ]
        if discovered:
            targets = discovered

    errors = []
    not_found = None
    for host, port in targets:
        try:
            status, reason, headers, body = _proxy_output_download(path, host, port)
        except Exception as e:
            errors.append(f"{host}:{port}: {e}")
            continue
        if status != 404:
            return status, reason, headers, body
        not_found = (status, reason, headers, body)

    if not_found is not None:
        return not_found
    raise RuntimeError("; ".join(errors) or "no IDA instances available")


def _tool_error(request_id, message: str) -> JsonRpcResponse:
    """A routing failure is a tool error, not a protocol error."""
    return JsonRpcResponse(
        {
            "jsonrpc": "2.0",
            "result": {
                "content": [
                    {"type": "text", "text": json.dumps({"error": message}, separators=(",", ":"))}
                ],
                "isError": True,
            },
            "id": request_id,
        }
    )


def _proxy_failure(request_obj: dict, error: Exception) -> JsonRpcResponse | None:
    """Build the response for a request that never reached IDA. Call from an except block."""
    full_info = traceback.format_exc()
    request_id = request_obj.get("id")
    if request_id is None:
        return None  # Notification, no response needed

    shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
    return JsonRpcResponse(
        {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": (
                    "Failed to complete request to IDA Pro. "
                    f"Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?\n"
                    "The request was not retried automatically. "
                    "If this was a mutating operation, verify IDA state before retrying.\n"
                    f"{full_info}"
                ),
                "data": str(error),
            },
            "id": request_id,
        }
    )


def _forward(
    request_obj: dict, host: str | None = None, port: int | None = None
) -> JsonRpcResponse | None:
    try:
        return _proxy_to_ida(request_obj, host, port)
    except Exception as e:
        # A failure often means the registration is stale; make the next lookup honest.
        if not _pinned:
            _refresh_instances(force=True)
        return _proxy_failure(request_obj, e)


def _inject_instance_arg(tool: dict) -> dict:
    tool = copy.deepcopy(tool)
    schema = tool.setdefault("inputSchema", {"type": "object", "properties": {}})
    schema.setdefault("type", "object")
    schema.setdefault("properties", {}).setdefault(INSTANCE_ARG, INSTANCE_ARG_SCHEMA)
    required = schema.setdefault("required", [])
    if INSTANCE_ARG not in required:
        required.append(INSTANCE_ARG)
    return tool


def _instance_tools() -> list[dict]:
    """Union the tools of every reachable instance; surfaces differ with ?ext= and --unsafe."""
    tools: dict[str, dict] = {}
    errors = []
    for iid, info in _refresh_instances(force=True).items():
        try:
            response = _proxy_to_ida(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                info["host"],
                int(info["port"]),
            )
        except Exception as e:
            errors.append(f"{iid}: {e}")
            continue
        for tool in response.get("result", {}).get("tools", []):
            name = tool.get("name")
            if name and name not in tools:
                tools[name] = _inject_instance_arg(tool)

    if errors:
        print(f"[MCP] tools/list failed for {'; '.join(errors)}", file=sys.stderr)
    return list(tools.values())


def _dispatch_tools_call(request_obj: dict) -> JsonRpcResponse | None:
    params = request_obj.get("params") or {}
    request_id = request_obj.get("id")

    if params.get("name", "") in LOCAL_TOOLS:
        return dispatch_original(request_obj)

    arguments = copy.deepcopy(params.get("arguments") or {})
    instance = arguments.pop(INSTANCE_ARG, None)
    if not isinstance(instance, str) or not instance:
        return _tool_error(request_id, INSTANCE_REQUIRED_ERROR)

    try:
        host, port = _resolve_instance(instance)
    except LookupError as e:
        return _tool_error(request_id, str(e))

    forwarded = copy.deepcopy(request_obj)
    forwarded.setdefault("params", {})["arguments"] = arguments
    return _forward(forwarded, host, port)


def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests by routing everything (except initialize/notifications) to IDA."""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    method = request_obj["method"]
    if method == "initialize" or method.startswith("notifications/"):
        return dispatch_original(request)

    # --ida-rpc pins one IDA, so there is nothing to choose between.
    if _pinned:
        return _forward(request_obj)

    if method == "tools/list":
        try:
            tools = _instance_tools() + mcp._mcp_tools_list().get("tools", [])
        except Exception as e:
            return _proxy_failure(request_obj, e)
        return JsonRpcResponse(
            {"jsonrpc": "2.0", "result": {"tools": tools}, "id": request_obj.get("id")}
        )

    if method == "tools/call":
        return _dispatch_tools_call(request_obj)

    # resources/* and prompts/* carry no slot for an instance id.
    host, port = _default_target()
    return _forward(request_obj, host, port)


mcp.registry.dispatch = dispatch_proxy


class ProxyHttpRequestHandler(McpHttpRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if _OUTPUT_PATH_RE.match(parsed.path):
            if not self._check_api_request():
                return
            try:
                status, _, response_headers, body = _proxy_output_download_any(parsed.path)
            except Exception as e:
                self.send_error(502, f"Failed to proxy output download: {e}")
                return

            self.send_response(status)
            for header, value in response_headers:
                if header.lower() == "transfer-encoding":
                    continue
                self.send_header(header, value)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


DEFAULT_IDA_RPC = f"http://{IDA_HOST}:{IDA_PORT}"


def _resolve_ida_rpc(args) -> None:
    """Pin the IDA RPC target when --ida-rpc is given, otherwise route per call."""
    global IDA_HOST, IDA_PORT, _pinned

    if args.ida_rpc is not None:
        ida_rpc = urlparse(args.ida_rpc)
        if ida_rpc.hostname is None or ida_rpc.port is None:
            raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
        IDA_HOST = ida_rpc.hostname
        IDA_PORT = ida_rpc.port
        _pinned = True

        # Preserve ?ext= query param so proxy requests include the extensions
        ext_value = parse_qs(ida_rpc.query).get("ext", [""])[0]
        if ext_value:
            mcp._enabled_extensions.data = set(ext_value.split(","))

        set_ida_rpc(IDA_HOST, IDA_PORT)
        return

    instances = _refresh_instances(force=True)
    if not instances:
        print(
            "[MCP] No IDA instances discovered yet. Start the MCP plugin in IDA "
            "(Edit -> Plugins -> MCP), then call list_instances.",
            file=sys.stderr,
        )
    else:
        print(f"[MCP] Discovered {len(instances)} IDA instance(s):", file=sys.stderr)
        for iid, inst in instances.items():
            binary = os.path.basename(inst.get("binary") or "?")
            print(f"  {iid}  {binary} at {inst['host']}:{inst['port']}", file=sys.stderr)
        print("[MCP] Pass instance=<id> with every tool call.", file=sys.stderr)

    set_ida_rpc(IDA_HOST, IDA_PORT)


def main():
    global IDA_HOST, IDA_PORT

    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Install the MCP Server and IDA plugin. "
        "The IDA plugin is installed immediately. "
        "Optionally specify comma-separated client targets (e.g., 'claude,cursor'). "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--uninstall",
        nargs="?",
        const="",
        default=None,
        metavar="TARGETS",
        help="Uninstall the MCP Server and IDA plugin. "
        "The IDA plugin is uninstalled immediately. "
        "Optionally specify comma-separated client targets. "
        "Without targets, an interactive selector is shown.",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default=None,
        help="MCP transport for install: 'streamable-http' (default), 'stdio', or 'sse'. "
        "For running: use stdio (default) or pass a URL (e.g., http://127.0.0.1:8744[/mcp|/sse])",
    )
    parser.add_argument(
        "--scope",
        type=str,
        choices=["global", "project"],
        default=None,
        help="Installation scope: 'project' (current directory, default) or 'global' (user-level)",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=None,
        help="Pin a single IDA RPC server (e.g. http://127.0.0.1:13337), disabling "
        "per-call instance routing. Default: discover instances and require "
        "instance=<id> on every tool call.",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List all available MCP client targets",
    )
    args = parser.parse_args()

    # Handle --list-clients independently
    if args.list_clients:
        list_available_clients()
        return

    # Resolve IDA RPC target (explicit or auto-discovery)
    _resolve_ida_rpc(args)

    is_install = args.install is not None
    is_uninstall = args.uninstall is not None

    # Validate flag combinations
    if args.scope and not (is_install or is_uninstall):
        print("--scope requires --install or --uninstall")
        return

    if is_install and is_uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if is_install or is_uninstall:
        run_install_command(
            uninstall=is_uninstall,
            targets_str=args.install if is_install else args.uninstall,
            args=args,
        )
        return

    if args.config:
        print_mcp_config()
        return

    try:
        transport = args.transport or "stdio"
        if transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port, request_handler=ProxyHttpRequestHandler)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
