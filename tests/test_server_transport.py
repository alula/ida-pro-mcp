import json
import pathlib
import sys
import unittest
from unittest.mock import patch

from ida_pro_mcp import server

# discovery.py has no IDA imports, but its package __init__ does.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp"))
try:
    import discovery
finally:
    sys.path.pop(0)


class _FakeResponse:
    def __init__(self, status=200, reason="OK", body=b'{"jsonrpc":"2.0","result":{"ok":true},"id":1}'):
        self.status = status
        self.reason = reason
        self._body = body

    def read(self):
        return self._body


class _BaseFakeConnection:
    instances = []

    def __init__(self, host, port, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.request_calls = 0
        self.closed = False
        type(self).instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []

    def request(self, method, path, body, headers):
        self.request_calls += 1

    def close(self):
        self.closed = True


class _ResponseFailureConnection(_BaseFakeConnection):
    def getresponse(self):
        raise TimeoutError("read timeout")


class _Http503Connection(_BaseFakeConnection):
    def getresponse(self):
        return _FakeResponse(status=503, reason="Service Unavailable", body=b"busy")


class _ConnectFailureConnection(_BaseFakeConnection):
    def request(self, method, path, body, headers):
        super().request(method, path, body, headers)
        raise ConnectionRefusedError("refused")


class DispatchProxyTransportTests(unittest.TestCase):
    def setUp(self):
        _ResponseFailureConnection.reset()
        _Http503Connection.reset()
        _ConnectFailureConnection.reset()
        self._old_host = server.IDA_HOST
        self._old_port = server.IDA_PORT
        self._old_pinned = server._pinned
        server.IDA_HOST = "127.0.0.1"
        server.IDA_PORT = 13337

    def tearDown(self):
        server.IDA_HOST = self._old_host
        server.IDA_PORT = self._old_port
        server._pinned = self._old_pinned

    def test_proxy_request_forwards_external_base_header(self):
        original_getter = server.get_current_request_external_base_url

        class _RecordingConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)
                self.path = path
                self.headers = headers

            def getresponse(self):
                return _FakeResponse()

        _RecordingConnection.reset()
        server.get_current_request_external_base_url = lambda: "https://mcp.example.com/base"
        try:
            with patch("ida_pro_mcp.server.http.client.HTTPConnection", _RecordingConnection):
                server._proxy_to_ida(b"{}")
        finally:
            server.get_current_request_external_base_url = original_getter

        self.assertEqual(len(_RecordingConnection.instances), 1)
        self.assertEqual(
            _RecordingConnection.instances[0].headers.get("X-IDA-MCP-External-Base"),
            "https://mcp.example.com/base",
        )

    def test_proxy_always_sends_session_id_for_stdio_clients(self):
        """IDA requires a session header; stdio clients get this process' id."""
        class _RecordingConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)
                self.headers = headers

            def getresponse(self):
                return _FakeResponse()

        _RecordingConnection.reset()
        server.mcp._transport_session_id.data = "stdio:default"
        try:
            with patch("ida_pro_mcp.server.http.client.HTTPConnection", _RecordingConnection):
                server._proxy_to_ida(b"{}")
        finally:
            server.mcp._transport_session_id.data = None

        self.assertEqual(
            _RecordingConnection.instances[0].headers.get("Mcp-Session-Id"),
            server._PROXY_SESSION_ID,
        )

    def test_proxy_forwards_http_client_session_id(self):
        """An HTTP client's own session must reach IDA unchanged."""
        class _RecordingConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)
                self.headers = headers

            def getresponse(self):
                return _FakeResponse()

        _RecordingConnection.reset()
        server.mcp._transport_session_id.data = "http:client-abc"
        try:
            with patch("ida_pro_mcp.server.http.client.HTTPConnection", _RecordingConnection):
                server._proxy_to_ida(b"{}")
        finally:
            server.mcp._transport_session_id.data = None

        self.assertEqual(
            _RecordingConnection.instances[0].headers.get("Mcp-Session-Id"),
            "client-abc",
        )

    def test_proxy_to_ida_targets_module_default(self):
        class _RecordingConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)

            def getresponse(self):
                return _FakeResponse()

        _RecordingConnection.reset()
        server.IDA_HOST = "10.0.0.50"
        server.IDA_PORT = 24680
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _RecordingConnection):
            server._proxy_to_ida(b"{}")
        self.assertEqual(
            (_RecordingConnection.instances[0].host, _RecordingConnection.instances[0].port),
            ("10.0.0.50", 24680),
        )

    def test_dispatch_proxy_does_not_retry_post_send_failures(self):
        server._pinned = True
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _ResponseFailureConnection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("not retried automatically", response["error"]["message"])
        self.assertIn("read timeout", response["error"]["data"])
        self.assertEqual(len(_ResponseFailureConnection.instances), 1)
        self.assertEqual(_ResponseFailureConnection.instances[0].request_calls, 1)
        self.assertTrue(_ResponseFailureConnection.instances[0].closed)

    def test_dispatch_proxy_does_not_retry_http_503(self):
        server._pinned = True
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _Http503Connection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("HTTP 503 Service Unavailable", response["error"]["data"])
        self.assertEqual(len(_Http503Connection.instances), 1)
        self.assertEqual(_Http503Connection.instances[0].request_calls, 1)
        self.assertTrue(_Http503Connection.instances[0].closed)

    def test_dispatch_proxy_does_not_retry_connection_failures(self):
        server._pinned = True
        request = {"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _ConnectFailureConnection):
            response = server.dispatch_proxy(request)

        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertIn("refused", response["error"]["data"])
        self.assertEqual(len(_ConnectFailureConnection.instances), 1)
        self.assertEqual(_ConnectFailureConnection.instances[0].request_calls, 1)


if __name__ == "__main__":
    unittest.main()


def _fake_registrations():
    return [
        {
            "host": "127.0.0.1",
            "port": 13337,
            "pid": 101,
            "binary": "/games/game.exe",
            "idb_path": "/games/game.i64",
            "started_at": "2026-01-01T00:00:00+00:00",
            "backend": "gui",
        },
        {
            "host": "127.0.0.1",
            "port": 13338,
            "pid": 102,
            "binary": "/games/launcher.exe",
            "idb_path": "/games/launcher.i64",
            "started_at": "2026-01-02T00:00:00+00:00",
            "backend": "gui",
        },
    ]


class InstanceIdTests(unittest.TestCase):
    def test_id_follows_the_database_not_the_port(self):
        """An IDA restart lands on a new port; the agent's id must still work."""
        before = {"host": "127.0.0.1", "port": 13337, "idb_path": "/games/game.i64"}
        after = {"host": "127.0.0.1", "port": 13342, "idb_path": "/games/game.i64"}
        self.assertEqual(discovery.instance_id(before), discovery.instance_id(after))

    def test_distinct_databases_get_distinct_ids(self):
        ids = server.assign_instance_ids(_fake_registrations())
        self.assertEqual(len(ids), 2)

    def test_ids_are_short(self):
        ids = server.assign_instance_ids(_fake_registrations())
        self.assertTrue(all(len(i) == 4 for i in ids))

    def test_colliding_databases_widen_instead_of_clashing(self):
        same = [
            {"host": "127.0.0.1", "port": 13337, "idb_path": "/a.i64"},
            {"host": "127.0.0.1", "port": 13338, "idb_path": "/b.i64"},
        ]
        with patch.object(discovery, "instance_id", lambda info, length=4: "f" * length):
            ids = discovery.assign_instance_ids(same)
        # Every hash width collides, so the port disambiguates.
        self.assertEqual(len(ids), 2)
        self.assertTrue(all(":" in i for i in ids))


class InstanceRoutingTests(unittest.TestCase):
    def setUp(self):
        self._old_pinned = server._pinned
        server._pinned = False
        self.registrations = _fake_registrations()
        self.ids = list(server.assign_instance_ids(self.registrations))
        self._patcher = patch.object(
            server, "discover_instances", lambda: list(self.registrations)
        )
        self._patcher.start()
        server._instances = {}
        server._instances_at = 0.0

    def tearDown(self):
        self._patcher.stop()
        server._pinned = self._old_pinned
        server._instances = {}
        server._instances_at = 0.0

    @staticmethod
    def _recording_connection():
        class _RecordingConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)
                self.body = json.loads(body)

            def getresponse(self):
                return _FakeResponse()

        _RecordingConnection.reset()
        return _RecordingConnection

    def _call(self, arguments):
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "decompile", "arguments": arguments},
            "id": 1,
        }
        conn = self._recording_connection()
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", conn):
            response = server.dispatch_proxy(request)
        return response, conn

    @staticmethod
    def _tool_error_text(response):
        return response["result"]["content"][0]["text"]

    def test_call_without_instance_is_rejected_without_touching_ida(self):
        response, conn = self._call({"addr": "main"})
        self.assertTrue(response["result"]["isError"])
        self.assertIn("instance is required", self._tool_error_text(response))
        self.assertEqual(conn.instances, [])

    def test_call_with_unknown_instance_lists_the_running_ones(self):
        response, conn = self._call({"addr": "main", "instance": "beef"})
        self.assertTrue(response["result"]["isError"])
        text = self._tool_error_text(response)
        self.assertIn("Unknown instance", text)
        self.assertIn("game.exe", text)
        self.assertIn("launcher.exe", text)
        self.assertEqual(conn.instances, [])

    def test_call_is_forwarded_to_the_named_instance(self):
        response, conn = self._call({"addr": "main", "instance": self.ids[1]})
        self.assertIn("result", response)
        self.assertEqual(len(conn.instances), 1)
        self.assertEqual((conn.instances[0].host, conn.instances[0].port), ("127.0.0.1", 13338))

    def test_instance_argument_is_stripped_before_forwarding(self):
        """IDA has no `instance` parameter; leaving it in would be an unknown argument."""
        _, conn = self._call({"addr": "main", "instance": self.ids[0]})
        self.assertEqual(
            conn.instances[0].body["params"]["arguments"], {"addr": "main"}
        )

    def test_each_instance_is_reachable_independently(self):
        _, first = self._call({"addr": "main", "instance": self.ids[0]})
        _, second = self._call({"addr": "main", "instance": self.ids[1]})
        self.assertEqual(first.instances[0].port, 13337)
        self.assertEqual(second.instances[0].port, 13338)

    def test_tools_list_unions_instances_and_requires_instance(self):
        class _ToolsConnection(_BaseFakeConnection):
            def request(self, method, path, body, headers):
                super().request(method, path, body, headers)

            def getresponse(self):
                name = "decompile" if self.port == 13337 else "dbg_start"
                return _FakeResponse(
                    body=json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": {
                                "tools": [
                                    {"name": name, "inputSchema": {"type": "object", "properties": {}}}
                                ]
                            },
                        }
                    ).encode()
                )

        _ToolsConnection.reset()
        request = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", _ToolsConnection):
            response = server.dispatch_proxy(request)

        tools = {t["name"]: t for t in response["result"]["tools"]}
        self.assertIn("decompile", tools)
        self.assertIn("dbg_start", tools)
        self.assertIn("list_instances", tools)
        for name in ("decompile", "dbg_start"):
            self.assertIn("instance", tools[name]["inputSchema"]["properties"])
            self.assertIn("instance", tools[name]["inputSchema"]["required"])
        # The proxy answers list_instances itself, so it must not demand one.
        self.assertNotIn(
            "instance", tools["list_instances"]["inputSchema"].get("properties", {})
        )

    def test_list_instances_is_answered_locally(self):
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "list_instances", "arguments": {}},
            "id": 1,
        }
        conn = self._recording_connection()
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", conn):
            response = server.dispatch_proxy(request)

        self.assertEqual(conn.instances, [])
        listed = response["result"]["structuredContent"]["result"]
        self.assertEqual([e["instance"] for e in listed], self.ids)
        self.assertEqual([e["binary"] for e in listed], ["game.exe", "launcher.exe"])

    def test_resource_reads_fall_back_to_the_oldest_instance(self):
        """resources/read has no argument slot for an instance id."""
        request = {
            "jsonrpc": "2.0",
            "method": "resources/read",
            "params": {"uri": "ida://idb/metadata"},
            "id": 1,
        }
        conn = self._recording_connection()
        with patch("ida_pro_mcp.server.http.client.HTTPConnection", conn):
            server.dispatch_proxy(request)
        self.assertEqual(conn.instances[0].port, 13337)
