"""The stdio proxy in front of two real MCP servers, standing in for two IDA GUIs."""

import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _mcp_spec_support import McpServer, _pick_free_port, _wait_until_ready

from ida_pro_mcp import server


def _make_instance(name: str, extra_tool: bool = False) -> McpServer:
    srv = McpServer(name)

    @srv.tool
    def whoami() -> str:
        """Report which instance answered."""
        return name

    if extra_tool:
        @srv.tool
        def only_here() -> str:
            """A tool only one instance exposes."""
            return name

    # The plugin requires a session on every request; the proxy never calls
    # initialize, so this also proves its self-minted session id is accepted.
    srv.require_streamable_http_session = True
    return srv


class ProxyInstanceRoutingE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = "127.0.0.1"
        cls.servers = []
        cls.registrations = []
        for index, (name, extra) in enumerate((("alpha", False), ("beta", True))):
            srv = _make_instance(name, extra_tool=extra)
            port = _pick_free_port(cls.host)
            srv.serve(cls.host, port, background=True)
            _wait_until_ready(f"http://{cls.host}:{port}/mcp")
            cls.servers.append(srv)
            cls.registrations.append(
                {
                    "host": cls.host,
                    "port": port,
                    "pid": 1000 + index,
                    "binary": f"/bin/{name}.exe",
                    "idb_path": f"/bin/{name}.i64",
                    "started_at": f"2026-01-0{index + 1}T00:00:00+00:00",
                    "backend": "gui",
                }
            )
        cls.ids = list(server.assign_instance_ids(cls.registrations))

    @classmethod
    def tearDownClass(cls):
        for srv in cls.servers:
            srv.stop()

    def setUp(self):
        self._old_pinned = server._pinned
        server._pinned = False
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

    def _call(self, tool: str, instance: str):
        return server.dispatch_proxy(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool, "arguments": {"instance": instance}},
                "id": 1,
            }
        )

    def test_each_instance_answers_for_its_own_id(self):
        for instance, expected in zip(self.ids, ("alpha", "beta")):
            response = self._call("whoami", instance)
            self.assertNotIn("error", response, response)
            self.assertFalse(response["result"]["isError"], response)
            self.assertEqual(
                response["result"]["structuredContent"]["result"], expected
            )

    def test_tools_list_unions_both_instances(self):
        response = server.dispatch_proxy(
            {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        )
        names = {t["name"] for t in response["result"]["tools"]}
        self.assertIn("whoami", names)
        self.assertIn("only_here", names)
        self.assertIn("list_instances", names)

    def test_tool_missing_from_an_instance_errors_rather_than_misrouting(self):
        response = self._call("only_here", self.ids[0])
        self.assertTrue(response["result"]["isError"], response)


if __name__ == "__main__":
    unittest.main()
