from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import threading
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "vpngate_manager.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def load_function(name, namespace):
    function = next(node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.Module(body=[function], type_ignores=[]), "vpngate_manager.py", "exec"), namespace)
    return namespace[name]


def dashboard_html():
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "INDEX_HTML" for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("Dashboard HTML not found")


class RemovedBenchmarkTests(unittest.TestCase):
    def test_no_endpoint_or_queue_can_enable_benchmark(self):
        self.assertNotIn("/api/speed_multi_exit_channel", SOURCE)
        self.assertNotIn("request_channel_speed_test", SOURCE)

    def test_payload_ignores_stale_settings_without_loading_speed_file(self):
        config = {"channels": [{"id": "jp", "speed_auto": True, "speed_request_token": 123,
                                 "speed_test": {"status": "testing"}, "preferred_node_id": "manual"}]}
        reads = []

        def read_json(path, default):
            reads.append(path)
            return default

        namespace = {
            "Any": object, "Path": Path, "read_multi_exit_config": lambda: copy.deepcopy(config),
            "read_json": read_json, "MULTI_EXIT_DIR": Path("multi"), "STATE_FILE": Path("state.json"),
            "public_subscription_host": lambda: "", "lock": threading.Lock(), "read_nodes": lambda: [],
            "channel_candidate_nodes": lambda channel, nodes: [], "get_direct_node_status": lambda: {},
            "bundle_subscription_info": lambda: {}, "maintenance_lock": threading.Lock(),
        }
        payload = load_function("multi_exit_payload", namespace)()
        channel = payload["config"]["channels"][0]
        for obsolete in ("speed_auto", "speed_request_token", "speed_test"):
            self.assertNotIn(obsolete, channel)
        self.assertEqual(channel["preferred_node_id"], "manual")
        self.assertFalse(any(path.name == "speed_results.json" for path in reads))

    @unittest.skipUnless(shutil.which("node"), "Node.js needed for JavaScript syntax check")
    def test_dashboard_javascript_parses(self):
        scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", dashboard_html(), flags=re.S | re.I)
        self.assertTrue(scripts)
        for script in scripts:
            script = script.replace("__MULTI_EXIT_BOOTSTRAP_JSON__", "{}")
            result = subprocess.run(
                [shutil.which("node"), "-e", "new Function(JSON.parse(require('fs').readFileSync(0,'utf8')));"],
                input=json.dumps(script), capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_ui_has_no_benchmark_controls_and_save_keeps_explicit_pin(self):
        html = dashboard_html()
        for marker in ("speed_auto", "speedMultiExitChannel", "multiSpeed", "测速并自动择优"):
            self.assertNotIn(marker, html)
        save = html.split("async function saveMultiExitChannel(id){", 1)[1].split("setInterval(loadMultiExit", 1)[0]
        self.assertIn("const selectedNodeId=multiExitSelectedNodes[id]||'';", save)
        self.assertNotIn(":checked", save)


if __name__ == "__main__":
    unittest.main()
