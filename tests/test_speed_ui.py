from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


SOURCE = (Path(__file__).resolve().parents[1] / "vpngate_manager.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def load_function(name, namespace):
    function = next(node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name == name)
    code = compile(ast.Module(body=[function], type_ignores=[]), "vpngate_manager.py", "exec")
    exec(code, namespace)
    return namespace[name]


def dashboard_html():
    for node in TREE.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "INDEX_HTML" for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("Dashboard HTML not found")


class SpeedQueueTests(unittest.TestCase):
    def setUp(self):
        self.config = {"channels": [
            {"id": "jp", "enabled": True, "preferred_node_id": "manual", "restart_token": 123},
            {"id": "us", "preferred_node_id": "untouched", "speed_auto": False},
        ]}
        self.write = Mock()
        self.wake = Mock()
        self.namespace = {
            "Any": object, "multi_config_lock": threading.Lock(),
            "read_multi_exit_config": lambda: copy.deepcopy(self.config),
            "write_json": self.write, "wake_multi_exit_service": self.wake,
            "MULTI_EXIT_DIR": Path("channels"), "time": SimpleNamespace(time=lambda: 1000.0),
        }
        load_function("find_multi_channel", self.namespace)
        self.queue = load_function("request_channel_speed_test", self.namespace)

    def test_only_selected_channel_is_queued_without_restart(self):
        result = self.queue("jp")
        saved = self.write.call_args.args[1]
        self.assertTrue(result["ok"])
        self.assertTrue(result["running"])
        self.assertEqual(saved["channels"][0]["preferred_node_id"], "")
        self.assertTrue(saved["channels"][0]["speed_auto"])
        self.assertEqual(saved["channels"][0]["speed_request_token"], 1000.0)
        self.assertEqual(saved["channels"][0]["restart_token"], 123)
        self.assertEqual(saved["channels"][1], self.config["channels"][1])
        self.wake.assert_called_once_with()

    def test_unknown_channel_does_not_write_or_wake(self):
        with self.assertRaises(ValueError):
            self.queue("missing")
        self.write.assert_not_called()
        self.wake.assert_not_called()

    def test_disabled_channel_does_not_write_or_wake(self):
        self.config["channels"][0]["enabled"] = False
        with self.assertRaises(ValueError):
            self.queue("jp")
        self.write.assert_not_called()
        self.wake.assert_not_called()


class SpeedPayloadTests(unittest.TestCase):
    def test_speed_file_is_read_once_and_attached_per_channel(self):
        config = {"channels": [{"id": "jp"}, {"id": "us", "speed_auto": False}]}
        speed = {"channels": {"jp": {"status": "testing", "tested": 2, "total": 6}}}
        reads = []

        def read_json(path, default):
            reads.append(path)
            return speed if path.name == "speed_results.json" else default

        namespace = {
            "Any": object, "Path": Path, "read_multi_exit_config": lambda: copy.deepcopy(config),
            "read_json": read_json, "MULTI_EXIT_DIR": Path("multi"), "STATE_FILE": Path("state.json"),
            "public_subscription_host": lambda: "", "lock": threading.Lock(), "read_nodes": lambda: [],
            "channel_candidate_nodes": lambda channel, nodes: [], "get_direct_node_status": lambda: {},
            "bundle_subscription_info": lambda: {}, "maintenance_lock": threading.Lock(),
        }
        payload = load_function("multi_exit_payload", namespace)()
        channels = payload["config"]["channels"]
        self.assertEqual(channels[0]["speed_test"], speed["channels"]["jp"])
        self.assertEqual(channels[1]["speed_test"], {})
        self.assertTrue(channels[0]["speed_auto"])
        self.assertFalse(channels[1]["speed_auto"])
        self.assertEqual(reads.count(Path("multi/speed_results.json")), 1)


class DashboardSpeedTests(unittest.TestCase):
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

    def test_save_only_pins_explicitly_selected_node(self):
        html = dashboard_html()
        save = html.split("async function saveMultiExitChannel(id){", 1)[1].split("setInterval(loadMultiExit", 1)[0]
        self.assertIn("const selectedNodeId=multiExitSelectedNodes[id]||'';", save)
        self.assertNotIn(":checked", save)
        self.assertIn("speed_auto:card.querySelector('[data-field=speed_auto]').checked", save)
        speed = html.split("async function speedMultiExitChannel(id){", 1)[1].split("async function monitorChannelAvailability", 1)[0]
        self.assertIn("delete multiExitSelectedNodes[id]", speed)


if __name__ == "__main__":
    unittest.main()
