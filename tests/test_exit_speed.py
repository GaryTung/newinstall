from __future__ import annotations

import ast
import copy
import json
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import multi_exit_manager as manager


class StableSelectionTests(unittest.TestCase):
    def setUp(self):
        self.channel = {"id": "us", "country": "美国", "ip_type": "residential_only", "enabled": True}
        self.nodes = [{"id": key, "ip": ip, "ip_type": "residential", "country": "美国",
                       "probe_status": "available", "latency_ms": latency}
                      for key, ip, latency in [("stable", "8.8.8.1", 100), ("fast", "8.8.8.2", 10)]]

    def selected(self, channel=None, history=None):
        with patch.object(manager, "read_json", return_value=self.nodes) as read, \
             patch.object(manager, "deep_failure_records", return_value={}), \
             patch.object(manager, "verified_exit_records", return_value={}):
            result = manager.select_candidates(channel or self.channel, history=history)
            read.assert_called_once_with(manager.NODES_FILE, [])
            return result

    def test_successful_history_precedes_lower_latency(self):
        selected = self.selected(history={"stable": {"successful_connections": 4, "total_uptime_seconds": 3600}})
        self.assertEqual("stable", selected[0]["id"])

    def test_explicit_manual_pin_still_precedes_history(self):
        selected = self.selected({**self.channel, "preferred_node_id": "fast"},
                                 {"stable": {"successful_connections": 4}})
        self.assertEqual("fast", selected[0]["id"])

    def test_stale_benchmark_config_never_changes_order_or_signature(self):
        legacy = {**self.channel, "speed_auto": True, "speed_request_token": 99999999999}
        self.assertEqual(self.selected(), self.selected(legacy))
        self.assertEqual(manager.channel_signature(self.channel), manager.channel_signature(legacy))

    def test_production_module_has_no_benchmark_dependency_or_worker(self):
        source = (ROOT / "multi_exit_manager.py").read_text(encoding="utf-8")
        for marker in ("exit_speed", "speed_loop", "speed_results.json", "choose_switch", "speed_target"):
            self.assertNotIn(marker, source)

    def test_healthy_daemon_does_not_parse_catalog_or_choose_another_node(self):
        class EndPass(Exception):
            pass

        channel = {**self.channel, "speed_auto": True, "speed_request_token": 1}
        runtime = {"node_id": "stable", "exit_ip": "8.8.8.1", "exit_country_code": "US",
                   "status": "connected", "openvpn_pid": 100, "proxy_pid": 101,
                   "proxy_address": "10.240.1.2", "config_signature": manager.channel_signature(channel)}
        state = {"channels": {"us": runtime}, "history_policy_version": 1}

        def read_json(path, default):
            self.assertEqual(path, manager.STATE_FILE, "Healthy pass unexpectedly reads a catalog/results file")
            return copy.deepcopy(state)

        with patch.object(manager, "DATA_DIR", Mock()), patch.object(manager, "read_json", side_effect=read_json), \
             patch.object(manager, "load_config", return_value={"channels": [channel]}), \
             patch.object(manager, "process_alive", return_value=True), \
             patch.object(manager, "proxy_health", return_value=(True, "8.8.8.1", 12)), \
             patch.object(manager, "clear_deep_failure"), patch.object(manager, "mark_exit_verified"), \
             patch.object(manager, "write_json"), patch.object(manager, "signal", SimpleNamespace(SIGUSR1=10, signal=Mock())), \
             patch.object(manager, "WAKE_EVENT", SimpleNamespace(wait=Mock(side_effect=EndPass))), \
             patch.object(manager, "select_candidates", side_effect=AssertionError("unexpected full catalog selection")), \
             patch.object(manager, "connect_channel", side_effect=AssertionError("unexpected tunnel switch")):
            with self.assertRaises(EndPass):
                manager.daemon()


if __name__ == "__main__":
    unittest.main()
