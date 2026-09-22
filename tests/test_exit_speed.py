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

    def selected(self, channel=None, history=None, **kwargs):
        with patch.object(manager, "read_json", return_value=self.nodes) as read, \
             patch.object(manager, "deep_failure_records", return_value={}), \
             patch.object(manager, "verified_exit_records", return_value={}):
            result = manager.select_candidates(channel or self.channel, history=history, **kwargs)
            read.assert_called_once_with(manager.NODES_FILE, [])
            return result

    def test_successful_history_precedes_lower_latency(self):
        selected = self.selected(history={"stable": {"successful_connections": 4, "total_uptime_seconds": 3600}})
        self.assertEqual("stable", selected[0]["id"])

    def test_explicit_manual_pin_still_precedes_history(self):
        selected = self.selected({**self.channel, "preferred_node_id": "fast"},
                                 {"stable": {"successful_connections": 4}})
        self.assertEqual("fast", selected[0]["id"])

    def test_same_country_automatic_lines_prefer_an_unused_exit(self):
        selected = self.selected(
            history={"stable": {"successful_connections": 4, "total_uptime_seconds": 3600}},
            occupied_node_ids={"stable"}, occupied_exit_ips={"8.8.8.1"},
        )
        self.assertEqual(["fast", "stable"], [node["id"] for node in selected])

    def test_manual_pin_can_intentionally_reuse_an_occupied_exit(self):
        selected = self.selected(
            {**self.channel, "preferred_node_id": "stable"},
            occupied_node_ids={"stable"}, occupied_exit_ips={"8.8.8.1"},
        )
        self.assertEqual("stable", selected[0]["id"])

    def test_occupied_exit_remains_a_fallback_when_capacity_is_insufficient(self):
        self.nodes = [self.nodes[0]]
        selected = self.selected(occupied_node_ids={"stable"}, occupied_exit_ips={"8.8.8.1"})
        self.assertEqual(["stable"], [node["id"] for node in selected])

    def test_only_sibling_lines_in_the_same_country_reserve_exits(self):
        channel = {**self.channel, "id": "us-vless"}
        state = {"channels": {
            "us-hy2": {"node_id": "stable", "exit_ip": "8.8.8.1", "status": "connected"},
            "jp-hy2": {"node_id": "jp-node", "exit_ip": "9.9.9.9", "status": "connected"},
        }}
        configured = [
            {"id": "us-hy2", "country": "US", "enabled": True},
            {"id": "us-vless", "country": "美国", "enabled": True},
            {"id": "jp-hy2", "country": "日本", "enabled": True},
        ]
        self.assertEqual(
            ({"stable"}, {"8.8.8.1"}),
            manager.occupied_country_exits(channel, state, configured),
        )

    def test_stale_benchmark_config_never_changes_order_or_signature(self):
        legacy = {**self.channel, "speed_auto": True, "speed_request_token": 99999999999}
        self.assertEqual(self.selected(), self.selected(legacy))
        self.assertEqual(manager.channel_signature(self.channel), manager.channel_signature(legacy))

    def test_production_module_has_no_benchmark_dependency_or_worker(self):
        source = (ROOT / "multi_exit_manager.py").read_text(encoding="utf-8")
        for marker in ("exit_speed", "speed_loop", "speed_results.json", "choose_switch", "speed_target"):
            self.assertNotIn(marker, source)

    def test_proxy_process_accepts_server_specific_low_memory_settings(self):
        source = (ROOT / "multi_exit_manager.py").read_text(encoding="utf-8")
        self.assertIn('"LOCAL_PROXY_DNS_CACHE_SIZE"', source)
        self.assertIn('"LOCAL_PROXY_DNS_CACHE_TTL"', source)
        self.assertIn('"LOCAL_PROXY_MAX_CONNECTIONS"', source)

    def test_history_compaction_is_country_scoped_bounded_and_preserves_active_nodes(self):
        history = {
            "US_old": {"last_success_at": 1},
            "JP_recent": {"last_success_at": 30},
            "JP_old": {"last_success_at": 2},
            "KR_protected": {"last_success_at": 0},
        }
        compacted = manager.compact_history_map(
            history, "JP", protected={"KR_protected"}, limit=2,
        )
        self.assertEqual(["KR_protected", "JP_recent"], list(compacted))

    def test_expired_deep_failures_are_pruned_and_records_are_bounded(self):
        records = {
            "expired": {"failed_at": 1, "blocked_until": 2},
            "active": {"failed_at": 90, "blocked_until": 200},
            "recent": {"failed_at": 95, "blocked_until": 96},
        }
        with patch.object(manager, "DEEP_FAILURE_RETENTION_SECONDS", 20), \
             patch.object(manager, "DEEP_FAILURE_MAX_ENTRIES", 2):
            self.assertEqual(
                ["active", "recent"],
                list(manager.bounded_failure_records(records, now=100)),
            )

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
             patch.object(manager, "write_json") as write, patch.object(manager, "signal", SimpleNamespace(SIGUSR1=10, signal=Mock())), \
             patch.object(manager, "WAKE_EVENT", SimpleNamespace(wait=Mock(side_effect=EndPass))), \
             patch.object(manager, "select_candidates", side_effect=AssertionError("unexpected full catalog selection")), \
             patch.object(manager, "connect_channel", side_effect=AssertionError("unexpected tunnel switch")):
            with self.assertRaises(EndPass):
                manager.daemon()
            self.assertEqual(1, write.call_count)


if __name__ == "__main__":
    unittest.main()
