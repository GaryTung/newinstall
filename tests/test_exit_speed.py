from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import exit_speed as speed
import multi_exit_manager as manager


class SpeedSelectionTests(unittest.TestCase):
    def setUp(self):
        self.now = 100000
        self.channel = {"id": "us", "country": "美国", "ip_type": "residential_only", "enabled": True}
        self.nodes = [{"id": key, "ip": ip, "ip_type": "residential", "country": "美国", "probe_status": "available"}
                      for key, ip in [("current", "8.8.8.1"), ("fast", "8.8.8.2"), ("slow", "8.8.8.3")]]
        self.result = {"status": "complete", "policy_key": speed.policy_key(self.channel), "samples": {}}
        for node, bps in zip(self.nodes, (100, 200, 50)):
            self.result["samples"][node["id"]] = {"ok": True, "tested_at": self.now, "bps": bps,
                "node_key": speed.node_key(node), "policy_key": speed.policy_key(self.channel),
                "exit_ip": node["ip"], "ip_type": "residential", "country_code": "US"}
        self.runtime = {"status": "connected", "node_id": "current", "exit_ip": self.nodes[0]["ip"]}

    def test_fastest_measured_eligible_exit_wins(self):
        self.assertEqual("fast", speed.choose_switch(self.channel, self.runtime, self.nodes, self.result, self.now))
        self.assertEqual("fast", speed.ranked_samples(self.channel, self.nodes, self.result, self.now)[0][2])

    def test_pin_disabled_testing_and_unhealthy_prevent_speed_switch(self):
        for change in ({"preferred_node_id": "current"}, {"speed_auto": False}):
            self.assertEqual("", speed.choose_switch({**self.channel, **change}, self.runtime, self.nodes, self.result, self.now))
        for state in ("testing", "error"):
            self.assertEqual("", speed.choose_switch(self.channel, self.runtime, self.nodes, {**self.result, "status": state}, self.now))
        self.assertEqual("", speed.choose_switch(self.channel, {**self.runtime, "status": "failed"}, self.nodes, self.result, self.now))

    def test_small_gain_cooldown_and_failed_baseline_do_not_churn(self):
        self.result["samples"]["fast"]["bps"] = 120
        self.assertEqual("", speed.choose_switch(self.channel, self.runtime, self.nodes, self.result, self.now))
        self.result["samples"]["fast"]["bps"] = 200
        self.assertEqual("", speed.choose_switch(self.channel, {**self.runtime, "speed_switch_at": self.now - 100}, self.nodes, self.result, self.now))
        self.result["samples"]["current"]["ok"] = False
        self.assertEqual("", speed.choose_switch(self.channel, self.runtime, self.nodes, self.result, self.now))

    def test_explicit_request_bypasses_hysteresis_only_after_its_round(self):
        self.result["samples"]["fast"]["bps"] = 120
        channel = {**self.channel, "speed_request_token": 12}
        runtime = {**self.runtime, "speed_switch_at": self.now - 1}
        self.assertEqual("", speed.choose_switch(channel, runtime, self.nodes, self.result, self.now))
        self.result["request_token"] = 12
        self.assertEqual("fast", speed.choose_switch(channel, runtime, self.nodes, self.result, self.now))
        runtime["speed_request_applied"] = 12
        self.assertEqual("", speed.choose_switch(channel, runtime, self.nodes, self.result, self.now))

    def test_stale_changed_config_or_actual_hosting_cannot_win(self):
        for change in ({"tested_at": self.now - speed.RESULT_TTL}, {"node_key": "old"},
                       {"policy_key": "old"}, {"ip_type": "hosting"}, {"exit_ip": "219.100.37.245"}):
            result = copy.deepcopy(self.result)
            result["samples"]["fast"].update(change)
            self.assertEqual("", speed.choose_switch(self.channel, self.runtime, self.nodes, result, self.now))

    def test_residential_preference_beats_faster_hosting(self):
        channel = {**self.channel, "ip_type": "residential_preferred"}
        result = copy.deepcopy(self.result)
        result["policy_key"] = speed.policy_key(channel)
        for sample in result["samples"].values():
            sample["policy_key"] = speed.policy_key(channel)
        result["samples"]["fast"]["ip_type"] = "hosting"
        self.assertEqual("current", speed.ranked_samples(channel, self.nodes, result, self.now)[0][2])

    def test_changed_actual_exit_requires_a_new_baseline(self):
        runtime = {**self.runtime, "exit_ip": "8.8.4.4"}
        self.assertEqual("", speed.choose_switch(self.channel, runtime, self.nodes, self.result, self.now))

    def test_rotation_tests_current_and_oldest_alternatives_with_fixed_limit(self):
        nodes = self.nodes + [{"id": f"new{x}"} for x in range(20)]
        batch = speed.batch_candidates(nodes, self.runtime, self.result)
        self.assertEqual(speed.BATCH_SIZE, len(batch))
        self.assertEqual("current", batch[0]["id"])
        self.assertTrue(all(n["id"].startswith("new") for n in batch[1:]))

    def test_slow_download_never_marks_production_node_unavailable(self):
        fake = SimpleNamespace(run=Mock(return_value=SimpleNamespace(returncode=28, stdout="200 1234 10")))
        with self.assertRaises(RuntimeError):
            speed.download_sample(fake)
        args = fake.run.call_args.args[0]
        self.assertIn(f"{speed.PROXY_IP}:1080", args)
        self.assertIn("--noproxy", args)
        self.assertIn("/dev/null", args)

    def test_benchmark_always_cleans_only_scratch_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = SimpleNamespace(DATA_DIR=Path(directory), stop_namespace_processes=Mock(),
                                   start_openvpn=Mock(side_effect=RuntimeError("unreachable")))
            with self.assertRaises(RuntimeError):
                speed.benchmark(fake, self.channel, self.nodes[0])
            self.assertEqual([speed.NS, speed.NS], [call.args[0] for call in fake.stop_namespace_processes.call_args_list])

    def test_slow_but_healthy_partial_download_is_a_valid_baseline(self):
        fake = SimpleNamespace(run=Mock(return_value=SimpleNamespace(returncode=28, stdout="200 262144 10.0")))
        self.assertEqual(26214.4, speed.download_sample(fake))

    def test_namespace_never_matches_production_and_unowned_cleanup_is_noop(self):
        self.assertGreater(len(speed.NS), len("avpn-") + 10)
        fake = SimpleNamespace(DATA_DIR=Path("unused"), read_json=Mock(return_value={}),
                               run=Mock(), stop_namespace_processes=Mock())
        speed.cleanup_namespace(fake)
        fake.run.assert_not_called()
        fake.stop_namespace_processes.assert_not_called()

    def test_setup_refuses_unowned_interface_before_modifying_network(self):
        fake = SimpleNamespace(DATA_DIR=Path("unused"), read_json=Mock(return_value={}),
                               run=Mock(side_effect=[SimpleNamespace(stdout=""), SimpleNamespace(returncode=0)]))
        with self.assertRaisesRegex(RuntimeError, "未确认归属"):
            speed.setup_namespace(fake)
        self.assertEqual(2, fake.run.call_count)

    def test_daemon_recovery_uses_real_speed_but_preserves_country_policy(self):
        result = {"channels": {"us": self.result}}
        with patch.object(manager, "read_json", return_value=self.nodes), patch.object(manager, "deep_failure_records", return_value={}), \
             patch.object(manager, "verified_exit_records", return_value={}), patch.object(speed, "read_results", return_value=result), \
             patch.object(manager.time, "time", return_value=self.now):
            self.assertEqual("fast", manager.select_candidates(self.channel)[0]["id"])
            self.assertEqual("current", manager.select_candidates({**self.channel, "preferred_node_id": "current"})[0]["id"])


if __name__ == "__main__":
    unittest.main()
