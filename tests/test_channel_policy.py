from __future__ import annotations

import ast
import importlib.util
import threading
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("shared_channel_policy", ROOT / "channel_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class ChannelPolicyTests(unittest.TestCase):
    def test_country_provider_exclusions_do_not_block_other_countries(self):
        self.assertIn("KDDI", policy.provider_rejection({"country": "日本"}, {"owner": "Kddi Corporation"}))
        self.assertIn("KDDI", policy.provider_rejection({"country": "JP"}, asn="AS2516"))
        self.assertIn("KT", policy.provider_rejection({"country": "South Korea"}, {"owner": "KT"}))
        self.assertIn("KT", policy.provider_rejection({"country": "韩国"}, asn=4766))
        self.assertEqual("", policy.provider_rejection({"country": "美国"}, {"owner": "KDDI"}))
        self.assertEqual("", policy.provider_rejection({"country": "韩国"}, {"owner": "SK Telecom"}))
        self.assertEqual("", policy.provider_rejection({"country": "日本"}, asn="AS25160"))

    def test_exit_classification_and_provider_override_entry_classification(self):
        node = {"owner": "Allowed ISP", "ip_type": "residential", "exit_ip_type": "hosting"}
        self.assertEqual(99, policy.ip_type_rank(node, "residential_only"))
        self.assertEqual(0, policy.ip_type_rank(node, "hosting_only"))
        self.assertIn("住宅", policy.candidate_rejection({"country": "日本", "ip_type": "residential_only"}, node))
        node["exit_provider"] = "KDDI"
        self.assertIn("KDDI", policy.candidate_rejection({"country": "日本", "ip_type": "all"}, node))

    def test_failures_are_channel_scoped_with_legacy_fallback(self):
        records = {"jp-a:node": {"blocked_until": 99}, "node": {"blocked_until": 7}}
        self.assertEqual(99, policy.failure_record(records, "node", "jp-a")["blocked_until"])
        self.assertEqual(7, policy.failure_record(records, "node", "jp-b")["blocked_until"])
        records.pop("node")
        self.assertEqual({}, policy.failure_record(records, "node", "jp-b"))
        records["node"] = {"blocked_until": 7}
        records["jp-b:node"] = {}
        self.assertEqual({}, policy.failure_record(records, "node", "jp-b"))

    def test_confirmed_hosting_overrides_cached_residential_classification(self):
        for address in ("121.128.66.171", "47.153.119.84", "61.76.60.93", "118.47.249.153",
                        "219.100.37.245"):
            with self.subTest(address=address):
                node = {"ip": address, "ip_type": "residential", "exit_ip_type": "residential"}
                self.assertEqual("hosting", policy.effective_ip_type(node))
                self.assertEqual(99, policy.ip_type_rank(node, "residential_only"))
        self.assertEqual("residential", policy.effective_ip_type({
            "ip": "219.100.37.245", "exit_ip": "1.2.3.4", "exit_ip_type": "residential",
        }))

    def manager_environment(self, nodes, failures):
        tree = ast.parse((ROOT / "vpngate_manager.py").read_text(encoding="utf-8"))
        names = {"channel_candidate_nodes", "channel_source_candidates", "channel_ip_type_rank",
                 "policy_available_channel_nodes"}
        selected = ast.Module(body=[
            n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names
        ], type_ignores=[])
        env = {
            "Any": object, "time": time, "lock": threading.RLock(),
            "read_nodes": lambda: nodes,
            "read_json": lambda path, default: failures if path == "failures" else {},
            "MULTI_EXIT_DEEP_FAILURES_FILE": "failures",
            "MULTI_EXIT_VERIFIED_EXITS_FILE": "verified",
            "country_matches": lambda left, right: left == right,
            "normalized_country_name": lambda value: value,
            "parse_int": lambda value: int(value or 0),
            "candidate_rejection": policy.candidate_rejection,
            "ip_type_rank": policy.ip_type_rank,
            "effective_ip_type": policy.effective_ip_type,
            "failure_record": policy.failure_record,
        }
        exec(compile(selected, "candidate-functions", "exec"), env)
        return env

    def test_dashboard_and_standby_agree_on_eligible_nodes(self):
        nodes = [
            {"id": "kddi", "country": "日本", "owner": "KDDI", "ip_type": "residential", "probe_status": "available"},
            {"id": "good", "country": "日本", "owner": "Allowed", "ip_type": "residential", "probe_status": "available"},
            {"id": "hosting", "country": "日本", "ip_type": "residential", "exit_ip_type": "hosting", "probe_status": "available"},
            {"id": "kr", "country": "韩国", "owner": "Allowed", "ip_type": "residential", "probe_status": "available"},
        ]
        env = self.manager_environment(nodes, {})
        channel = {"id": "jp", "country": "日本", "ip_type": "residential_only"}
        dashboard = env["channel_candidate_nodes"](channel)
        self.assertEqual(3, len(dashboard))
        eligible = [n["id"] for n in dashboard if n["probe_status"] == "available" and n["policy_eligible"]]
        self.assertEqual(["good"], eligible)
        self.assertEqual(eligible, [n["id"] for n in env["policy_available_channel_nodes"](channel)])
        self.assertEqual(eligible, [n["id"] for n in env["channel_source_candidates"](channel)])
        self.assertIn("KDDI", next(n for n in dashboard if n["id"] == "kddi")["policy_rejection"])

    def test_failed_tunnel_does_not_hide_candidate_from_another_channel(self):
        nodes = [{"id": "good", "country": "日本", "ip_type": "residential", "probe_status": "available"}]
        until = time.time() + 600
        env = self.manager_environment(nodes, {"jp-a:good": {"blocked_until": until, "error": "timeout"}})
        first = {"id": "jp-a", "country": "日本", "ip_type": "all"}
        second = {"id": "jp-b", "country": "日本", "ip_type": "all"}
        self.assertEqual("unavailable", env["channel_candidate_nodes"](first)[0]["probe_status"])
        self.assertEqual([], env["policy_available_channel_nodes"](first))
        self.assertEqual(until, env["channel_source_candidates"](first)[0]["next_probe_at"])
        self.assertEqual("available", env["channel_candidate_nodes"](second)[0]["probe_status"])
        self.assertEqual(["good"], [n["id"] for n in env["policy_available_channel_nodes"](second)])
        self.assertEqual("available", nodes[0]["probe_status"])


if __name__ == "__main__":
    unittest.main()
