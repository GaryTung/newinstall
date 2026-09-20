from __future__ import annotations

import ast
import concurrent.futures
import copy
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

SOURCE = (Path(__file__).resolve().parents[1] / "vpngate_manager.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def function(name, namespace):
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "vpngate_manager.py", "exec"), namespace)
    return namespace[name]


class MaintenanceAdmissionTests(unittest.TestCase):
    def denied(self):
        return {"Any": object, "set_state": Mock(), "ensure_dirs": Mock(),
                "resource_guard": SimpleNamespace(background_work_allowed=Mock(return_value=(False, "memory deferred")))}

    def test_catalog_force_cannot_override_memory_guard_or_resume_pause(self):
        namespace = self.denied()
        namespace["resume_metadata_refresh"] = Mock(side_effect=AssertionError("must not resume"))
        self.assertEqual(function("refresh_node_catalog_only", namespace)(force=True), "memory deferred")
        namespace["resume_metadata_refresh"].assert_not_called()

    def test_country_detection_deferral_has_a_visible_completion_without_loading_nodes(self):
        namespace = self.denied()
        namespace.update({"read_json": lambda *args: {}, "STATE_FILE": Path("state"),
                          "time": SimpleNamespace(time=lambda: 100.0)})
        result = function("test_node_availability_only", namespace)(["one"], channel_id="jp")
        self.assertEqual(result, "memory deferred")
        state = namespace["set_state"].call_args.kwargs
        self.assertTrue(state["channel_test_results"]["jp"]["deferred"])
        self.assertEqual(state["channel_test_results"]["jp"]["completed_at"], 100.0)

    def test_direct_batch_entry_does_not_start_any_probe_or_load_catalog(self):
        namespace = self.denied()
        result = function("test_multiple_nodes", namespace)(["one", "two"])
        self.assertEqual([n["id"] for n in result], ["one", "two"])
        self.assertTrue(all(n["_deferred"] for n in result))
        self.assertTrue(all("probe_status" not in n for n in result))

    def test_manual_single_probe_is_also_guarded(self):
        with self.assertRaisesRegex(ValueError, "memory deferred"):
            function("test_node_by_id", self.denied())("one")

    def test_low_memory_legacy_maintenance_cannot_restart_connections(self):
        self.assertEqual(function("maintain_valid_nodes", self.denied())(force=True), "memory deferred")

    def test_low_memory_fetch_never_requests_primary_or_mirrors(self):
        namespace = self.denied()
        namespace.update({"metadata_cancel_event": threading.Event(), "CatalogRefreshCancelled": RuntimeError})
        with self.assertRaisesRegex(RuntimeError, "memory deferred"):
            function("fetch_candidates", namespace)(aggregate_all_sources=True)

    def test_memory_falling_between_candidates_preserves_original_health_and_backoff(self):
        nodes = [
            {"id": "one", "probe_status": "available", "probed_at": 10.0, "availability_failures": 0},
            {"id": "two", "probe_status": "unavailable", "probed_at": 11.0,
             "availability_failures": 2, "next_probe_at": 4000.0},
        ]
        catalog = copy.deepcopy(nodes)
        writes = []

        def write_json(path, data):
            nonlocal catalog
            catalog = copy.deepcopy(data)
            writes.append(catalog)

        enrich, callback = Mock(), Mock()
        guard = SimpleNamespace(
            background_work_allowed=Mock(side_effect=[(True, "ok"), (False, "deferred"), (False, "deferred")]),
            recommended_probe_workers=Mock(return_value=1),
        )
        namespace = {"Any": object, "resource_guard": guard, "set_state": Mock(),
                     "cleanup_stale_probe_processes": Mock(), "lock": threading.Lock(),
                     "read_nodes": lambda: copy.deepcopy(catalog), "write_json": write_json,
                     "NODES_FILE": Path("nodes"), "sort_all_nodes": lambda value: value,
                     "time": SimpleNamespace(time=lambda: 100.0), "AVAILABILITY_TEST_WORKERS": 2,
                     "concurrent": concurrent, "vpn_utils": SimpleNamespace(enrich_ip_info=enrich)}
        result = function("test_multiple_nodes", namespace)(["one", "two"], on_result=callback)
        self.assertTrue(all(node["_deferred"] for node in result))
        for original, saved in zip(nodes, catalog):
            for key, value in original.items():
                self.assertEqual(saved[key], value)
            self.assertNotIn("_deferred", saved)
        callback.assert_not_called()
        enrich.assert_not_called()
        guard.recommended_probe_workers.assert_called_once_with(2)
        self.assertEqual(len(writes), 3)  # initial/testing, final batch flush, final status save


class MainOpenVPNOwnershipTests(unittest.TestCase):
    def check(self, arguments, *, same_namespace=True, unreadable_namespace=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_dir = root / "configs"
            proc_dir = root / "123"
            proc_dir.mkdir()
            args = [arg.replace("CONFIG_ROOT", str(config_dir)) for arg in arguments]
            (proc_dir / "cmdline").write_bytes(b"\0".join(arg.encode() for arg in args) + b"\0")
            readlink = Mock(side_effect=OSError("not found")) if unreadable_namespace else Mock(
                side_effect=lambda path: "net:[1]" if str(path) == "/proc/self/ns/net" or same_namespace else "net:[2]"
            )
            namespace = {"Path": Path, "CONFIG_DIR": config_dir, "os": SimpleNamespace(readlink=readlink)}
            return function("is_owned_main_openvpn", namespace)(proc_dir)

    def test_only_main_namespace_profile_under_owned_config_dir_is_accepted(self):
        self.assertTrue(self.check(["/usr/sbin/openvpn", "--config", "CONFIG_ROOT/.test_one.ovpn"]))
        self.assertTrue(self.check(["/usr/sbin/openvpn", "--config=CONFIG_ROOT/main.ovpn"]))

    def test_country_namespace_with_shared_auth_is_never_owned(self):
        self.assertFalse(self.check(["openvpn", "--config", "CONFIG_ROOT/one.ovpn",
                                     "--auth-user-pass", "CONFIG_ROOT/../vpngate_auth.txt"], same_namespace=False))

    def test_shared_auth_alone_and_external_or_prefix_profiles_are_not_ownership(self):
        for args in (["openvpn", "--auth-user-pass", "CONFIG_ROOT/../vpngate_auth.txt"],
                     ["openvpn", "--config", "CONFIG_ROOT-other/one.ovpn"],
                     ["openvpn", "--config", "CONFIG_ROOT/../other.ovpn"],
                     ["openvpn", "--config", "relative.ovpn"],
                     ["bash", "openvpn", "--config", "CONFIG_ROOT/one.ovpn"]):
            with self.subTest(args=args):
                self.assertFalse(self.check(args))

    def test_missing_namespace_fails_closed(self):
        self.assertFalse(self.check(["openvpn", "--config", "CONFIG_ROOT/one.ovpn"], unreadable_namespace=True))


if __name__ == "__main__":
    unittest.main()
