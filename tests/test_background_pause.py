from __future__ import annotations

import ast
import copy
import io
import json
from http import HTTPStatus
from pathlib import Path
import secrets
import threading
from types import SimpleNamespace
import unittest
import urllib.parse
from unittest.mock import MagicMock, Mock


SOURCE = (Path(__file__).resolve().parents[1] / "vpngate_manager.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def load_function(name, namespace, owner=None):
    container = TREE if owner is None else next(n for n in TREE.body if isinstance(n, ast.ClassDef) and n.name == owner)
    function = next(n for n in container.body if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[function], type_ignores=[]), "vpngate_manager.py", "exec"), namespace)
    return namespace[name]


def handler(path, authorized=True):
    return SimpleNamespace(
        path=path, headers={}, wfile=io.BytesIO(),
        validate_path=Mock(return_value=path), is_authorized=Mock(return_value=authorized),
        read_json_body=Mock(return_value={}), get_secret_path=Mock(return_value="private"),
        send_json=Mock(), send_bytes=Mock(), send_response=Mock(), send_header=Mock(),
        end_headers=Mock(), send_error=Mock(),
    )


class BackgroundPauseStartupTests(unittest.TestCase):
    def test_environment_defaults_off_and_accepts_explicit_pause(self):
        assignment = next(n for n in TREE.body if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == "BACKGROUND_PAUSED" for t in n.targets))
        code = compile(ast.Module(body=[assignment], type_ignores=[]), "pause-setting", "exec")
        for value, expected in (("", False), ("0", False), ("false", False), ("1", True), (" TRUE ", True)):
            namespace = {"os": SimpleNamespace(environ={"VPNGATE_BACKGROUND_PAUSED": value})}
            exec(code, namespace)
            self.assertEqual(namespace["BACKGROUND_PAUSED"], expected)

    def test_main_returns_before_cleanup_migration_catalog_or_workers(self):
        namespace = {"ensure_dirs": Mock(), "BACKGROUND_PAUSED": True, "serve_paused_admin": Mock()}
        # All normal startup dependencies are deliberately absent: touching any
        # of them fails instead of invoking a real process, filesystem or network.
        load_function("main", namespace)()
        namespace["ensure_dirs"].assert_called_once_with()
        namespace["serve_paused_admin"].assert_called_once_with()

    def test_paused_admin_starts_only_bundle_and_web(self):
        thread_factory, server_factory = Mock(), Mock()
        namespace = {
            "metadata_cancel_event": Mock(), "set_state": Mock(),
            "BACKGROUND_PAUSED_MESSAGE": "maintenance paused", "threading": SimpleNamespace(Thread=thread_factory),
            "start_bundle_server": Mock(), "load_ui_config": lambda: {"host": "::", "port": 8787},
            "UI_HOST": "::", "UI_PORT": 8787, "bounded_int": lambda value, *args: int(value),
            "DualStackHTTPServer": server_factory, "Handler": object(), "print": Mock(),
        }
        load_function("serve_paused_admin", namespace)()
        thread_factory.assert_called_once_with(target=namespace["start_bundle_server"], daemon=True)
        thread_factory.return_value.start.assert_called_once_with()
        server_factory.assert_called_once_with(("::", 8787), namespace["Handler"])
        server_factory.return_value.serve_forever.assert_called_once_with()
        self.assertTrue(namespace["set_state"].call_args.kwargs["background_paused"])


class BackgroundPauseHttpTests(unittest.TestCase):
    def post_namespace(self):
        return {"BACKGROUND_PAUSED": True, "BACKGROUND_PAUSED_MESSAGE": "maintenance paused", "HTTPStatus": HTTPStatus}

    def test_mutating_and_expensive_posts_fail_before_reading_body(self):
        namespace = self.post_namespace()
        post = load_function("do_POST", namespace, "Handler")
        paths = ("/api/refresh_nodes", "/api/check", "/api/test_availability", "/api/test_nodes",
                 "/api/test_node", "/api/test_proxy", "/api/test_multi_exit_channel",
                 "/api/speed_multi_exit_channel", "/api/update_multi_exit_channel",
                 "/api/update_multi_exit", "/api/delete_multi_exit_channel",
                 "/api/switch_multi_exit_node", "/api/update_direct_protocol", "/api/connect")
        for path in paths:
            with self.subTest(path=path):
                request = handler(path)
                post(request)
                request.read_json_body.assert_not_called()
                body, status = request.send_json.call_args.args
                self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
                self.assertTrue(body["background_paused"])

    def test_pause_does_not_bypass_authentication(self):
        request = handler("/api/refresh_nodes", authorized=False)
        load_function("do_POST", self.post_namespace(), "Handler")(request)
        self.assertEqual(request.send_json.call_args.args[1], HTTPStatus.UNAUTHORIZED)

    def test_login_and_logout_still_work(self):
        namespace = {**self.post_namespace(), "json": json, "lock": threading.Lock(), "active_sessions": {},
                     "load_ui_config": lambda: {"username": "admin", "password": "test-only-password"},
                     "uuid": SimpleNamespace(uuid4=lambda: SimpleNamespace(hex="test-session")),
                     "time": SimpleNamespace(time=lambda: 100.0)}
        post = load_function("do_POST", namespace, "Handler")
        login = handler("/api/login", authorized=False)
        login.read_json_body.return_value = {"username": "admin", "password": "test-only-password"}
        post(login)
        login.send_response.assert_called_once_with(HTTPStatus.OK)
        self.assertIn("test-session", namespace["active_sessions"])
        logout = handler("/api/logout", authorized=False)
        logout.headers = {"Cookie": "session=test-session"}
        post(logout)
        logout.send_response.assert_called_once_with(HTTPStatus.OK)
        self.assertEqual(namespace["active_sessions"], {})

    def test_saved_channel_status_is_read_only_and_gateway_does_not_probe(self):
        payload = Mock(return_value={"ok": True, "config": {"channels": []}})
        namespace = {**self.post_namespace(), "multi_exit_payload": payload}
        get = load_function("do_GET", namespace, "Handler")
        request = handler("/api/multi_exit")
        get(request)
        payload.assert_called_once_with(read_only=True)
        request = handler("/api/gateway_status")
        get(request)
        self.assertTrue(request.send_json.call_args.args[0]["background_paused"])
        # No socket/subprocess dependencies are supplied, so any live probe fails.

    def test_subscription_endpoint_keeps_existing_token_and_content(self):
        token = "existing-subscription-token"
        aggregate = Mock(return_value=b"existing-node-content")
        namespace = {"urllib": SimpleNamespace(parse=urllib.parse), "secrets": secrets,
                     "ensure_bundle_token": Mock(return_value=token),
                     "aggregate_universal_subscription": aggregate, "HTTPStatus": HTTPStatus}
        request = handler("/all/" + token)
        load_function("do_GET", namespace, "BundleHandler")(request)
        aggregate.assert_called_once_with()
        request.send_response.assert_called_once_with(HTTPStatus.OK)
        self.assertEqual(request.wfile.getvalue(), b"existing-node-content")


class BackgroundPauseReadOnlyStatusTests(unittest.TestCase):
    def test_channel_payload_uses_saved_provider_without_enrichment(self):
        runtime = {"channels": {"jp": {"node_id": "node", "exit_ip": "192.0.2.1", "exit_provider": "saved provider"}}}
        probe = Mock(side_effect=AssertionError("unexpected provider lookup"))

        def read_json(path, default):
            return copy.deepcopy(runtime) if path.name == "state.json" and path.parent == Path("multi") else default

        namespace = {
            "Any": object, "Path": Path, "read_multi_exit_config": lambda: {"channels": [{"id": "jp"}]},
            "read_json": read_json, "MULTI_EXIT_DIR": Path("multi"), "STATE_FILE": Path("main-state.json"),
            "public_subscription_host": lambda: "", "lock": threading.Lock(), "read_nodes": lambda: [],
            "channel_candidate_nodes": lambda *args: [], "get_direct_node_status": lambda: {},
            "bundle_subscription_info": lambda: {}, "maintenance_lock": threading.Lock(),
            "vpn_utils": SimpleNamespace(enrich_ip_info=probe),
        }
        result = load_function("multi_exit_payload", namespace)(read_only=True)
        probe.assert_not_called()
        self.assertEqual(result["state"]["channels"]["jp"]["exit_provider"], "saved provider")
        self.assertTrue(result["maintenance"]["background_paused"])

    def test_direct_status_uses_local_ip_file_not_public_request(self):
        database, data_dir, connection = MagicMock(), MagicMock(), MagicMock()
        database.exists.return_value = True
        data_dir.__truediv__.return_value.read_text.return_value = "192.0.2.10\n"
        row = {"remark": "服务器直连", "port": 12345, "protocol": "hysteria", "tag": "direct-in"}
        setting = json.dumps({"routing": {"rules": [{"inboundTag": ["direct-in"], "outboundTag": "direct"}]}})
        connection.execute.return_value.fetchone.side_effect = [row, (setting,)]
        opener = Mock(side_effect=AssertionError("unexpected public IP lookup"))
        namespace = {
            "Any": object, "Path": Mock(return_value=database), "DATA_DIR": data_dir, "json": json,
            "sqlite3": SimpleNamespace(connect=Mock(return_value=connection), Row=object()),
            "subprocess": SimpleNamespace(run=Mock(return_value=SimpleNamespace(stdout="active"))),
            "time": SimpleNamespace(time=lambda: 10000.0), "BACKGROUND_PAUSED": True,
            "_direct_ip_cache": {"value": "", "time": 0},
            "urllib": SimpleNamespace(request=SimpleNamespace(urlopen=opener)),
        }
        result = load_function("get_direct_node_status", namespace)()
        self.assertEqual(result["status"], "connected")
        self.assertEqual(result["exit_ip"], "192.0.2.10")
        opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
