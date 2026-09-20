from __future__ import annotations

import ast
import socket
import threading
from pathlib import Path
from types import SimpleNamespace
import unittest
import urllib.request
from unittest.mock import MagicMock, Mock, patch

SOURCE = (Path(__file__).resolve().parents[1] / "vpngate_manager.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def load(name, namespace):
    node = next(n for n in TREE.body if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "vpngate_manager.py", "exec"), namespace)
    return namespace[name]


def environment(limit=128):
    namespace = {"Any": object, "CATALOG_RESPONSE_MAX_BYTES": limit,
                 "CATALOG_RESPONSE_MAX_HEADER_BYTES": 64 * 1024}
    for name in ("CatalogRefreshCancelled", "CatalogResponseTooLarge", "check_catalog_content_length",
                 "read_bounded_catalog_response"):
        load(name, namespace)
    return namespace


class CatalogResponseLimitTests(unittest.TestCase):
    def test_production_limit_is_eight_mib_not_environment_override(self):
        assignment = next(n for n in TREE.body if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == "CATALOG_RESPONSE_MAX_BYTES" for t in n.targets))
        namespace = {}
        exec(compile(ast.Module(body=[assignment], type_ignores=[]), "limit", "exec"), namespace)
        self.assertEqual(namespace["CATALOG_RESPONSE_MAX_BYTES"], 8 * 1024 * 1024)

    def test_declared_oversize_is_rejected_before_reading(self):
        namespace = environment()
        response = SimpleNamespace(headers={"Content-Length": "129"}, read=Mock())
        with self.assertRaisesRegex(namespace["CatalogResponseTooLarge"], "8 MiB"):
            namespace["read_bounded_catalog_response"](response)
        response.read.assert_not_called()

    def test_actual_read_is_limited_with_missing_invalid_or_false_length(self):
        namespace = environment()
        for headers in ({}, {"Content-Length": "1"}, {"Content-Length": "invalid"}, {"Content-Length": "-1"}):
            with self.subTest(headers=headers):
                response = SimpleNamespace(headers=headers, read=Mock(return_value=b"x" * 129))
                with self.assertRaises(namespace["CatalogResponseTooLarge"]):
                    namespace["read_bounded_catalog_response"](response)
                response.read.assert_called_once_with(129)

    def test_exact_limit_and_utf8_are_accepted(self):
        namespace = environment()
        for body in (b"x" * 128, "日本".encode("utf-8"), b""):
            response = SimpleNamespace(headers={}, read=Mock(return_value=body))
            self.assertEqual(namespace["read_bounded_catalog_response"](response), body.decode("utf-8"))
            response.read.assert_called_once_with(129)

    def test_direct_verified_and_legacy_unverified_branches_use_bounded_reader(self):
        for verify in (True, False):
            namespace = environment()
            response = MagicMock()
            response.__enter__.return_value = response
            response.headers = {}
            response.read.return_value = b"catalog"
            opener = Mock(return_value=response)
            namespace.update({"vpn_utils": SimpleNamespace(get_upstream_proxy=lambda: (None, None, None)),
                              "urllib": SimpleNamespace(request=SimpleNamespace(Request=urllib.request.Request, urlopen=opener))})
            result = load("fetch_api_text", namespace)("https://example.invalid/api/iphone/", verify)
            self.assertEqual(result, "catalog")
            response.read.assert_called_once_with(129)

    def test_oversize_proxy_does_not_retry_same_source_direct(self):
        namespace = environment()
        opener = Mock(side_effect=AssertionError("must not retry"))
        namespace.update({"vpn_utils": SimpleNamespace(get_upstream_proxy=lambda: ("http", "127.0.0.1", 9000)),
                          "print": Mock(), "urllib": SimpleNamespace(request=SimpleNamespace(urlopen=opener)),
                          "fetch_api_text_via_proxy": Mock(side_effect=namespace["CatalogResponseTooLarge"]("too large"))})
        with self.assertRaises(namespace["CatalogResponseTooLarge"]):
            load("fetch_api_text", namespace)("https://example.invalid/")
        opener.assert_not_called()

    def test_oversize_is_a_safe_catalog_cancel_and_old_directory_is_not_rewritten(self):
        namespace = environment()
        merge = Mock(side_effect=AssertionError("must not replace old directory"))
        lock = threading.Lock()
        namespace.update({"resource_guard": SimpleNamespace(background_work_allowed=lambda: (True, "ok")),
                          "ensure_dirs": Mock(), "metadata_refresh_paused": lambda: False,
                          "metadata_cancel_event": threading.Event(), "maintenance_lock": lock,
                          "lock": threading.Lock(), "is_connecting": False,
                          "reset_stale_testing_nodes": Mock(), "set_state": Mock(),
                          "fetch_candidates": Mock(side_effect=namespace["CatalogResponseTooLarge"]("8 MiB exceeded")),
                          "enrich_and_store_candidates": merge})
        result = load("refresh_node_catalog_only", namespace)()
        self.assertIn("8 MiB exceeded", result)
        merge.assert_not_called()
        self.assertFalse(lock.locked())
        self.assertFalse(namespace["is_connecting"])

    def test_oversize_source_propagates_without_parsing_partial_csv(self):
        namespace = environment()
        parser = Mock(side_effect=AssertionError("must not parse partial CSV"))
        namespace.update({"resource_guard": SimpleNamespace(background_work_allowed=lambda: (True, "ok")),
                          "metadata_cancel_event": threading.Event(), "load_blacklist": lambda: {},
                          "threading": threading, "load_ui_config": lambda: {}, "print": Mock(),
                          "log_to_json": Mock(), "API_URL": "https://example.invalid/api/iphone/",
                          "fetch_api_text": Mock(side_effect=namespace["CatalogResponseTooLarge"]("too large")),
                          "parse_vpngate_rows": parser})
        with self.assertRaises(namespace["CatalogResponseTooLarge"]):
            load("fetch_candidates", namespace)(True)
        parser.assert_not_called()


class SocketCatalogLimitTests(unittest.TestCase):
    def execute(self, response, *, limit=128, header_limit=65536):
        namespace = environment(limit)
        namespace["CATALOG_RESPONSE_MAX_HEADER_BYTES"] = header_limit
        remaining = bytearray(response)
        connection = Mock()

        def recv(size):
            data = bytes(remaining[:size])
            del remaining[:size]
            return data

        connection.recv.side_effect = recv
        namespace.update({"time": SimpleNamespace(monotonic=lambda: 100.0),
                          "vpn_utils": SimpleNamespace(get_upstream_proxy_auth=lambda: (None, None))})
        fetch = load("fetch_api_text_via_proxy", namespace)
        with patch.object(socket, "socket", return_value=connection):
            try:
                result = fetch("http://example.invalid/api/iphone/", "http", "127.0.0.1", 9000)
                return result, connection
            finally:
                connection.close.assert_called_once_with()
                self.assertTrue(all(0 < call.args[0] <= limit + 1 for call in connection.recv.call_args_list))

    def test_socket_response_actual_limit_rejects_instead_of_truncating(self):
        with self.assertRaisesRegex(RuntimeError, "8 MiB"):
            self.execute(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 200)

    def test_socket_declared_length_rejected_without_needing_large_body(self):
        with self.assertRaisesRegex(RuntimeError, "8 MiB"):
            self.execute(b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n")

    def test_socket_chunked_response_still_decodes_below_limit(self):
        result, _ = self.execute(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
        self.assertEqual(result, "abc")

    def test_socket_unbounded_header_is_also_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "64 KiB"):
            self.execute(b"HTTP/1.1 200 OK\r\nLong: " + b"x" * 80, limit=256, header_limit=32)


if __name__ == "__main__":
    unittest.main()
