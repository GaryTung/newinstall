from __future__ import annotations

import ast
import importlib.util
import json
import re
import sqlite3
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class Stability31PackageTests(unittest.TestCase):
    def test_required_installation_files_exist(self) -> None:
        required = (
            "install.sh",
            "install-core.sh",
            "unified-install.sh",
            "install-multi-exit.sh",
            "vpngate_manager.py",
            "vpn_utils.py",
            "proxy_server.py",
            "multi_exit_manager.py",
            "xui_provision.py",
            "xui_multi_provision.py",
        )
        for name in required:
            self.assertTrue((ROOT / name).is_file(), name)

    def test_python_sources_parse(self) -> None:
        for name in (
            "vpngate_manager.py",
            "vpn_utils.py",
            "proxy_server.py",
            "multi_exit_manager.py",
            "xui_provision.py",
            "xui_multi_provision.py",
        ):
            source = (ROOT / name).read_text(encoding="utf-8")
            ast.parse(source, filename=name)

    def test_bootstrap_downloads_full_repo_and_calls_unified_installer(self) -> None:
        bootstrap = (ROOT / "install.sh").read_text(encoding="utf-8")
        unified = (ROOT / "unified-install.sh").read_text(encoding="utf-8")
        self.assertIn("archive/refs/heads/${BRANCH}.tar.gz", bootstrap)
        self.assertIn("unified-install.sh", bootstrap)
        self.assertIn("install-core.sh", unified)
        self.assertIn("install-multi-exit.sh", unified)

    def test_stability_31_rules_are_present(self) -> None:
        multi = (ROOT / "multi_exit_manager.py").read_text(encoding="utf-8")
        manager = (ROOT / "vpngate_manager.py").read_text(encoding="utf-8")
        for marker in (
            "VERIFIED_EXITS_FILE",
            "FULL_EXIT_VERIFIED_TTL_SECONDS",
            "MAX_CONNECT_CANDIDATES",
            "https://api.ipify.org",
            "https://ipv4.icanhazip.com",
            "https://ifconfig.me/ip",
            "mark_exit_verified(",
        ):
            self.assertIn(marker, multi)
        for marker in (
            "MULTI_EXIT_VERIFIED_EXITS_FILE",
            "cleanup_stale_probe_processes",
            "flush_step = max(4, max_workers * 4)",
        ):
            self.assertIn(marker, manager)

    def test_v2rayng_tls_subscription_fix_is_present(self) -> None:
        manager = (ROOT / "vpngate_manager.py").read_text(encoding="utf-8")
        self.assertIn("normalize_hysteria2_client_tls", manager)
        self.assertIn('(\"security\", \"tls\")', manager)
        self.assertIn('(\"insecure\", \"0\")', manager)
        self.assertIn("skip-cert-verify: false", manager)

    def test_installer_certificate_recovery_and_info_command(self) -> None:
        unified = (ROOT / "unified-install.sh").read_text(encoding="utf-8")
        control = (ROOT / "aimilivpnctl").read_text(encoding="utf-8")
        for marker in (
            "allow_local_port 80 tcp",
            "node-gateway-firewall.service",
            "issue_missing_certificate",
            "--certificate-profile shortlived",
            "show_available_info",
        ):
            self.assertIn(marker, unified)
        self.assertIn("  credentials)", control)
        self.assertNotIn("+  credentials)", control)
        self.assertIn("  info)", control)
        self.assertIn("XUI_ACCESS_URL", control)
        self.assertIn("gateway-result.json", control)

    def test_host_firewall_is_opened_by_default(self) -> None:
        unified = (ROOT / "unified-install.sh").read_text(encoding="utf-8")
        for marker in (
            'OPEN_ALL_PORTS="${OPEN_ALL_PORTS:-1}"',
            "open_all_host_ports",
            '"${firewall_cmd}" -P INPUT ACCEPT',
            'iptables-persistent',
            'ufw --force disable',
        ):
            self.assertIn(marker, unified)

    def test_fresh_xui_database_gets_default_xray_template(self) -> None:
        for name in ("xui_provision.py", "xui_multi_provision.py"):
            source = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("def default_xray_template", source)
            self.assertIn('"protocol": "freedom"', source)
            self.assertIn('"tag": "direct"', source)
            self.assertIn('"tag": "blocked"', source)
            self.assertNotIn("3x-ui 缺少 xrayTemplateConfig", source)

        def load_module(name: str):
            spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
            module = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            spec.loader.exec_module(module)
            return module

        db = sqlite3.connect(":memory:")
        db.execute("create table settings(id integer primary key, key text unique, value text)")
        single = load_module("xui_provision")
        single.modify_xray_template(db, "in-test", 7928)
        config = json.loads(db.execute(
            "select value from settings where key='xrayTemplateConfig'"
        ).fetchone()[0])
        self.assertTrue(any(item.get("tag") == "direct" for item in config["outbounds"]))
        self.assertTrue(any(item.get("tag") == "VPNGATE-AUTO" for item in config["outbounds"]))

        db.execute("delete from settings")
        multi = load_module("xui_multi_provision")
        multi.update_xray_template(db, [], "in-direct", "in-direct")
        config = json.loads(db.execute(
            "select value from settings where key='xrayTemplateConfig'"
        ).fetchone()[0])
        self.assertTrue(any(item.get("tag") == "blocked" for item in config["outbounds"]))
        db.close()

    def test_repository_contains_no_runtime_credentials(self) -> None:
        forbidden_paths = (
            ROOT / "vpngate_data",
            ROOT / "ui_auth.json",
            ROOT / "vpngate_auth.txt",
        )
        self.assertTrue(all(not path.exists() for path in forbidden_paths))
        private_key = re.compile(r"BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY")
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path.suffix.lower() not in {".py", ".sh", ".md", ".txt", ""}:
                continue
            self.assertIsNone(private_key.search(path.read_text(encoding="utf-8", errors="ignore")), str(path))


if __name__ == "__main__":
    unittest.main()
