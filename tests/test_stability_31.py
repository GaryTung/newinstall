from __future__ import annotations

import ast
import re
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
