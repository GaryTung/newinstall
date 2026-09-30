import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CertificateReloadTests(unittest.TestCase):
    def test_installer_reload_command_covers_both_tls_consumers(self):
        source = (ROOT / "unified-install.sh").read_text(encoding="utf-8")
        self.assertIn("systemctl try-restart x-ui.service aimilivpn.service", source)

    def test_renewal_wrapper_reloads_only_unchanged_service_pids(self):
        source = (ROOT / "node-gateway-cert-renew.sh").read_text(encoding="utf-8")
        self.assertIn('before="$(certificate_digest)"', source)
        self.assertIn('after="$(certificate_digest)"', source)
        self.assertIn('if [[ "$before" == "$after" ]]', source)
        self.assertIn('if [[ -n "$old_pid" && "$old_pid" != "0" && "$new_pid" == "$old_pid" ]]', source)
        self.assertIn('reload_if_stale x-ui.service', source)
        self.assertIn('reload_if_stale aimilivpn.service', source)

    def test_systemd_service_uses_wrapper_without_unconditional_restart(self):
        service = (ROOT / "node-gateway-cert-renew.service").read_text(encoding="utf-8")
        self.assertIn("ExecStart=/usr/local/sbin/node-gateway-cert-renew", service)
        self.assertNotIn("ExecStartPost", service)

    def test_upgrade_installs_and_enables_renewal_units(self):
        source = (ROOT / "upgrade-dashboard.sh").read_text(encoding="utf-8")
        for name in ("node-gateway-cert-renew.sh", "node-gateway-cert-renew.service", "node-gateway-cert-renew.timer"):
            self.assertIn(name, source)
        self.assertIn("systemctl enable node-gateway-cert-renew.timer", source)


if __name__ == "__main__":
    unittest.main()
