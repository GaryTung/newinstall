import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CertificateReloadTests(unittest.TestCase):
    def test_installer_reload_command_covers_both_tls_consumers(self):
        source = (ROOT / "unified-install.sh").read_text(encoding="utf-8")
        self.assertIn("systemctl try-restart x-ui.service aimilivpn.service", source)

    def test_renewal_wrapper_reconciles_with_persisted_certificate_digest(self):
        source = (ROOT / "node-gateway-cert-renew.sh").read_text(encoding="utf-8")
        self.assertIn('CERT_DIGEST_FILE="${CERT_STATE_DIR}/cert-loaded.digest"', source)
        self.assertIn('previous="$(< "$CERT_DIGEST_FILE")"', source)
        self.assertIn('if [[ "$current" == "$previous" ]]', source)
        self.assertIn('for service in x-ui.service aimilivpn.service', source)
        self.assertIn('reconcile_loaded_certificate', source)
        self.assertIn('ACME_CHECK_INTERVAL="${ACME_CHECK_INTERVAL:-86400}"', source)

    def test_systemd_service_uses_wrapper_without_unconditional_restart(self):
        service = (ROOT / "node-gateway-cert-renew.service").read_text(encoding="utf-8")
        self.assertIn("ExecStart=/usr/local/sbin/node-gateway-cert-renew", service)
        self.assertNotIn("ExecStartPost", service)

    def test_upgrade_installs_and_enables_renewal_units(self):
        source = (ROOT / "upgrade-dashboard.sh").read_text(encoding="utf-8")
        for name in ("node-gateway-cert-renew.sh", "node-gateway-cert-renew.service", "node-gateway-cert-renew.timer"):
            self.assertIn(name, source)
        self.assertIn("systemctl enable node-gateway-cert-renew.timer", source)
        self.assertIn("systemctl restart node-gateway-cert-renew.timer", source)
        self.assertIn("node-gateway-cert-renew --mark-loaded", source)

    def test_timer_checks_every_ten_minutes(self):
        timer = (ROOT / "node-gateway-cert-renew.timer").read_text(encoding="utf-8")
        self.assertIn("OnUnitActiveSec=10min", timer)


if __name__ == "__main__":
    unittest.main()
