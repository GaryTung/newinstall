import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AptLockWaitTests(unittest.TestCase):
    def test_bootstrap_waits_before_initial_packages(self):
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn("apt_get_wait()", source)
        self.assertIn("apt_get_wait update", source)
        self.assertIn("apt_get_wait install", source)
        self.assertNotIn("\n  apt-get update", source)

    def test_all_packaged_installers_use_shared_waiter(self):
        for name in ("unified-install.sh", "install-core.sh", "install-multi-exit.sh"):
            source = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn('source "${SCRIPT_DIR}/apt-wait.sh"', source, name)
            self.assertNotIn("\napt-get update", source, name)
            self.assertIn("apt_get_wait update", source, name)

    def test_waiter_is_bounded_and_only_retries_lock_errors(self):
        source = (ROOT / "apt-wait.sh").read_text(encoding="utf-8")
        self.assertIn('APT_LOCK_TIMEOUT_SECONDS:-900', source)
        self.assertIn('DPkg::Lock::Timeout=30', source)
        self.assertIn('could not get lock', source.lower())
        self.assertIn('return "$status"', source)
        self.assertNotIn("rm -f /var/lib/apt", source)
        self.assertNotIn("kill ", source)


if __name__ == "__main__":
    unittest.main()
