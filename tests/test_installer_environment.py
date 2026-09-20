"""Run only the installer's environment-file initializer, never installation."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "install-core.sh").read_text(encoding="utf-8")
FUNCTION = re.search(r"(?ms)^initialize_environment_file\(\) \{\n.*?^\}", SCRIPT).group(0)
WINDOWS_BASH = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
BASH = str(WINDOWS_BASH) if os.name == "nt" and WINDOWS_BASH.is_file() else shutil.which("bash")


@unittest.skipUnless(BASH, "Bash is required for the isolated installer test")
class InstallerEnvironmentTests(unittest.TestCase):
    def run_initializer(self, target: Path) -> subprocess.CompletedProcess:
        command = """set -Eeuo pipefail
ENV_FILE=$1
DATA_DIR=/var/lib/aimilivpn
UI_HOST=::
UI_PORT=8787
PROXY_HOST=127.0.0.1
PROXY_PORT=7928
fail() { printf '%s\\n' "$*" >&2; exit 1; }
""" + FUNCTION + "\ninitialize_environment_file\n"
        return subprocess.run(
            [BASH, "-c", command, "installer-env-test", target.as_posix()],
            capture_output=True, text=True, encoding="utf-8", timeout=10,
        )

    def test_fresh_install_creates_all_runtime_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "gateway.env"
            result = self.run_initializer(target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.read_text(), (
                "VPNGATE_DATA_DIR=/var/lib/aimilivpn\nUI_HOST=::\nUI_PORT=8787\n"
                "LOCAL_PROXY_HOST=127.0.0.1\nLOCAL_PROXY_PORT=7928\nPYTHONUNBUFFERED=1\n"
            ))
            if os.name != "nt":
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_existing_pause_limits_custom_paths_and_comments_are_byte_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "gateway.env"
            original = (
                b"# Operator settings\nVPNGATE_BACKGROUND_PAUSED=1\n"
                b"VPNGATE_DATA_DIR=/srv/private-catalog\nUI_HOST=127.0.0.1\nUI_PORT=9898\n"
                b"LOCAL_PROXY_PORT=8989\nVPNGATE_MIRROR_WORKERS=1\n"
                b"AVAILABILITY_TEST_WORKERS=1\nCUSTOM_SETTING='keep me'\n"
            )
            target.write_bytes(original)
            result = self.run_initializer(target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.read_bytes(), original)

    def test_empty_existing_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "gateway.env"
            target.touch()
            result = self.run_initializer(target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(target.read_bytes(), b"")

    def test_invalid_existing_directory_fails_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "gateway.env"
            target.mkdir()
            result = self.run_initializer(target)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(target.is_dir())
            self.assertEqual(list(target.iterdir()), [])

    def test_initializer_is_called_once_and_not_replaced_by_later_write(self):
        self.assertEqual(SCRIPT.count("\ninitialize_environment_file\n"), 1)
        self.assertEqual(SCRIPT.count('cat > "${ENV_FILE}"'), 1)


if __name__ == "__main__":
    unittest.main()
