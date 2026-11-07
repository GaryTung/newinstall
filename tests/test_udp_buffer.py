"""Exercise buffer setup with a fake sysctl; never touch host networking."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'configure-udp-buffer.sh').read_text(encoding='utf-8')
FUNCTION = re.search(r'(?ms)^configure_udp_receive_buffer\(\) \{\n.*?^\}', SOURCE).group(0)
WIN_BASH = Path('C:/Program Files/Git/bin/bash.exe')
BASH = str(WIN_BASH) if os.name == 'nt' and WIN_BASH.exists() else shutil.which('bash')


@unittest.skipUnless(BASH, 'Bash required')
class BufferTests(unittest.TestCase):
    def exercise(self, fail=False, existing=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'default').write_text('212992')
            (root / 'max').write_text('212992')
            target = root / 'buffer.conf'
            if existing:
                target.write_text('# previous configuration\n')
            mock = r'''
sysctl() {
  if [[ $1 == -n ]]; then
    case "$2" in
      net.core.rmem_default) cat "$root/default" ;;
      net.core.rmem_max) cat "$root/max" ;;
    esac
  elif [[ $1 == -p ]]; then
    printf 4194304 > "$root/max"
    [[ $fail == 0 ]] || return 1
    printf 4194304 > "$root/default"
  elif [[ $1 == -w ]]; then
    shift
    for item in "$@"; do
      case "$item" in
        net.core.rmem_default=*) printf '%s' "${item#*=}" > "$root/default" ;;
        net.core.rmem_max=*) printf '%s' "${item#*=}" > "$root/max" ;;
      esac
    done
  else return 2; fi
}
'''
            function = FUNCTION.replace('/var/backups/aimilivpn/udp-buffer.XXXXXX', '$root/udp-buffer.XXXXXX')
            command = 'set -Eeuo pipefail\nroot=$1\nfail=$2\n' + mock + function + '\nconfigure_udp_receive_buffer "$root/buffer.conf"\n'
            result = subprocess.run([BASH, '-c', command, 'test', root.as_posix(), str(int(fail))],
                                    capture_output=True, timeout=15)
            if fail:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((root / 'default').read_text(), '212992')
                self.assertEqual((root / 'max').read_text(), '212992')
                self.assertEqual(target.exists(), existing)
                if existing:
                    self.assertEqual(target.read_text(), '# previous configuration\n')
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / 'default').read_text(), '4194304')
                self.assertEqual((root / 'max').read_text(), '4194304')
                self.assertIn('net.core.rmem_default = 4194304', target.read_text())
                self.assertIn('net.core.rmem_max = 4194304', target.read_text())

    def test_fresh_setup(self): self.exercise()
    def test_existing_setup(self): self.exercise(existing=True)
    def test_failure_removes_new_file(self): self.exercise(fail=True)
    def test_failure_restores_existing_file(self): self.exercise(fail=True, existing=True)

    def test_install_and_upgrade_apply_before_xray_start(self):
        install = (ROOT / 'unified-install.sh').read_text(encoding='utf-8')
        upgrade = (ROOT / 'upgrade-dashboard.sh').read_text(encoding='utf-8')
        self.assertLess(install.index('bash "${SCRIPT_DIR}/configure-udp-buffer.sh"'), install.index('systemctl restart x-ui\n'))
        self.assertLess(upgrade.index('bash "$work/configure-udp-buffer.sh"'), upgrade.index('systemctl start x-ui\n'))
        self.assertIn('/etc/sysctl.d/90-hy2-udp-recv.conf', upgrade)
        self.assertIn('net.core.rmem_default=$previous_rmem_default', upgrade)


if __name__ == '__main__': unittest.main()
