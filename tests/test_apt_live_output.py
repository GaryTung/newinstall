"""Exercise mocked apt only; never run package installation or need root."""
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
WIN_BASH = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/bin/bash.exe'
BASH = str(WIN_BASH) if os.name == 'nt' and WIN_BASH.exists() else shutil.which('bash')


def function(name):
    return re.search(r'(?ms)^apt_get_wait\(\) \{\n.*?^\}',
                     (ROOT / name).read_text(encoding='utf-8')).group(0)


@unittest.skipUnless(BASH, 'Bash required')
class AptLiveOutputTests(unittest.TestCase):
    def run_mock(self, stub, tail='apt_get_wait install test-package', extra=''):
        with tempfile.TemporaryDirectory() as directory:
            command = ('set -Eeuo pipefail\nexport TMPDIR="$1"\n' + extra + '\n'
                       + function('apt-wait.sh') + '\n' + stub + '\n' + tail)
            result = subprocess.run([BASH, '-c', command, 'apt-test', Path(directory).as_posix()],
                                    capture_output=True, text=True, encoding='utf-8', timeout=10)
            self.assertEqual(list(Path(directory).glob('node-gateway-apt.*')), [])
            return result

    def test_bootstrap_and_shared_function_are_identical(self):
        self.assertEqual(function('install.sh'), function('apt-wait.sh'))

    def test_success_streams_stdout_and_stderr(self):
        result = self.run_mock('apt-get() { echo mock-stdout; echo mock-stderr >&2; }')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('mock-stdout'), 1)
        self.assertEqual(result.stdout.count('mock-stderr'), 1)
        self.assertIn('本步骤完成', result.stdout)

    def test_apt_failure_is_not_masked_by_tee(self):
        result = self.run_mock('apt-get() { echo repository-failure >&2; return 100; }')
        self.assertEqual(result.returncode, 100)
        self.assertEqual(result.stdout.count('repository-failure'), 1)
        self.assertIn('退出码 100', result.stderr)

    def test_tee_failure_is_not_reported_as_success(self):
        result = self.run_mock('apt-get() { echo mock; }; tee() { command cat >/dev/null; return 23; }')
        self.assertEqual(result.returncode, 23)
        self.assertNotIn('本步骤完成', result.stdout)

    def test_lock_retries_then_succeeds(self):
        result = self.run_mock('''apt-get() {
  if [[ ! -f "$TMPDIR/retried" ]]; then
    : > "$TMPDIR/retried"
    echo 'E: Could not get lock: is held by process 99999999' >&2
    return 100
  fi
  echo retry-success
}
sleep() { :; }
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('等待锁释放', result.stdout)
        self.assertEqual(result.stdout.count('retry-success'), 1)

    def test_lock_timeout_preserves_failure(self):
        result = self.run_mock("apt-get() { echo 'E: Could not get lock'; return 100; }",
                               extra='APT_LOCK_TIMEOUT_SECONDS=0')
        self.assertEqual(result.returncode, 100)
        self.assertIn('等待 APT/DPKG 锁超过', result.stderr)

    def test_parent_trap_and_shell_options_preserved(self):
        result = self.run_mock('apt-get() { return 0; }', extra="trap 'echo parent-exit' EXIT",
                               tail='before=$-; apt_get_wait update; [[ "$before" == "$-" ]]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('parent-exit'), 1)

    def test_streams_before_apt_finishes_in_both_entrypoints(self):
        for name in ('install.sh', 'apt-wait.sh'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                command = '''set -Eeuo pipefail
export TMPDIR="$1"
''' + function(name) + '''
apt-get() {
  echo EARLY_OUTPUT
  for ((i=0; i<100; i++)); do
    if [[ -f "$TMPDIR/release" ]]; then echo LATE_OUTPUT; return 0; fi
    sleep 0.05
  done
  return 99
}
apt_get_wait update
'''
                proc = subprocess.Popen([BASH, '-c', command, 'stream-test', Path(directory).as_posix()],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, encoding='utf-8')
                lines = queue.Queue()
                def reader():
                    for line in proc.stdout:
                        lines.put(line)
                    lines.put(None)
                worker = threading.Thread(target=reader, daemon=True)
                worker.start()
                try:
                    while True:
                        line = lines.get(timeout=4)
                        self.assertIsNotNone(line, 'apt finished before streaming early output')
                        if 'EARLY_OUTPUT' in line:
                            break
                    self.assertIsNone(proc.poll(), 'Output must arrive while apt is waiting')
                    Path(directory, 'release').touch()
                    self.assertEqual(proc.wait(timeout=5), 0)
                    worker.join(timeout=2)
                    self.assertEqual(list(Path(directory).glob('node-gateway-apt.*')), [])
                finally:
                    Path(directory, 'release').touch()
                    if proc.poll() is None:
                        proc.wait(timeout=8)
                    worker.join(timeout=2)
                    proc.stdout.close()


if __name__ == '__main__':
    unittest.main()
