import ast
import threading
import unittest
from pathlib import Path


class BootstrapTests(unittest.TestCase):
    def test_late_channel_discovered_and_no_duplicate_workers(self):
        source = Path(__file__).resolve().parents[1] / 'vpngate_manager.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        names = {'ensure_channel_bootstrap', 'bootstrap_supervisor_loop'}
        selected = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[])
        started = []
        channels = []

        class FakeThread:
            def __init__(self, target, args, daemon):
                self.args = args
            def start(self):
                started.append(self.args[0])
            def is_alive(self):
                return True

        class StopLoop(BaseException):
            pass

        class Clock:
            count = 0
            @classmethod
            def sleep(cls, seconds):
                cls.count += 1
                if cls.count == 1:
                    channels.extend([{'id': 'jp', 'awaiting_initial_test': True},
                                     {'id': 'us', 'awaiting_initial_test': True, 'enabled': False}])
                if cls.count == 4:
                    raise StopLoop()

        env = {'threading': type('Threads', (), {'Thread': FakeThread}),
               'bootstrap_workers': {}, 'bootstrap_workers_lock': threading.Lock(),
               'bootstrap_new_channel': lambda cid: None,
               'read_multi_exit_config': lambda: {'channels': channels}, 'time': Clock}
        exec(compile(selected, str(source), 'exec'), env)
        with self.assertRaises(StopLoop):
            env['bootstrap_supervisor_loop']()
        self.assertEqual(started, ['jp'])


if __name__ == '__main__':
    unittest.main()
