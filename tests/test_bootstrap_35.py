import ast
import threading
import time
import unittest
from pathlib import Path


class BootstrapTests(unittest.TestCase):
    def test_node_display_names_are_chinese_country_and_creation_date(self):
        source = (Path(__file__).resolve().parents[1] / 'vpngate_manager.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        names = {'normalized_country_name', 'channel_display_name'}
        selected = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[])
        env = {'Any': object, 'time': time, 'vpn_utils': type('V', (), {'COUNTRY_TRANSLATIONS': {}})}
        exec(compile(selected, 'names', 'exec'), env)
        stamp = time.mktime(time.strptime('20260905', '%Y%m%d'))
        self.assertEqual(env['channel_display_name']({'country': '日本', 'created_at': stamp}), '日本-20260905')
        self.assertIn('names[str(direct["subId"])] = "服务器直连"', source)
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
