import ast
import importlib.util
import json
import sqlite3
import threading
import time
import unittest
from pathlib import Path


class BootstrapTests(unittest.TestCase):
    def test_initial_detection_does_not_become_a_manual_pin(self):
        source = (Path(__file__).resolve().parents[1] / 'vpngate_manager.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'mark_channel_ready')
        assignments = [node for node in ast.walk(function) if isinstance(node, ast.Assign)]
        self.assertFalse(any(
            any(isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name) and target.value.id == 'channel'
                and isinstance(target.slice, ast.Constant) and target.slice.value == 'preferred_node_id'
                for target in item.targets)
            for item in assignments
        ))

    def test_node_display_names_are_chinese_country_and_creation_date(self):
        source = (Path(__file__).resolve().parents[1] / 'vpngate_manager.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        names = {'normalized_country_name', 'channel_display_name'}
        selected = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[])
        env = {'Any': object, 'time': time, 'vpn_utils': type('V', (), {'COUNTRY_TRANSLATIONS': {}}),
               'server_node_name': lambda name: '236.' + name}
        exec(compile(selected, 'names', 'exec'), env)
        stamp = time.mktime(time.strptime('20260905', '%Y%m%d'))
        self.assertEqual(env['channel_display_name']({'country': '日本', 'protocol': 'vless', 'inbound_port': 7866, 'created_at': stamp}), '236.日本-VLESS-7866-20260905')
        self.assertIn('names[str(direct["subId"])] = server_node_name("服务器直连")', source)

    def test_same_country_and_protocol_can_use_different_ports(self):
        source = (Path(__file__).resolve().parents[1] / 'vpngate_manager.py').read_text(encoding='utf-8')
        self.assertNotIn('configured.has(country)', source)
        self.assertNotIn('已经存在相同协议的线路，请选择另一协议', source)
        self.assertIn('已被其他线路使用', source)

    def test_manual_ip_selection_is_saved_and_wakes_only_changed_channel(self):
        manager = (Path(__file__).resolve().parents[1] / 'vpngate_manager.py').read_text(encoding='utf-8')
        daemon = (Path(__file__).resolve().parents[1] / 'multi_exit_manager.py').read_text(encoding='utf-8')
        self.assertIn('payload.preferred_node_id=preferredNodeId', manager)
        self.assertIn('wake_multi_exit_service()', manager)
        self.assertIn('candidate.get("probe_status") != "available"', manager)
        self.assertIn('WAKE_EVENT.wait(', daemon)

    def test_fresh_direct_inbound_accepts_server_suffix_name(self):
        source = Path(__file__).resolve().parents[1] / 'xui_provision.py'
        spec = importlib.util.spec_from_file_location('xui_provision_for_name_test', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        inbound, _, _ = module.make_inbound(
            'vless', 24129, '/cert.pem', '/key.pem', '161.33.194.236', '236.服务器直连'
        )
        self.assertEqual(inbound['remark'], '236.服务器直连')

    def test_fingerprint_browser_socks_is_authenticated_and_country_routed(self):
        root = Path(__file__).resolve().parents[1]
        manager = (root / 'vpngate_manager.py').read_text(encoding='utf-8')
        provision_source = (root / 'xui_multi_provision.py').read_text(encoding='utf-8')
        for marker in (
            '启用指纹浏览器 SOCKS5', 'copyChannelSocks',
            'socks_username', 'socks_password', 'SOCKS5本身不加密',
        ):
            self.assertIn(marker, manager)
        self.assertIn('"auth": "password"', provision_source)
        self.assertNotIn('"auth": "noauth"', provision_source)
        self.assertIn('socks-country-', provision_source)

        source = root / 'xui_multi_provision.py'
        spec = importlib.util.spec_from_file_location('xui_multi_socks_route_test', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        db = sqlite3.connect(':memory:')
        db.execute('create table settings(id integer primary key, key text unique, value text)')
        module.update_xray_template(db, [{
            'outbound_tag': 'VPNGATE-COUNTRY-JP', 'proxy_address': '10.240.1.2',
            'inbound_tag': 'country-jp', 'inbound_tags': ['country-jp', 'socks-country-jp'],
        }], 'direct-test', 'direct-test')
        config = json.loads(db.execute(
            "select value from settings where key='xrayTemplateConfig'"
        ).fetchone()[0])
        rule = next(item for item in config['routing']['rules'] if item.get('outboundTag') == 'VPNGATE-COUNTRY-JP')
        self.assertEqual(rule['inboundTag'], ['country-jp', 'socks-country-jp'])
        db.close()

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
