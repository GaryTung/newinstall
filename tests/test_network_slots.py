import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from channel_network import ensure_network_slots, channel_network, slot_from_proxy_address
from migrate_network_slots import allocate_legacy, reconcile_template, transport_failure


def load_daemon():
    spec = importlib.util.spec_from_file_location('network_test_daemon', ROOT / 'multi_exit_manager.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StableNetworkTests(unittest.TestCase):
    def test_delete_middle_then_add_does_not_move_or_reuse_survivor_addresses(self):
        config = {'channels': [{'id': cid} for cid in ('a', 'b', 'c', 'd')]}
        ensure_network_slots(config)
        original = {c['id']: channel_network(c['network_slot']) for c in config['channels']}
        config['channels'].pop(1)
        config['channels'].append({'id': 'e'})
        ensure_network_slots(config)
        current = {c['id']: channel_network(c['network_slot']) for c in config['channels']}
        self.assertEqual(current['c'], original['c'])
        self.assertEqual(current['d'], original['d'])
        self.assertNotIn(current['e'], original.values())
        self.assertFalse(ensure_network_slots(config))

    def test_disabled_and_reordered_channels_keep_reserved_slots(self):
        config = {'channels': [{'id': 'a', 'network_slot': 8, 'enabled': False}, {'id': 'b'}]}
        ensure_network_slots(config)
        config['channels'].reverse()
        self.assertFalse(ensure_network_slots(config))
        self.assertEqual({c['id']: c['network_slot'] for c in config['channels']}, {'a': 8, 'b': 9})

    def test_legacy_migration_preserves_healthy_and_repairs_duplicate_targets(self):
        config = {'channels': [{'id': cid} for cid in ('us', 'jp', 'kr', 'jpt', 'jpv')]}
        state = {'channels': {cid: {'status': 'connected', 'proxy_address': ip} for cid, ip in [('us', '10.253.200.2'), ('jp', '10.253.200.6'), ('kr', '10.253.200.10')]}}
        allocate_legacy(config, state)
        targets = {'VPNGATE-COUNTRY-' + c['id'].upper(): channel_network(c['network_slot'])[2] for c in config['channels']}
        template = {'outbounds': [{'tag': tag, 'protocol': 'socks', 'settings': {'servers': [{'address': '10.253.200.18', 'port': 1080}]}} for tag in targets]}
        reconcile_template(template, targets)
        addresses = [o['settings']['servers'][0]['address'] for o in template['outbounds']]
        self.assertEqual(len(set(addresses)), 5)
        self.assertEqual(addresses[:3], ['10.253.200.2', '10.253.200.6', '10.253.200.10'])
        self.assertEqual(slot_from_proxy_address('10.253.200.18'), 5)

    def test_only_transport_failures_are_reset_by_migration(self):
        self.assertTrue(transport_failure({'error': 'TCP: Connection timed out'}))
        self.assertFalse(transport_failure({'error': '日本线路已排除 KDDI 服务商'}))
        self.assertFalse(transport_failure({'error': '真实出口 经IPPure判定为非住宅IP'}))

    def test_failure_in_one_channel_does_not_blacklist_another(self):
        daemon = load_daemon()
        with tempfile.TemporaryDirectory() as directory:
            daemon.DEEP_FAILURES_FILE = Path(directory) / 'failures.json'
            daemon.VERIFIED_EXITS_FILE = Path(directory) / 'verified.json'
            daemon.NODES_FILE = Path(directory) / 'nodes.json'
            node = {'id': 'JP_test', 'country': '日本', 'ip_type': 'residential', 'probe_status': 'available'}
            daemon.write_json(daemon.NODES_FILE, [node])
            daemon.mark_exit_verified('JP_test', '1.2.3.4', 'JP')
            daemon.mark_deep_failure('JP_test', 'Connection timed out', 'broken')
            good = {'id': 'good', 'country': '日本', 'ip_type': 'residential_only', 'tested_only': True}
            self.assertEqual(len(daemon.select_candidates(good)), 1)
            self.assertEqual(daemon.select_candidates({**good, 'id': 'broken'}), [])
            self.assertIn('JP_test', daemon.verified_exit_records())
            daemon.clear_deep_failure('JP_test', 'good')
            self.assertIn('broken:JP_test', daemon.deep_failure_records())

    def test_reconcile_removes_only_stale_managed_address(self):
        daemon = load_daemon()
        calls = []
        def fake_run(command, **kwargs):
            calls.append(command)
            return type('Result', (), {'stdout': json.dumps([{'addr_info': [
                {'local': '10.253.200.17', 'prefixlen': 30},
                {'local': '10.253.200.13', 'prefixlen': 30},
                {'local': '192.0.2.1', 'prefixlen': 24},
            ]}])})()
        with patch.object(daemon, 'run', fake_run):
            daemon.reconcile_interface_address([], 'vh-test', '10.253.200.13')
        self.assertEqual([c for c in calls if 'del' in c], [['ip', 'addr', 'del', '10.253.200.17/30', 'dev', 'vh-test']])


if __name__ == '__main__':
    unittest.main()
