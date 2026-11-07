import ast
import contextlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('direct_provision_test', ROOT / 'xui_provision.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
spec2 = importlib.util.spec_from_file_location('multi_direct_test', ROOT / 'xui_multi_provision.py')
m = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(m)


def database(path=':memory:'):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    example, _, _ = p.make_inbound('hysteria', 24129, '/cert', '/key', '198.44.112.13')
    columns = ','.join(k + (' INTEGER' if isinstance(v, int) else ' TEXT') for k, v in example.items())
    db.execute('create table inbounds(id integer primary key,' + columns + ')')
    db.executescript('''
        create table settings(id integer primary key,key text unique,value text);
        create table clients(id integer primary key,email text unique,sub_id text,uuid text,
          password text,auth text,flow text,security text,limit_ip integer,total_gb integer,
          expiry_time integer,enable integer,tg_id integer,comment text,reset integer,
          created_at integer,updated_at integer);
        create table client_inbounds(client_id integer,inbound_id integer,flow_override text,created_at integer);
    ''')
    return db


def args(protocol='hysteria'):
    return SimpleNamespace(protocol=protocol, port=24129, server_ip='198.44.112.13',
                           host='198.44.112.13', cert='/cert', key='/key', proxy_port=7928,
                           sub_port=2096, reserve_port=[3322])


class DirectTests(unittest.TestCase):
    @patch.object(p, 'port_available', return_value=True)
    def test_all_primary_choices_create_three_tls_directs(self, _):
        for primary in ('hysteria', 'vless', 'trojan'):
            with self.subTest(primary=primary), contextlib.closing(database()) as db:
                items = p.ensure_direct_inbounds(db, args(primary))
                self.assertEqual({i['protocol'] for i in items}, {'hysteria', 'vless', 'trojan'})
                self.assertEqual(len({i['port'] for i in items}), 3)
                self.assertEqual(items[0]['port'], 24129)
                for i in items:
                    s = json.loads(i['stream_settings'])
                    self.assertEqual(s['security'], 'tls')
                    self.assertEqual(s['tlsSettings']['certificates'][0]['certificateFile'], '/cert')
                    self.assertEqual(s['network'], 'hysteria' if i['protocol']=='hysteria' else 'tcp')
                cfg = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
                for i in items:
                    self.assertEqual(next(r['outboundTag'] for r in cfg['routing']['rules'] if i['tag'] in r.get('inboundTag', [])), 'direct')
                self.assertEqual(db.execute('select count(*) from clients').fetchone()[0], 3)

    @patch.object(p, 'port_available', return_value=True)
    def test_repeat_keeps_all_ids_ports_and_credentials(self, _):
        with contextlib.closing(database()) as db:
            p.ensure_direct_inbounds(db, args())
            before = [tuple(r) for r in db.execute('select * from inbounds')]
            clients = [tuple(r) for r in db.execute('select * from clients')]
            different = args('trojan'); different.port = 55555
            p.ensure_direct_inbounds(db, different)
            self.assertEqual(before, [tuple(r) for r in db.execute('select * from inbounds')])
            self.assertEqual(clients, [tuple(r) for r in db.execute('select * from clients')])

    def test_extra_ports_skip_database_listener_and_panel(self):
        with contextlib.closing(database()) as db:
            db.execute("insert into inbounds(remark,port) values('unrelated',24130)")
            options = args(); options.reserve_port.append(24131)
            with patch.object(p, 'port_available', side_effect=lambda port, proto: port != 24132):
                items = p.ensure_direct_inbounds(db, options)
            self.assertEqual([i['port'] for i in items], [24129, 24133, 24134])
            self.assertEqual(db.execute("select port from inbounds where remark='unrelated'").fetchone()[0], 24130)

    @patch.object(p, 'port_available', return_value=True)
    def test_country_save_preserves_extra_direct_routes(self, _):
        with contextlib.closing(database()) as db:
            items = p.ensure_direct_inbounds(db, args())
            m.update_xray_template(db, [{'outbound_tag':'VPNGATE-COUNTRY-JP',
                'inbound_tag':'country-jp','proxy_address':'10.253.200.6'}], items[0]['tag'], items[0]['tag'])
            cfg = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
            for i in items:
                self.assertEqual(next(r['outboundTag'] for r in cfg['routing']['rules'] if i['tag'] in r.get('inboundTag', [])), 'direct')

    @patch.object(p, 'port_available', return_value=True)
    def test_extra_subscriptions_discovered_without_result_metadata(self, _):
        source = ast.parse((ROOT/'vpngate_manager.py').read_text(encoding='utf-8'))
        names = {'extra_direct_subscriptions','provisioned_subscription_ids','provisioned_subscription_names'}
        code = ast.Module(body=[n for n in source.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[])
        env = {'Path':Path, 'sqlite3':sqlite3, 'json':json}
        exec(compile(code, 'subscription-test', 'exec'), env)
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder)/'test.db')
            with contextlib.closing(database(path)) as db:
                items = p.ensure_direct_inbounds(db, args()); db.commit()
            extras = env['extra_direct_subscriptions'](path)
            self.assertEqual({e['name'] for e in extras}, {'13.服务器直连-VLESS','13.服务器直连-TROJAN'})
            env.update(extra_direct_subscriptions=lambda:extras,
                       read_json=lambda *a: {'direct':{'subId':'main'},'channels':[]},
                       read_multi_exit_config=lambda:{'channels':[]}, server_node_name=lambda x:'13.'+x)
            self.assertEqual(len(env['provisioned_subscription_ids']()),3)
            self.assertEqual(len(env['provisioned_subscription_names']()),3)
