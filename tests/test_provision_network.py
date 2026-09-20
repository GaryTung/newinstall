from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("xui_network_test", ROOT / "xui_multi_provision.py")
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)


class ProvisionNetworkTests(unittest.TestCase):
    def test_disabled_deleted_and_reordered_channels_keep_stable_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "channels.json"
            path.write_text(json.dumps({"channels": [
                {"id": "disabled", "enabled": False}, {"id": "jp"}, {"id": "kr"},
            ]}), encoding="utf-8")
            initial = provision.load_channel_config(path)
            self.assertEqual([c["network_slot"] for c in initial["channels"]], [1, 2, 3])
            initial["channels"] = [initial["channels"][2], initial["channels"][1], {"id": "new"}]
            path.write_text(json.dumps(initial), encoding="utf-8")
            updated = provision.load_channel_config(path)
            self.assertEqual({c["id"]: c["network_slot"] for c in updated["channels"]},
                             {"kr": 3, "jp": 2, "new": 4})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), updated)

    def test_partial_provision_uses_persisted_slot_and_preserves_other_route(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            database = directory / "x-ui.db"
            channels = directory / "channels.json"
            result = directory / "result.json"
            with contextlib.closing(sqlite3.connect(database)) as db, db:
                db.executescript("""
                    create table inbounds(id integer primary key, remark text, port integer,
                      protocol text, settings text, stream_settings text, tag text,
                      enable integer, up integer, down integer, last_traffic_reset_time integer);
                    create table settings(id integer primary key, key text unique, value text);
                    create table clients(id integer primary key, email text, sub_id text,
                      uuid text, password text, auth text, flow text, security text,
                      limit_ip integer, total_gb integer, expiry_time integer, enable integer,
                      tg_id integer, comment text, reset integer, created_at integer, updated_at integer);
                    create table client_inbounds(client_id integer, inbound_id integer,
                      flow_override text, created_at integer);
                """)
                db.execute("insert into inbounds values(1,?,?,?,?,?,?,1,0,0,0)", (
                    "服务器直连", 24129, "vless",
                    json.dumps({"clients": [{"id": "direct-uuid", "email": "direct", "subId": "direct-sub"}]}),
                    json.dumps({"tlsSettings": {}}), "in-direct",
                ))
                provision.update_xray_template(db, [{
                    "outbound_tag": "VPNGATE-COUNTRY-KR", "proxy_address": "10.253.200.18",
                    "inbound_tag": "in-kr",
                }], "in-direct", "in-direct")
            channels.write_text(json.dumps({"network_next_slot": 10, "channels": [
                {"id": "off", "enabled": False, "network_slot": 2},
                {"id": "jp", "enabled": True, "network_slot": 9, "country": "日本",
                 "protocol": "trojan", "inbound_port": 11488},
            ]}), encoding="utf-8")
            result.write_text(json.dumps({"channels": [{"id": "kr", "proxy_address": "10.253.200.18"}]}), encoding="utf-8")
            with patch.object(sys, "argv", ["xui-multi-provision", "--channels", str(channels),
                                           "--database", str(database), "--result", str(result),
                                           "--channel-id", "jp"]), contextlib.redirect_stdout(io.StringIO()):
                provision.main()
            with contextlib.closing(sqlite3.connect(database)) as db:
                config = json.loads(db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()[0])
            outbounds = {item["tag"]: item for item in config["outbounds"]}
            self.assertEqual(outbounds["VPNGATE-COUNTRY-JP"]["settings"]["servers"][0]["address"], "10.253.200.34")
            self.assertEqual(outbounds["VPNGATE-COUNTRY-KR"]["settings"]["servers"][0]["address"], "10.253.200.18")
            output = json.loads(result.read_text(encoding="utf-8"))
            self.assertEqual(next(c for c in output["channels"] if c["id"] == "jp")["network_slot"], 9)
            self.assertEqual(next(c for c in output["channels"] if c["id"] == "kr")["proxy_address"], "10.253.200.18")


if __name__ == "__main__":
    unittest.main()
