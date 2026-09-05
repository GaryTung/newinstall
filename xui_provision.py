#!/usr/bin/env python3
"""Provision one TLS inbound and route it through the local VPNGate SOCKS proxy."""

import argparse
import json
import os
import secrets
import shutil
import sqlite3
import sys
import time
import uuid
from pathlib import Path


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def upsert_setting(db, key, value):
    row = db.execute("select id from settings where key=?", (key,)).fetchone()
    if row:
        db.execute("update settings set value=? where key=?", (str(value), key))
    else:
        db.execute("insert into settings(key,value) values(?,?)", (key, str(value)))


def tls_stream(cert_file, key_file, server_name):
    return {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "serverName": server_name,
            "minVersion": "1.2",
            "maxVersion": "1.3",
            "alpn": ["h2", "http/1.1"],
            "certificates": [{
                "certificateFile": cert_file,
                "keyFile": key_file,
                "ocspStapling": 0,
                "oneTimeLoading": False,
                "usage": "encipherment",
                "buildChain": False,
            }],
        },
    }


def make_inbound(protocol, port, cert_file, key_file, server_name):
    client_id = str(uuid.uuid4())
    password = secrets.token_urlsafe(18)
    sub_id = secrets.token_urlsafe(12)
    email = "gateway-" + secrets.token_hex(4)
    now_ms = int(time.time() * 1000)
    base_client = {
        "email": email,
        "enable": True,
        "expiryTime": 0,
        "limitIp": 0,
        "totalGB": 0,
        "subId": sub_id,
        "tgId": 0,
        "reset": 0,
        "comment": "自动生成",
        "created_at": now_ms,
        "updated_at": now_ms,
    }
    tag_suffix = "udp" if protocol == "hysteria" else "tcp"
    tag = f"in-{port}-{tag_suffix}"
    if protocol == "vless":
        client = {**base_client, "id": client_id, "flow": ""}
        settings = {"clients": [client], "decryption": "none", "fallbacks": []}
        stream = tls_stream(cert_file, key_file, server_name)
    elif protocol == "trojan":
        client = {**base_client, "id": client_id, "password": password}
        settings = {"clients": [client], "fallbacks": []}
        stream = tls_stream(cert_file, key_file, server_name)
    else:
        client = {
            **base_client,
            "id": client_id,
            "password": password,
            "auth": password,
            "security": "auto",
        }
        settings = {"clients": [client], "version": 2}
        stream = tls_stream(cert_file, key_file, server_name)
        stream["network"] = "hysteria"
        stream["hysteriaSettings"] = {"version": 2, "udpIdleTimeout": 60}
        stream["tlsSettings"]["alpn"] = ["h3"]
        stream["finalmask"] = {"udp": [{"type": "salamander", "settings": {"password": password}}]}
    inbound = {
        "user_id": 1,
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": "VPS-DIRECT",
        "sub_sort_index": 1,
        "enable": 1,
        "expiry_time": 0,
        "traffic_reset": "never",
        "traffic_reset_day": 1,
        "last_traffic_reset_time": 0,
        "listen": "0.0.0.0",
        "port": port,
        "protocol": protocol,
        "settings": compact(settings),
        "stream_settings": compact(stream),
        "tag": tag,
        "sniffing": compact({"enabled": False}),
        "node_id": None,
        "share_addr_strategy": "custom",
        "share_addr": server_name,
        "origin_node_guid": "",
    }
    return inbound, sub_id, tag


def modify_xray_template(db, tag, proxy_port):
    row = db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
    if not row:
        raise RuntimeError("3x-ui 缺少 xrayTemplateConfig 设置")
    config = json.loads(row[0])
    outbounds = config.setdefault("outbounds", [])
    outbounds[:] = [o for o in outbounds if o.get("tag") != "VPNGATE-AUTO"]
    outbounds.append({
        "tag": "VPNGATE-AUTO",
        "protocol": "socks",
        "settings": {"servers": [{"address": "127.0.0.1", "port": proxy_port, "users": []}]},
    })
    routing = config.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    rules[:] = [r for r in rules if r.get("outboundTag") != "VPNGATE-AUTO"]
    rules.append({"type": "field", "inboundTag": [tag], "outboundTag": "direct", "enabled": True})
    upsert_setting(db, "xrayTemplateConfig", compact(config))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", choices=("vless", "trojan", "hysteria"), required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--proxy-port", type=int, default=7928)
    parser.add_argument("--sub-port", type=int, default=2096)
    parser.add_argument("--database", default="/etc/x-ui/x-ui.db")
    parser.add_argument("--result", default="/etc/x-ui/gateway-result.json")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.sub_port <= 65535:
        raise SystemExit("端口必须在 1-65535 范围内")
    for path in (args.cert, args.key, args.database):
        if not Path(path).is_file():
            raise SystemExit(f"文件不存在: {path}")

    database = Path(args.database)
    backup = database.with_name(database.name + ".gateway-backup-" + time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(database, backup)
    db = sqlite3.connect(database)
    db.row_factory = sqlite3.Row
    try:
        inbound, sub_id, tag = make_inbound(
            args.protocol, args.port, args.cert, args.key, args.host
        )
        conflict = db.execute(
            "select id,remark from inbounds where port=? and remark not in ('AUTO-GATEWAY','VPS-DIRECT')", (args.port,)
        ).fetchone()
        if conflict:
            raise RuntimeError(f"端口 {args.port} 已被入站 {conflict['remark']} 使用")
        old_ids = [r[0] for r in db.execute("select id from inbounds where remark in ('AUTO-GATEWAY','VPS-DIRECT')")]
        for old_id in old_ids:
            linked = [r[0] for r in db.execute("select client_id from client_inbounds where inbound_id=?", (old_id,))]
            db.execute("delete from client_inbounds where inbound_id=?", (old_id,))
            for client_row_id in linked:
                db.execute("delete from clients where id=? and not exists (select 1 from client_inbounds where client_id=?)", (client_row_id, client_row_id))
        db.execute("delete from inbounds where remark in ('AUTO-GATEWAY','VPS-DIRECT')")
        columns = [r[1] for r in db.execute("pragma table_info(inbounds)")]
        names = [name for name in inbound if name in columns]
        placeholders = ",".join("?" for _ in names)
        cursor = db.execute(
            f"insert into inbounds ({','.join(names)}) values ({placeholders})",
            [inbound[name] for name in names],
        )
        inbound_id = cursor.lastrowid
        client = json.loads(inbound["settings"])["clients"][0]
        client_cursor = db.execute(
            """insert into clients
            (email,sub_id,uuid,password,auth,flow,security,limit_ip,total_gb,expiry_time,enable,tg_id,comment,reset,created_at,updated_at)
            values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (client.get("email"), client.get("subId"), client.get("id"), client.get("password"),
             client.get("auth"), client.get("flow", ""), client.get("security", "auto"),
             0, 0, 0, 1, 0, client.get("comment", ""), 0,
             client.get("created_at"), client.get("updated_at")),
        )
        db.execute(
            "insert into client_inbounds(client_id,inbound_id,flow_override,created_at) values(?,?,?,?)",
            (client_cursor.lastrowid, inbound_id, client.get("flow", ""), client.get("created_at")),
        )
        modify_xray_template(db, tag, args.proxy_port)
        upsert_setting(db, "subEnable", "true")
        upsert_setting(db, "subPath", "/sub/")
        upsert_setting(db, "subClashPath", "/clash/")
        upsert_setting(db, "subPort", args.sub_port)
        upsert_setting(db, "subDomain", args.host)
        upsert_setting(db, "subCertFile", args.cert)
        upsert_setting(db, "subKeyFile", args.key)
        upsert_setting(db, "subClashEnable", "true")
        db.commit()
    except Exception:
        db.rollback()
        db.close()
        shutil.copy2(backup, database)
        raise
    finally:
        try:
            db.close()
        except Exception:
            pass

    result = {
        "protocol": args.protocol,
        "port": args.port,
        "host": args.host,
        "subId": sub_id,
        "subscription": f"https://{args.host}:{args.sub_port}/sub/{sub_id}",
        "clash": f"https://{args.host}:{args.sub_port}/clash/{sub_id}",
        "backup": str(backup),
    }
    result_path = Path(args.result)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(result_path, 0o600)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"配置失败: {exc}", file=sys.stderr)
        raise SystemExit(1)
