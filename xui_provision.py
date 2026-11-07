#!/usr/bin/env python3
"""Provision one TLS inbound and route it through the local VPNGate SOCKS proxy."""

import argparse
import json
import os
import secrets
import socket
import shutil
import sqlite3
import sys
import time
import uuid
from pathlib import Path


def default_xray_template():
    """Return the 3x-ui v3 built-in baseline used when a fresh DB has no row."""
    return {
        "api": {"services": ["HandlerService", "LoggerService", "StatsService", "RoutingService"], "tag": "api"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": 62789, "protocol": "tunnel",
            "settings": {"rewriteAddress": "127.0.0.1"}, "tag": "api",
        }],
        "log": {"access": "none", "dnsLog": False, "error": "", "loglevel": "warning", "maskAddress": ""},
        "metrics": {"listen": "127.0.0.1:11111", "tag": "metrics_out"},
        "outbounds": [
            {"protocol": "freedom", "settings": {"domainStrategy": "AsIs", "finalRules": [
                {"action": "block", "ip": ["geoip:private"]}, {"action": "allow"},
            ]}, "tag": "direct"},
            {"protocol": "blackhole", "settings": {}, "tag": "blocked"},
        ],
        "policy": {
            "levels": {"0": {"statsUserDownlink": True, "statsUserUplink": True}},
            "system": {"statsInboundDownlink": True, "statsInboundUplink": True,
                       "statsOutboundDownlink": False, "statsOutboundUplink": False},
        },
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"inboundTag": ["api"], "outboundTag": "api", "type": "field"},
            {"ip": ["geoip:private"], "outboundTag": "blocked", "type": "field"},
            {"outboundTag": "blocked", "protocol": ["bittorrent"], "type": "field"},
        ]},
        "stats": {},
    }


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


def make_inbound(protocol, port, cert_file, key_file, server_name, display_name="服务器直连"):
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
        "remark": display_name,
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
    if row and str(row[0] or "").strip():
        config = json.loads(row[0])
    else:
        config = default_xray_template()
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
    rules[:] = [r for r in rules if tag not in (r.get("inboundTag") or [])]
    rules.insert(0, {"type": "field", "inboundTag": [tag], "outboundTag": "direct", "enabled": True})
    upsert_setting(db, "xrayTemplateConfig", compact(config))


def insert_inbound(db, inbound):
    columns = {r[1] for r in db.execute("pragma table_info(inbounds)")}
    names = [name for name in inbound if name in columns]
    cursor = db.execute(f"insert into inbounds ({','.join(names)}) values ({','.join('?' for _ in names)})",
                        [inbound[name] for name in names])
    inbound_id = cursor.lastrowid
    c = json.loads(inbound['settings'])['clients'][0]
    fields = {'email': c['email'], 'sub_id': c['subId'], 'uuid': c.get('id'),
              'password': c.get('password'), 'auth': c.get('auth'), 'flow': c.get('flow', ''),
              'security': c.get('security', 'auto'), 'limit_ip': 0, 'total_gb': 0,
              'expiry_time': 0, 'enable': 1, 'tg_id': 0, 'comment': c.get('comment', ''),
              'reset': 0, 'created_at': c['created_at'], 'updated_at': c['updated_at']}
    cursor = db.execute(f"insert into clients ({','.join(fields)}) values ({','.join('?' for _ in fields)})", list(fields.values()))
    db.execute('insert into client_inbounds(client_id,inbound_id,flow_override,created_at) values(?,?,?,?)',
               (cursor.lastrowid, inbound_id, c.get('flow', ''), c['created_at']))
    return inbound


def port_available(port, protocol):
    # Check both families and the actual transport without reserving a live listener.
    kind = socket.SOCK_DGRAM if protocol == 'hysteria' else socket.SOCK_STREAM
    for family, address in [(socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')]:
        try:
            with socket.socket(family, kind) as probe:
                probe.bind((address, port))
        except OSError as exc:
            import errno
            if family == socket.AF_INET6 and exc.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
                continue
            return False
    return True


def ensure_direct_inbounds(db, args):
    """Create missing protocols only; retain existing ports, identities and credentials."""
    primary = db.execute("""select * from inbounds where remark in
        ('AUTO-GATEWAY','VPS-DIRECT','服务器直连') or remark like '%.服务器直连'
        order by id limit 1""").fetchone()
    suffix = args.server_ip.strip().split('.')
    prefix = suffix[-1] + '.' if len(suffix) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in suffix) else ''
    base_name = prefix + '服务器直连'
    used = {r[0] for r in db.execute('select port from inbounds')}
    used.update({22, 80, 443, 3322, 8787, 2097, 7928, 62789, 11111, 7866, 7888, args.sub_port})
    used.update(args.reserve_port)
    if primary:
        primary = dict(primary)
    else:
        if args.port in used or not port_available(args.port, args.protocol):
            raise RuntimeError(f'直连端口 {args.port} 已占用或为保留端口')
        primary, _, _ = make_inbound(args.protocol, args.port, args.cert, args.key, args.host, base_name)
        insert_inbound(db, primary)
        used.add(args.port)
    results = [primary]
    for protocol in ('hysteria', 'vless', 'trojan'):
        if protocol == primary['protocol']:
            continue
        name = base_name + '-' + ('HY2' if protocol == 'hysteria' else protocol.upper())
        existing = db.execute('select * from inbounds where remark=?', (name,)).fetchone()
        if existing:
            if existing['protocol'] != protocol:
                raise RuntimeError(f'{name} 协议与预期不符，未修改已有节点')
            results.append(dict(existing))
            continue
        start = int(primary['port']) + 1
        candidates = list(range(start, 65536)) + list(range(1024, start))
        port = next((p for p in candidates if p not in used and port_available(p, protocol)), None)
        if port is None:
            raise RuntimeError('没有可用的直连端口')
        inbound, _, _ = make_inbound(protocol, port, args.cert, args.key, args.host, name)
        insert_inbound(db, inbound)
        used.add(port)
        results.append(inbound)
    for inbound in results:
        modify_xray_template(db, inbound['tag'], args.proxy_port)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", choices=("vless", "trojan", "hysteria"), required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--server-ip", default="")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--proxy-port", type=int, default=7928)
    parser.add_argument("--sub-port", type=int, default=2096)
    parser.add_argument("--reserve-port", type=int, action="append", default=[])
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
        direct_inbounds = ensure_direct_inbounds(db, args)
        primary = direct_inbounds[0]
        sub_id = json.loads(primary['settings'])['clients'][0]['subId']
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
        "protocol": primary['protocol'],
        "port": primary['port'],
        "directs": [{"name": i['remark'], "protocol": i['protocol'], "port": i['port'],
                     "subId": json.loads(i['settings'])['clients'][0]['subId']} for i in direct_inbounds],
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
