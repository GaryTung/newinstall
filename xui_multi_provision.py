#!/usr/bin/env python3
"""Create/update one 3x-ui inbound and routed SOCKS outbound per country channel."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import sqlite3
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


def load_json(value, default):
    try:
        return json.loads(value or "")
    except Exception:
        return default


def channel_ip(index):
    slot = index - 1
    third = 200 + (slot // 60)
    fourth = (slot % 60) * 4
    return f"10.253.{third}.{fourth + 2}"


def new_client(protocol, existing=None, existing_protocol=None, display_name=None):
    if existing and existing_protocol == protocol:
        return dict(existing)
    now = int(time.time() * 1000)
    password = secrets.token_urlsafe(18)
    generated_email = re.sub(r"[^A-Za-z0-9_.-]", "-", str(display_name or "")).strip("-.")[:48]
    client = {
        "email": generated_email or "country-" + secrets.token_hex(4), "enable": True,
        "expiryTime": 0, "limitIp": 0, "totalGB": 0,
        "subId": secrets.token_urlsafe(12), "tgId": 0, "reset": 0,
        "comment": "多国家出口自动生成", "created_at": now, "updated_at": now,
    }
    if existing:
        client["email"] = existing.get("email") or client["email"]
        client["subId"] = existing.get("subId") or client["subId"]
    if protocol == "vless":
        client.update({"id": str(uuid.uuid4()), "flow": ""})
    elif protocol == "trojan":
        client.update({"id": str(uuid.uuid4()), "password": password})
    elif protocol == "hysteria":
        client.update({"id": str(uuid.uuid4()), "password": password, "auth": password, "security": "auto"})
    else:
        raise RuntimeError(f"暂不支持自动复制协议 {protocol}")
    return client


def protocol_settings(protocol, client):
    result = {"clients": [client]}
    if protocol == "vless":
        result.setdefault("decryption", "none")
        result.setdefault("fallbacks", [])
    elif protocol == "trojan":
        result.setdefault("fallbacks", [])
    elif protocol == "hysteria":
        result["version"] = 2
    return result


def protocol_stream(source_stream, protocol, client):
    tls = dict(source_stream.get("tlsSettings") or {})
    result = {"network": "tcp", "security": "tls", "tlsSettings": tls}
    if protocol == "hysteria":
        result["network"] = "hysteria"
        result["hysteriaSettings"] = {"version": 2, "udpIdleTimeout": 60}
        result["tlsSettings"]["alpn"] = ["h3"]
        result["finalmask"] = {"udp": [{"type": "salamander", "settings": {"password": client["password"]}}]}
    else:
        result["tlsSettings"]["alpn"] = ["h2", "http/1.1"]
    return result


def remove_normalized_client(db, inbound_id):
    ids = [r[0] for r in db.execute("select client_id from client_inbounds where inbound_id=?", (inbound_id,))]
    db.execute("delete from client_inbounds where inbound_id=?", (inbound_id,))
    for client_id in ids:
        db.execute("delete from clients where id=? and not exists (select 1 from client_inbounds where client_id=?)", (client_id, client_id))


def insert_normalized_client(db, inbound_id, client):
    cursor = db.execute(
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
        (cursor.lastrowid, inbound_id, client.get("flow", ""), client.get("created_at")),
    )


def source_inbound(db):
    row = db.execute(
        """select * from inbounds
        where protocol in ('vless','trojan','hysteria') and remark not like 'COUNTRY:%'
        order by case when remark in ('AUTO-GATEWAY','VPS-DIRECT','服务器直连') then 0 else 1 end, id limit 1"""
    ).fetchone()
    if not row:
        raise RuntimeError("未找到可复制的 VLESS、Trojan 或 Hysteria2 入站")
    return dict(row)


def update_xray_template(db, routes, direct_tag, old_direct_tag, partial=False, direct_only=False):
    row = db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
    if row and str(row[0] or "").strip():
        config = json.loads(row[0])
    else:
        config = default_xray_template()
    prefixes = ("VPNGATE-COUNTRY-",)
    outbounds = config.setdefault("outbounds", [])
    rules = config.setdefault("routing", {}).setdefault("rules", [])
    route_tags = {route["outbound_tag"] for route in routes}
    if partial:
        outbounds[:] = [x for x in outbounds if str(x.get("tag", "")) not in route_tags]
    elif not direct_only:
        outbounds[:] = [x for x in outbounds if not str(x.get("tag", "")).startswith(prefixes)]
    route_inbound_tags = {route["inbound_tag"] for route in routes}
    if direct_only:
        rules[:] = [x for x in rules if direct_tag not in (x.get("inboundTag") or []) and old_direct_tag not in (x.get("inboundTag") or [])]
        rules.append({"type": "field", "inboundTag": [direct_tag], "outboundTag": "direct", "enabled": True})
    elif partial:
        rules[:] = [x for x in rules if str(x.get("outboundTag", "")) not in route_tags and not route_inbound_tags.intersection(x.get("inboundTag") or [])]
    else:
        rules[:] = [
            x for x in rules
            if not str(x.get("outboundTag", "")).startswith(prefixes)
            and direct_tag not in (x.get("inboundTag") or [])
            and old_direct_tag not in (x.get("inboundTag") or [])
        ]
        rules.append({
            "type": "field", "inboundTag": [direct_tag],
            "outboundTag": "direct", "enabled": True,
        })
    for route in routes:
        outbounds.append({
            "tag": route["outbound_tag"], "protocol": "socks",
            "settings": {"servers": [{"address": route["proxy_address"], "port": 1080, "users": []}]},
        })
        rules.append({
            "type": "field", "inboundTag": [route["inbound_tag"]],
            "outboundTag": route["outbound_tag"], "enabled": True,
        })
    row = db.execute("select id from settings where key='xrayTemplateConfig'").fetchone()
    if row:
        db.execute("update settings set value=? where key='xrayTemplateConfig'", (compact(config),))
    else:
        db.execute("insert into settings(key,value) values('xrayTemplateConfig',?)", (compact(config),))


def delete_channel(database: Path, result_path: Path, channel_id: str):
    """Delete exactly one generated country inbound, client, route and result entry."""
    cid = re.sub(r"[^a-z0-9-]", "", str(channel_id or "").lower())[:12]
    if not cid:
        raise RuntimeError("删除线路 ID 无效")
    backup = database.with_name(database.name + ".multi-exit-delete-backup-" + time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(database, backup)
    previous = load_json(result_path.read_text(encoding="utf-8") if result_path.exists() else "", {})
    previous_item = next((item for item in previous.get("channels", []) if str(item.get("id") or "").lower() == cid), {})
    db = sqlite3.connect(database)
    db.row_factory = sqlite3.Row
    try:
        remark = "COUNTRY:" + cid
        inbound = db.execute("select * from inbounds where remark=?", (remark,)).fetchone()
        inbound_tag = str(inbound["tag"] if inbound else previous_item.get("inbound_tag") or "")
        if inbound:
            remove_normalized_client(db, inbound["id"])
            db.execute("delete from inbounds where id=?", (inbound["id"],))
        row = db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
        if row:
            template = json.loads(row[0])
            outbound_tag = "VPNGATE-COUNTRY-" + cid.upper()
            template["outbounds"] = [
                item for item in template.get("outbounds", [])
                if str(item.get("tag") or "") != outbound_tag
            ]
            template.setdefault("routing", {})["rules"] = [
                item for item in template.get("routing", {}).get("rules", [])
                if str(item.get("outboundTag") or "") != outbound_tag
                and (not inbound_tag or inbound_tag not in (item.get("inboundTag") or []))
            ]
            db.execute("update settings set value=? where key='xrayTemplateConfig'", (compact(template),))
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

    previous["channels"] = [
        item for item in previous.get("channels", [])
        if str(item.get("id") or "").lower() != cid
    ]
    result_path.write_text(json.dumps(previous, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(result_path, 0o600)
    print(json.dumps({"ok": True, "deleted": cid, "backup": str(backup)}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--channels", default="/var/lib/aimilivpn-multiexit/channels.json")
    parser.add_argument("--database", default="/etc/x-ui/x-ui.db")
    parser.add_argument("--result", default="/etc/x-ui/multi-exit-result.json")
    parser.add_argument("--channel-id", default="")
    parser.add_argument("--delete-channel-id", default="")
    parser.add_argument("--direct-only", action="store_true")
    args = parser.parse_args()
    if args.delete_channel_id:
        delete_channel(Path(args.database), Path(args.result), args.delete_channel_id)
        return
    channel_config = load_json(Path(args.channels).read_text(encoding="utf-8"), {})
    channels = channel_config.get("channels", [])
    channels = [c for c in channels if c.get("enabled", True)]
    if not channels:
        raise RuntimeError("没有启用的国家通道")

    database = Path(args.database)
    backup = database.with_name(database.name + ".multi-exit-backup-" + time.strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(database, backup)
    db = sqlite3.connect(database)
    db.row_factory = sqlite3.Row
    results = []
    try:
        source = source_inbound(db)
        old_direct_tag = source["tag"]
        old_direct_protocol = source["protocol"]
        direct_protocol = str(channel_config.get("direct_protocol") or old_direct_protocol)
        if direct_protocol not in ("vless", "trojan", "hysteria"):
            raise RuntimeError("直连节点协议必须是 vless、trojan 或 hysteria")
        source_stream = load_json(source["stream_settings"], {})
        source_settings = load_json(source["settings"], {})
        source_client = (source_settings.get("clients") or [None])[0]
        direct_client = source_client
        direct_tag = old_direct_tag
        if not args.channel_id:
            direct_client = new_client(direct_protocol, source_client, old_direct_protocol)
            direct_tag = f"in-{source['port']}-{'udp' if direct_protocol == 'hysteria' else 'tcp'}"
            remove_normalized_client(db, source["id"])
            db.execute(
                "update inbounds set remark='服务器直连',protocol=?,tag=?,settings=?,stream_settings=? where id=?",
                (direct_protocol, direct_tag, compact(protocol_settings(direct_protocol, direct_client)),
                 compact(protocol_stream(source_stream, direct_protocol, direct_client)), source["id"]),
            )
            insert_normalized_client(db, source["id"], direct_client)
            if not args.direct_only:
                desired_remarks = {"COUNTRY:" + str(c["id"]).lower() for c in channels}
                stale = db.execute("select id,remark from inbounds where remark like 'COUNTRY:%'").fetchall()
                for row in stale:
                    if row["remark"] not in desired_remarks:
                        remove_normalized_client(db, row["id"])
                        db.execute("delete from inbounds where id=?", (row["id"],))
        columns = [r[1] for r in db.execute("pragma table_info(inbounds)")]
        for index, channel in enumerate(channels, 1):
            cid = str(channel["id"]).lower()
            if args.direct_only:
                continue
            if args.channel_id and cid != args.channel_id.lower():
                continue
            remark = "COUNTRY:" + cid
            port = int(channel["inbound_port"])
            conflict = db.execute("select id,remark from inbounds where port=? and remark<>?", (port, remark)).fetchone()
            existing = db.execute("select * from inbounds where remark=?", (remark,)).fetchone()
            if conflict:
                raise RuntimeError(f"端口 {port} 已被入站 {conflict['remark']} 使用")
            old_client = None
            old_protocol = None
            if existing:
                old_protocol = existing["protocol"]
                old_settings = load_json(existing["settings"], {})
                old_client = (old_settings.get("clients") or [None])[0]
                remove_normalized_client(db, existing["id"])
                db.execute("delete from inbounds where id=?", (existing["id"],))
            protocol = str(channel.get("protocol") or old_protocol or old_direct_protocol)
            if protocol not in ("vless", "trojan", "hysteria"):
                raise RuntimeError(f"线路 {cid} 的协议无效")
            client = new_client(protocol, old_client, old_protocol, channel.get("name"))
            item = dict(source)
            item.pop("id", None)
            item.update({
                "remark": remark, "port": port, "enable": 1,
                "tag": f"in-{port}-{'udp' if protocol == 'hysteria' else 'tcp'}",
                "protocol": protocol,
                "settings": compact(protocol_settings(protocol, client)),
                "stream_settings": compact(protocol_stream(source_stream, protocol, client)),
                "up": 0, "down": 0, "last_traffic_reset_time": 0,
            })
            names = [name for name in item if name in columns]
            cursor = db.execute(
                f"insert into inbounds({','.join(names)}) values({','.join('?' for _ in names)})",
                [item[name] for name in names],
            )
            insert_normalized_client(db, cursor.lastrowid, client)
            results.append({
                "id": cid, "name": channel.get("name", cid), "country": channel["country"],
                "port": port, "protocol": protocol, "subId": client.get("subId"),
                "inbound_tag": item["tag"], "outbound_tag": "VPNGATE-COUNTRY-" + cid.upper(),
                "proxy_address": channel_ip(index),
            })
        if args.channel_id and not results:
            raise RuntimeError(f"未找到线路 {args.channel_id}")
        update_xray_template(db, results, direct_tag, old_direct_tag, partial=bool(args.channel_id), direct_only=args.direct_only)
        db.commit()
    except Exception:
        db.rollback(); db.close(); shutil.copy2(backup, database); raise
    finally:
        try: db.close()
        except Exception: pass

    output = {
        "backup": str(backup),
        "direct": {
            "name": "服务器直连",
            "port": source["port"],
            "protocol": direct_protocol,
            "subId": direct_client.get("subId"),
            "inbound_tag": direct_tag,
            "outbound_tag": "direct",
        },
        "channels": results,
    }
    if args.channel_id or args.direct_only:
        previous = load_json(Path(args.result).read_text(encoding="utf-8") if Path(args.result).exists() else "", {})
        if args.direct_only:
            output["channels"] = previous.get("channels", [])
        else:
            previous_channels = [x for x in previous.get("channels", []) if x.get("id") != args.channel_id.lower()]
            output["channels"] = previous_channels + results
    result_path = Path(args.result)
    result_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(result_path, 0o600)
    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
