#!/usr/bin/env python3
"""Run isolated per-country VPNGate exits and expose one SOCKS port per channel."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path


APP_DIR = Path(os.environ.get("VPNGATE_APP_DIR", "/opt/aimilivpn"))
SOURCE_DATA = Path(os.environ.get("VPNGATE_DATA_DIR", "/var/lib/aimilivpn"))
if not (SOURCE_DATA / "nodes.json").exists() and Path("/opt/aimilivpn/vpngate_data/nodes.json").exists():
    SOURCE_DATA = Path("/opt/aimilivpn/vpngate_data")
DATA_DIR = Path(os.environ.get("MULTI_EXIT_DATA_DIR", "/var/lib/aimilivpn-multiexit"))
CONFIG_FILE = DATA_DIR / "channels.json"
STATE_FILE = DATA_DIR / "state.json"
DEEP_FAILURES_FILE = DATA_DIR / "deep_failures.json"
VERIFIED_EXITS_FILE = DATA_DIR / "verified_exits.json"
AUTH_FILE = SOURCE_DATA / "vpngate_auth.txt"
NODES_FILE = SOURCE_DATA / "nodes.json"
PROXY_PORT = 1080
FORCED_HOSTING_EXIT_IPS = {
    "47.153.119.84",  # Ping0 hosting result; exact-IP override only
    "61.76.60.93",  # AS4766 Korea Telecom; Ping0 hosting result overrides IPPure residential
    "118.47.249.153",  # AS4766 KT; Ping0 hosting result overrides IPPure residential
}
JAPAN_BLOCKED_ASNS = {"AS2516"}
JAPAN_BLOCKED_PROVIDER_MARKERS = ("kddi",)
KOREA_BLOCKED_ASNS = {"AS4766"}
KOREA_BLOCKED_PROVIDER_MARKERS = ("korea telecom", "kornet", "kixs", "kt corporation")
CHECK_SECONDS = int(os.environ.get("MULTI_EXIT_CHECK_SECONDS", "15"))
RETRY_SECONDS = int(os.environ.get("MULTI_EXIT_RETRY_SECONDS", "15"))
HEALTH_FAILURE_THRESHOLD = int(os.environ.get("MULTI_EXIT_HEALTH_FAILURE_THRESHOLD", "2"))
RECOVERY_COOLDOWN_RETRY_SECONDS = int(os.environ.get("MULTI_EXIT_RECOVERY_RETRY_SECONDS", "60"))
FULL_EXIT_VERIFIED_TTL_SECONDS = int(os.environ.get("MULTI_EXIT_VERIFIED_TTL_SECONDS", "1200"))
MAX_CONNECT_CANDIDATES = int(os.environ.get("MULTI_EXIT_MAX_CONNECT_CANDIDATES", "8"))
FAILURE_BACKOFF_SECONDS = (10 * 60, 30 * 60, 2 * 3600, 6 * 3600)
HEALTH_ENDPOINTS = (
    "https://api.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://ifconfig.me/ip",
)
WAKE_EVENT = threading.Event()

COUNTRY_ALIASES = {
    "美国": {"美国", "United States", "US"},
    "日本": {"日本", "Japan", "JP"},
    "韩国": {"韩国", "South Korea", "Korea Republic of", "KR"},
}

COUNTRY_CODES = {
    "美国": "US", "United States": "US", "US": "US",
    "日本": "JP", "Japan": "JP", "JP": "JP",
    "韩国": "KR", "South Korea": "KR", "Korea Republic of": "KR", "KR": "KR",
}


def run(args, *, check=True, capture=False, timeout=30):
    return subprocess.run(
        [str(x) for x in args], check=check, timeout=timeout,
        text=True, capture_output=capture,
    )


def read_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(temp, 0o600)
    temp.replace(path)


def deep_failure_records():
    value = read_json(DEEP_FAILURES_FILE, {})
    return value if isinstance(value, dict) else {}


def verified_exit_records():
    value = read_json(VERIFIED_EXITS_FILE, {})
    return value if isinstance(value, dict) else {}


def mark_exit_verified(node_id, exit_ip, country_code="", provider="", ip_type=""):
    """Remember nodes that passed the complete, routed egress validation."""
    node_id = str(node_id or "")
    if not node_id:
        return
    records = verified_exit_records()
    previous = dict(records.get(node_id) or {})
    now = time.time()
    if (
        str(previous.get("exit_ip") or "") == str(exit_ip or "")
        and now - float(previous.get("verified_at") or 0) < 300
    ):
        return
    records[node_id] = {
        "verified_at": now,
        "exit_ip": str(exit_ip or ""),
        "country_code": str(country_code or "").upper(),
        "provider": str(provider or ""),
        "ip_type": str(ip_type or ""),
    }
    write_json(VERIFIED_EXITS_FILE, records)


def mark_deep_failure(node_id, error):
    """Record that a reachable endpoint failed the complete VPN exit test."""
    node_id = str(node_id or "")
    if not node_id:
        return
    records = deep_failure_records()
    previous = dict(records.get(node_id) or {})
    failures = int(previous.get("failures") or 0) + 1
    now = time.time()
    records[node_id] = {
        "status": "deep_unavailable",
        "failures": failures,
        "failed_at": now,
        "blocked_until": now + FAILURE_BACKOFF_SECONDS[min(failures - 1, len(FAILURE_BACKOFF_SECONDS) - 1)],
        "error": str(error or "完整 VPN 出口验证失败")[-500:],
    }
    write_json(DEEP_FAILURES_FILE, records)
    verified = verified_exit_records()
    if node_id in verified:
        verified.pop(node_id, None)
        write_json(VERIFIED_EXITS_FILE, verified)


def clear_deep_failure(node_id):
    records = deep_failure_records()
    node_id = str(node_id or "")
    if node_id in records:
        records.pop(node_id, None)
        write_json(DEEP_FAILURES_FILE, records)


def default_config():
    return {
        "version": 1,
        "channels": [
            {"id": "us", "name": "美国线路", "inbound_port": 7825, "country": "美国", "ip_type": "residential_preferred", "enabled": True, "tested_only": True, "awaiting_initial_test": True},
            {"id": "jp", "name": "日本线路", "inbound_port": 7866, "country": "日本", "ip_type": "all", "enabled": True, "tested_only": True, "awaiting_initial_test": True},
            {"id": "kr", "name": "韩国线路", "inbound_port": 7888, "country": "韩国", "ip_type": "all", "enabled": True, "tested_only": True, "awaiting_initial_test": True},
        ],
    }


def load_config():
    cfg = read_json(CONFIG_FILE, None)
    if not isinstance(cfg, dict):
        cfg = default_config()
        write_json(CONFIG_FILE, cfg)
    channels = []
    seen_ids, seen_ports = set(), set()
    for index, raw in enumerate(cfg.get("channels", []), 1):
        item = dict(raw) if isinstance(raw, dict) else {}
        cid = str(item.get("id") or f"line{index}").lower().strip()
        if not cid.replace("-", "").isalnum() or cid in seen_ids:
            continue
        port = int(item.get("inbound_port") or 0)
        if not 1024 <= port <= 65535 or port in seen_ports:
            continue
        seen_ids.add(cid); seen_ports.add(port)
        item.update({"id": cid, "inbound_port": port, "enabled": bool(item.get("enabled", True))})
        item["country"] = str(item.get("country") or "").strip()
        item["ip_type"] = str(item.get("ip_type") or "all").strip()
        channels.append(item)
    cfg["channels"] = channels
    return cfg


def channel_network(index):
    # One /30 per channel: host=.1, namespace=.2
    slot = index - 1
    third = 200 + (slot // 60)
    fourth = (slot % 60) * 4
    base = f"10.253.{third}.{fourth}"
    return f"10.253.{third}.{fourth}/30", f"10.253.{third}.{fourth + 1}", f"10.253.{third}.{fourth + 2}"


def ns_name(channel):
    return "avpn-" + channel["id"][:10]


def process_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def terminate_pid(pid):
    if not pid or not process_alive(pid):
        return
    try:
        os.kill(int(pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    for _ in range(30):
        if not process_alive(pid):
            return
        time.sleep(0.1)
    try:
        os.kill(int(pid), signal.SIGKILL)
    except ProcessLookupError:
        pass


def stop_namespace_processes(ns):
    """Fail closed by removing stale VPN/proxy processes from this channel only."""
    result = run(["ip", "netns", "pids", ns], check=False, capture=True)
    for value in result.stdout.split():
        if value.isdigit():
            terminate_pid(int(value))


def remove_channel_namespace(channel_id, runtime):
    """Remove only the deleted channel's processes, namespace, veth and firewall rules."""
    cid = str(channel_id or "")
    ns = str(runtime.get("namespace") or ("avpn-" + cid[:10]))
    host_if = ("vh-" + cid)[:15]
    stop_runtime(runtime)
    stop_namespace_processes(ns)
    for direction in (("-i", host_if), ("-o", host_if)):
        run(["iptables", "-D", "FORWARD", direction[0], direction[1], "-j", "ACCEPT"], check=False)
    proxy_address = str(runtime.get("proxy_address") or "")
    if proxy_address:
        try:
            subnet = str(ipaddress.ip_network(f"{proxy_address}/30", strict=False))
            run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"], check=False)
        except ValueError:
            pass
    run(["ip", "netns", "del", ns], check=False)
    run(["ip", "link", "del", host_if], check=False)


def ensure_namespace(channel, index):
    ns = ns_name(channel)
    _, host_ip, ns_ip = channel_network(index)
    host_if = ("vh-" + channel["id"])[:15]
    ns_if = ("vn-" + channel["id"])[:15]
    existing = run(["ip", "netns", "list"], check=False, capture=True).stdout
    if ns not in existing.split():
        run(["ip", "netns", "add", ns])
    if run(["ip", "link", "show", host_if], check=False).returncode != 0:
        run(["ip", "link", "add", host_if, "type", "veth", "peer", "name", ns_if])
        run(["ip", "link", "set", ns_if, "netns", ns])
    run(["ip", "addr", "replace", f"{host_ip}/30", "dev", host_if])
    run(["ip", "link", "set", host_if, "up"])
    run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])
    run(["ip", "netns", "exec", ns, "ip", "addr", "replace", f"{ns_ip}/30", "dev", ns_if])
    run(["ip", "netns", "exec", ns, "ip", "link", "set", ns_if, "up"])
    run(["ip", "netns", "exec", ns, "ip", "route", "replace", "default", "via", host_ip])
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
    subnet, _, _ = channel_network(index)
    check_nat = run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"], check=False)
    if check_nat.returncode != 0:
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"])
    for direction in (("-i", host_if), ("-o", host_if)):
        check_fwd = run(["iptables", "-C", "FORWARD", direction[0], direction[1], "-j", "ACCEPT"], check=False)
        if check_fwd.returncode != 0:
            run(["iptables", "-A", "FORWARD", direction[0], direction[1], "-j", "ACCEPT"])
    return ns, ns_ip


def country_matches(node, country):
    actual = str(node.get("country") or node.get("CountryLong") or node.get("country_short") or "").strip()
    aliases = COUNTRY_ALIASES.get(country, {country})
    return actual.casefold() in {x.casefold() for x in aliases}


def japan_kddi_rejection(channel, node=None, provider="", asn=""):
    """Reject KDDI/AS2516 only for Japan channels, without affecting other countries."""
    country = str(channel.get("country") or "").strip()
    if COUNTRY_CODES.get(country) != "JP":
        return ""
    node = node if isinstance(node, dict) else {}
    provider_text = " ".join(str(value or "") for value in (
        provider,
        node.get("owner"), node.get("as_name"),
        node.get("exit_owner"), node.get("exit_as_name"),
    )).casefold()
    asn_text = " ".join(str(value or "").upper() for value in (
        asn, node.get("asn"), node.get("exit_asn"),
    ))
    if any(marker in provider_text for marker in JAPAN_BLOCKED_PROVIDER_MARKERS):
        return "日本线路已排除 KDDI 服务商"
    if any(blocked_asn in asn_text for blocked_asn in JAPAN_BLOCKED_ASNS):
        return "日本线路已排除 KDDI AS2516"
    return ""


def korea_kt_rejection(channel, node=None, provider="", asn=""):
    """Reject KT/Korea Telecom/AS4766 only for South Korea channels."""
    country = str(channel.get("country") or "").strip()
    if COUNTRY_CODES.get(country) != "KR":
        return ""
    node = node if isinstance(node, dict) else {}
    provider_values = [str(value or "").strip().casefold() for value in (
        provider,
        node.get("owner"), node.get("as_name"),
        node.get("exit_owner"), node.get("exit_as_name"),
    )]
    provider_text = " ".join(provider_values)
    asn_text = " ".join(str(value or "").upper() for value in (
        asn, node.get("asn"), node.get("exit_asn"),
    ))
    if "kt" in provider_values:
        return "韩国线路已排除 KT 服务商"
    if any(marker in provider_text for marker in KOREA_BLOCKED_PROVIDER_MARKERS):
        return "韩国线路已排除 KT/Korea Telecom 服务商"
    if any(blocked_asn in asn_text for blocked_asn in KOREA_BLOCKED_ASNS):
        return "韩国线路已排除 KT AS4766"
    return ""


def ip_type_rank(node, mode):
    value = str(node.get("exit_ip_type") or node.get("ip_type") or "unknown").lower()
    residential = value in {"residential", "mobile", "住宅", "移动"}
    hosting = value in {"hosting", "datacenter", "机房"}
    if mode == "residential_only":
        return 0 if residential else 99
    if mode == "hosting_only":
        return 0 if hosting else 99
    if mode == "residential_preferred":
        return 0 if residential else (1 if not hosting else 2)
    return 0


def history_entry(history, node_id):
    return history.setdefault(str(node_id or ""), {
        "successful_connections": 0,
        "consecutive_failures": 0,
        "total_uptime_seconds": 0,
        "longest_uptime_seconds": 0,
        "last_success_at": 0,
        "last_failure_at": 0,
        "cooldown_until": 0,
    })


def record_node_success(history, node_id):
    entry = history_entry(history, node_id)
    entry["successful_connections"] = int(entry.get("successful_connections") or 0) + 1
    entry["consecutive_failures"] = 0
    entry["cooldown_until"] = 0
    entry["last_success_at"] = time.time()


def record_node_failure(history, node_id):
    entry = history_entry(history, node_id)
    failures = int(entry.get("consecutive_failures") or 0) + 1
    entry["consecutive_failures"] = failures
    entry["last_failure_at"] = time.time()
    entry["cooldown_until"] = time.time() + FAILURE_BACKOFF_SECONDS[min(failures - 1, len(FAILURE_BACKOFF_SECONDS) - 1)]


def record_runtime_end(history, runtime, failed=False):
    node_id = str(runtime.get("node_id") or "")
    connected_at = float(runtime.get("connected_at") or 0)
    if not node_id:
        return
    entry = history_entry(history, node_id)
    if connected_at:
        uptime = max(0, int(time.time() - connected_at))
        entry["total_uptime_seconds"] = int(entry.get("total_uptime_seconds") or 0) + uptime
        entry["longest_uptime_seconds"] = max(int(entry.get("longest_uptime_seconds") or 0), uptime)
    if failed:
        record_node_failure(history, node_id)


def select_candidates(channel, exclude=None, history=None, recovery=False):
    exclude = set(exclude or [])
    history = history if isinstance(history, dict) else {}
    nodes = read_json(NODES_FILE, [])
    selected = []
    now = time.time()
    preferred = str(channel.get("preferred_node_id") or "")
    deep_failures = deep_failure_records()
    verified_exits = verified_exit_records()
    for node in nodes if isinstance(nodes, list) else []:
        nid = str(node.get("id") or "")
        if not nid or nid in exclude or not country_matches(node, channel["country"]):
            continue
        if japan_kddi_rejection(channel, node=node):
            continue
        if korea_kt_rejection(channel, node=node):
            continue
        deep_failure = deep_failures.get(nid) or {}
        if nid != preferred and float(deep_failure.get("blocked_until") or 0) > now:
            continue
        node_history = history.get(nid, {})
        # A deliberate manual selection overrides historical backoff once.
        # If the live connection fails, connect_channel still falls through to
        # the remaining same-country candidates in this attempt.
        if nid != preferred and float(node_history.get("cooldown_until") or 0) > now:
            last_failure = float(node_history.get("last_failure_at") or 0)
            if not recovery or now - last_failure < RECOVERY_COOLDOWN_RETRY_SECONDS:
                continue
        rank = ip_type_rank(node, channel.get("ip_type", "all"))
        if rank >= 99:
            continue
        status = str(node.get("probe_status") or "pending")
        if channel.get("tested_only") and status != "available":
            continue
        status_rank = 0 if status == "available" else (1 if status in {"pending", "testing"} else 3)
        latency = int(node.get("latency_ms") or node.get("ping") or 999999)
        score = int(node.get("score") or 0)
        verified_at = float((verified_exits.get(nid) or {}).get("verified_at") or 0)
        verified_rank = 0 if now - verified_at <= FULL_EXIT_VERIFIED_TTL_SECONDS else 1
        selected.append((
            0 if nid == preferred else 1,
            rank,
            verified_rank,
            status_rank,
            -int(node_history.get("successful_connections") or 0),
            -int(node_history.get("total_uptime_seconds") or 0),
            -int(node_history.get("longest_uptime_seconds") or 0),
            latency,
            -score,
            node,
        ))
    selected.sort(key=lambda row: row[:-1])
    return [row[-1] for row in selected]


def channel_signature(channel):
    value = {
        key: channel.get(key)
        for key in ("country", "ip_type", "preferred_node_id", "restart_token", "enabled")
    }
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:16]


def start_proxy(ns, work_dir):
    log = open(work_dir / "proxy.log", "ab", buffering=0)
    code = "import proxy_server; proxy_server.start_proxy_server('0.0.0.0',1080)"
    env = os.environ.copy()
    env.update({"PYTHONPATH": str(APP_DIR), "LOCAL_PROXY_HOST": "0.0.0.0", "LOCAL_PROXY_PORT": str(PROXY_PORT)})
    return subprocess.Popen(["ip", "netns", "exec", ns, "env", *[f"{k}={v}" for k, v in env.items() if k in {"PYTHONPATH", "LOCAL_PROXY_HOST", "LOCAL_PROXY_PORT"}], "python3", "-c", code], stdout=log, stderr=subprocess.STDOUT)


def start_openvpn(ns, work_dir, node):
    config = work_dir / "client.ovpn"
    config_text = str(node.get("config_text") or "")
    if not config_text and node.get("config_file"):
        try:
            config_text = Path(str(node.get("config_file"))).read_text(encoding="utf-8", errors="replace")
        except OSError:
            config_text = ""
    if not config_text:
        raise RuntimeError("OpenVPN configuration is missing")
    config.write_text(config_text, encoding="utf-8")
    log_path = work_dir / "openvpn.log"
    log_path.write_text("", encoding="utf-8")
    cmd = ["ip", "netns", "exec", ns, "openvpn", "--config", str(config), "--dev", "tun0", "--dev-type", "tun", "--route-nopull", "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6", "--auth-user-pass", str(AUTH_FILE), "--auth-nocache", "--connect-timeout", "15", "--connect-retry-max", "1", "--verb", "3", "--log", str(log_path)]
    process = subprocess.Popen(cmd)
    deadline = time.time() + 20
    while time.time() < deadline:
        if process.poll() is not None:
            break
        text = log_path.read_text(encoding="utf-8", errors="replace")
        if "Initialization Sequence Completed" in text:
            run(["ip", "netns", "exec", ns, "ip", "route", "replace", "default", "dev", "tun0", "table", "100"], check=False)
            run(["ip", "netns", "exec", ns, "ip", "rule", "del", "oif", "tun0", "table", "100"], check=False)
            run(["ip", "netns", "exec", ns, "ip", "rule", "add", "oif", "tun0", "table", "100"], check=False)
            return process
        if "AUTH_FAILED" in text or "Exiting due to fatal error" in text:
            break
        time.sleep(0.5)
    terminate_pid(process.pid)
    raise RuntimeError((log_path.read_text(encoding="utf-8", errors="replace")[-500:] or "OpenVPN timeout").replace("\n", " "))


def proxy_health(ns_ip):
    started = time.time()
    errors = []
    for endpoint in HEALTH_ENDPOINTS:
        result = run(
            ["curl", "-4fsS", "--max-time", "6", "--socks5-hostname", f"{ns_ip}:{PROXY_PORT}", endpoint],
            check=False, capture=True, timeout=10,
        )
        ip = (result.stdout or "").strip()
        try:
            valid_ip = ipaddress.ip_address(ip).version == 4
        except ValueError:
            valid_ip = False
        if result.returncode == 0 and valid_ip:
            return True, ip, int((time.time() - started) * 1000)
        errors.append((result.stderr or f"{endpoint} unavailable").strip()[-120:])
    return False, "；".join(x for x in errors if x)[-360:] or "proxy unavailable", int((time.time() - started) * 1000)


def ippure_exit_info(ns_ip):
    result = run([
        "curl", "-4fsS", "--max-time", "15", "--socks5-hostname",
        f"{ns_ip}:{PROXY_PORT}", "https://my.ippure.com/v1/info",
    ], check=False, capture=True, timeout=20)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or "IPPure unavailable").strip()[-240:])
    try:
        data = json.loads(result.stdout or "{}")
    except Exception as exc:
        raise RuntimeError(f"IPPure response invalid: {exc}") from exc
    residential = data.get("isResidential")
    ip_type = "residential" if residential is True else ("hosting" if residential is False else "")
    return {
        "ip": str(data.get("ip") or "").strip(),
        "ip_type": ip_type,
        "provider": str(data.get("asOrganization") or ""),
        "asn": f"AS{data.get('asn')}" if data.get("asn") else "",
        "risk_score": int(data.get("fraudScore") or 0),
        "classification_source": "ippure-live",
    }


def enforce_exit_ip_type(channel, exit_ip, info):
    mode = str(channel.get("ip_type") or "all")
    actual_ip = str(info.get("ip") or "")
    if actual_ip and actual_ip != exit_ip:
        raise RuntimeError(f"IPPure出口 {actual_ip} 与实际出口 {exit_ip} 不一致")
    if exit_ip in FORCED_HOSTING_EXIT_IPS:
        info["ip_type"] = "hosting"
        info["classification_source"] = "ping0-exact-ip-override"
    ip_type = str(info.get("ip_type") or "")
    if mode == "residential_only" and ip_type != "residential":
        raise RuntimeError(f"真实出口 {exit_ip} 经IPPure判定为非住宅IP，已拒绝用于仅住宅线路")
    if mode == "hosting_only" and ip_type != "hosting":
        raise RuntimeError(f"真实出口 {exit_ip} 经IPPure判定为非机房IP，已拒绝用于仅机房线路")


def exit_country_code(exit_ip, node):
    node_ip = str(node.get("exit_ip") or node.get("ip") or "").strip()
    if node_ip == exit_ip:
        cached = str(node.get("exit_country_short") or node.get("geo_country_short") or "").upper()
        if len(cached) == 2:
            return cached
    result = run([
        "curl", "-4fsS", "--max-time", "8",
        f"http://ip-api.com/json/{exit_ip}?fields=status,country,countryCode,query",
    ], check=False, capture=True, timeout=12)
    try:
        data = json.loads(result.stdout or "{}")
        if data.get("status") == "success":
            return str(data.get("countryCode") or "").upper()
    except Exception:
        pass
    return ""


def enforce_country_lock(channel, node, exit_ip):
    expected = COUNTRY_CODES.get(str(channel.get("country") or "").strip())
    if not expected:
        expected = str(node.get("country_short") or node.get("CountryShort") or node.get("geo_country_short") or "").upper()
    actual = exit_country_code(exit_ip, node)
    if not expected:
        raise RuntimeError(f"无法识别锁定国家 {channel.get('country')}")
    if not actual:
        raise RuntimeError(f"无法验证出口 {exit_ip} 的实际国家，已按严格国家锁定拒绝连接")
    if actual != expected:
        raise RuntimeError(f"出口 {exit_ip} 实际国家为 {actual}，不符合锁定国家 {expected}，已拒绝连接")
    return actual


def stop_runtime(runtime):
    terminate_pid(runtime.get("openvpn_pid"))
    terminate_pid(runtime.get("proxy_pid"))


def connect_channel(channel, index, previous, history):
    work = DATA_DIR / channel["id"]
    work.mkdir(parents=True, exist_ok=True)
    ns, ns_ip = ensure_namespace(channel, index)
    stop_namespace_processes(ns)
    failed = list(previous.get("recent_failures") or [])[-8:]
    candidates = select_candidates(channel, history=history)
    if not candidates:
        # Do not leave an offline country waiting hours for historical backoff.
        # Live retries remain rate-limited by last_failure_at.
        candidates = select_candidates(channel, history=history, recovery=True)
    if not candidates:
        raise RuntimeError(f"没有找到 {channel['country']} 候选节点，请先在主后台更新节点资料")
    last_error = ""
    for node in candidates[:MAX_CONNECT_CANDIDATES]:
        vpn = None
        try:
            vpn = start_openvpn(ns, work, node)
            proxy = start_proxy(ns, work)
            time.sleep(1)
            ok, detail, latency = proxy_health(ns_ip)
            if not ok:
                raise RuntimeError(detail)
            actual_country_code = enforce_country_lock(channel, node, detail)
            exit_info = ippure_exit_info(ns_ip)
            provider_rejection = japan_kddi_rejection(
                channel, node=node,
                provider=exit_info.get("provider", ""),
                asn=exit_info.get("asn", ""),
            )
            if provider_rejection:
                raise RuntimeError(provider_rejection)
            provider_rejection = korea_kt_rejection(
                channel, node=node,
                provider=exit_info.get("provider", ""),
                asn=exit_info.get("asn", ""),
            )
            if provider_rejection:
                raise RuntimeError(provider_rejection)
            enforce_exit_ip_type(channel, detail, exit_info)
            record_node_success(history, node.get("id"))
            clear_deep_failure(node.get("id"))
            mark_exit_verified(
                node.get("id"), detail, actual_country_code,
                exit_info.get("provider", ""), exit_info.get("ip_type", ""),
            )
            return {
                "id": channel["id"], "name": channel.get("name") or channel["id"],
                "country": channel["country"], "inbound_port": channel["inbound_port"],
                "proxy_address": ns_ip, "proxy_port": PROXY_PORT,
                "namespace": ns, "node_id": node.get("id"), "exit_ip": detail,
                "status": "connected", "latency_ms": latency,
                "exit_country_code": actual_country_code,
                "exit_ip_type": exit_info.get("ip_type", ""),
                "exit_provider": exit_info.get("provider", ""),
                "exit_asn": exit_info.get("asn", ""),
                "exit_risk_score": exit_info.get("risk_score", 0),
                "exit_classification_source": exit_info.get("classification_source", ""),
                "openvpn_pid": vpn.pid, "proxy_pid": proxy.pid,
                "connected_at": time.time(), "checked_at": time.time(), "recent_failures": failed,
            }
        except Exception as exc:
            last_error = str(exc)
            if vpn:
                terminate_pid(vpn.pid)
            stop_namespace_processes(ns)
            failed_id = str(node.get("id") or "")
            failed.append(failed_id)
            record_node_failure(history, failed_id)
            mark_deep_failure(failed_id, last_error)
    raise RuntimeError(last_error or "所有候选节点连接失败")


def daemon():
    signal.signal(signal.SIGUSR1, lambda _signum, _frame: WAKE_EVENT.set())
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    state = read_json(STATE_FILE, {"channels": {}})
    state.setdefault("channels", {})
    if int(state.get("history_policy_version") or 0) < 1:
        state["node_history"] = {}
        state["history_policy_version"] = 1
    history = state.setdefault("node_history", {})
    first_pass = True
    while True:
        cfg = load_config()
        desired = {c["id"]: c for c in cfg["channels"] if c.get("enabled")}
        for cid, runtime in list(state.get("channels", {}).items()):
            if cid not in desired:
                record_runtime_end(history, runtime, failed=False)
                remove_channel_namespace(cid, runtime)
                state["channels"].pop(cid, None)

        health_targets = []
        for channel in cfg["channels"]:
            if not channel.get("enabled") or channel.get("awaiting_initial_test"):
                continue
            runtime = state.get("channels", {}).get(channel["id"], {})
            if (
                process_alive(runtime.get("openvpn_pid"))
                and process_alive(runtime.get("proxy_pid"))
                and runtime.get("config_signature") == channel_signature(channel)
            ):
                health_targets.append((channel["id"], runtime.get("proxy_address", "")))
        health_results = {}
        if health_targets:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(health_targets))) as executor:
                futures = {
                    executor.submit(proxy_health, proxy_address): channel_id
                    for channel_id, proxy_address in health_targets
                }
                for future in concurrent.futures.as_completed(futures):
                    channel_id = futures[future]
                    try:
                        health_results[channel_id] = future.result()
                    except Exception as exc:
                        health_results[channel_id] = (False, str(exc), 0)

        for index, channel in enumerate(cfg["channels"], 1):
            if not channel.get("enabled"):
                continue
            runtime = state.setdefault("channels", {}).get(channel["id"], {})
            if channel.get("awaiting_initial_test"):
                stop_runtime(runtime)
                stop_namespace_processes(ns_name(channel))
                runtime.update({
                    "id": channel["id"], "name": channel.get("name"), "country": channel.get("country"),
                    "inbound_port": channel.get("inbound_port"), "status": "testing",
                    "error": "正在首次检测本国候选节点", "exit_ip": "", "exit_country_code": "",
                    "node_id": "", "openvpn_pid": 0, "proxy_pid": 0, "checked_at": time.time(),
                })
                state["channels"][channel["id"]] = runtime
                write_json(STATE_FILE, state)
                continue
            processes_alive = process_alive(runtime.get("openvpn_pid")) and process_alive(runtime.get("proxy_pid"))
            healthy = processes_alive
            signature = channel_signature(channel)
            provider_rejection = japan_kddi_rejection(
                channel,
                provider=runtime.get("exit_provider", ""),
                asn=runtime.get("exit_asn", ""),
            )
            if healthy and provider_rejection:
                mark_deep_failure(runtime.get("node_id"), provider_rejection)
                record_runtime_end(history, runtime, failed=False)
                healthy = False
                runtime.update({"status": "switching", "error": provider_rejection})
            provider_rejection = korea_kt_rejection(
                channel,
                provider=runtime.get("exit_provider", ""),
                asn=runtime.get("exit_asn", ""),
            )
            if healthy and provider_rejection:
                mark_deep_failure(runtime.get("node_id"), provider_rejection)
                record_runtime_end(history, runtime, failed=False)
                healthy = False
                runtime.update({"status": "switching", "error": provider_rejection})
            forced_exit_rejection = (
                str(channel.get("ip_type") or "") == "residential_only"
                and str(runtime.get("exit_ip") or "") in FORCED_HOSTING_EXIT_IPS
            )
            if healthy and forced_exit_rejection:
                reason = f"真实出口 {runtime.get('exit_ip')} 已按 Ping0 精确规则判定为机房IP"
                mark_deep_failure(runtime.get("node_id"), reason)
                record_runtime_end(history, runtime, failed=False)
                healthy = False
                runtime.update({
                    "status": "switching", "error": reason,
                    "exit_ip_type": "hosting",
                    "exit_classification_source": "ping0-exact-ip-override",
                })
            if healthy and runtime.get("config_signature") != signature:
                healthy = False
                runtime.update({"status": "switching", "error": "线路设置已修改，正在仅重连当前国家"})
            if healthy:
                ok, detail, latency = health_results.get(
                    channel["id"],
                    (False, "health result unavailable", 0),
                )
                runtime.update({"checked_at": time.time(), "latency_ms": latency})
                if ok:
                    try:
                        if detail != runtime.get("exit_ip") or not runtime.get("exit_country_code"):
                            nodes = read_json(NODES_FILE, [])
                            node = next((n for n in nodes if str(n.get("id")) == str(runtime.get("node_id"))), {})
                            runtime["exit_country_code"] = enforce_country_lock(channel, node, detail)
                        runtime.update({
                            "status": "connected", "exit_ip": detail, "error": "",
                            "consecutive_health_failures": 0,
                        })
                        mark_exit_verified(
                            runtime.get("node_id"), detail, runtime.get("exit_country_code", ""),
                            runtime.get("exit_provider", ""), runtime.get("exit_ip_type", ""),
                        )
                    except Exception as exc:
                        healthy = False
                        mark_deep_failure(runtime.get("node_id"), str(exc))
                        record_runtime_end(history, runtime, failed=True)
                        runtime.update({
                            "status": "failed", "error": str(exc)[-500:], "exit_ip": "", "exit_country_code": "",
                            "exit_ip_type": "", "exit_provider": "", "exit_asn": "",
                            "exit_risk_score": 0, "exit_classification_source": "",
                        })
                else:
                    failures = int(runtime.get("consecutive_health_failures") or 0) + 1
                    runtime["consecutive_health_failures"] = failures
                    if failures >= HEALTH_FAILURE_THRESHOLD:
                        healthy = False
                        mark_deep_failure(runtime.get("node_id"), detail)
                        record_runtime_end(history, runtime, failed=True)
                        runtime.update({
                            "status": "failed", "error": detail, "exit_ip": "", "exit_country_code": "",
                            "exit_ip_type": "", "exit_provider": "", "exit_asn": "",
                            "exit_risk_score": 0, "exit_classification_source": "",
                        })
                    else:
                        runtime.update({
                            "status": "connected",
                            "error": f"健康检测暂时失败 {failures}/{HEALTH_FAILURE_THRESHOLD}：{detail}",
                        })
            if not healthy:
                previous = dict(runtime)
                if not processes_alive and previous.get("node_id"):
                    if first_pass:
                        record_runtime_end(history, previous, failed=False)
                        old_entry = history_entry(history, previous.get("node_id"))
                        old_entry["successful_connections"] = max(1, int(old_entry.get("successful_connections") or 0))
                        old_entry["consecutive_failures"] = 0
                        old_entry["cooldown_until"] = 0
                    else:
                        mark_deep_failure(previous.get("node_id"), "VPN 进程异常退出")
                        record_runtime_end(history, previous, failed=True)
                stop_runtime(runtime)
                stop_namespace_processes(ns_name(channel))
                runtime.update({"status": "connecting", "error": "", "exit_ip": "", "exit_country_code": "", "node_id": "", "openvpn_pid": 0, "proxy_pid": 0, "checked_at": time.time()})
                write_json(STATE_FILE, state)
                try:
                    state["channels"][channel["id"]] = connect_channel(channel, index, previous, history)
                    state["channels"][channel["id"]]["config_signature"] = signature
                    state["channels"][channel["id"]]["consecutive_health_failures"] = 0
                except Exception as exc:
                    stop_namespace_processes(ns_name(channel))
                    runtime.update({
                        "status": "failed", "error": str(exc)[-500:], "exit_ip": "", "exit_country_code": "",
                        "exit_ip_type": "", "exit_provider": "", "exit_asn": "",
                        "exit_risk_score": 0, "exit_classification_source": "",
                        "node_id": "", "openvpn_pid": 0, "proxy_pid": 0, "checked_at": time.time(),
                    })
                    state["channels"][channel["id"]] = runtime
            write_json(STATE_FILE, state)
        first_pass = False
        WAKE_EVENT.wait(CHECK_SECONDS if all(x.get("status") == "connected" for x in state.get("channels", {}).values()) else RETRY_SECONDS)
        WAKE_EVENT.clear()


def status():
    print(json.dumps({"config": load_config(), "state": read_json(STATE_FILE, {"channels": {}})}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("daemon", "status"), nargs="?", default="daemon")
    args = parser.parse_args()
    daemon() if args.command == "daemon" else status()
