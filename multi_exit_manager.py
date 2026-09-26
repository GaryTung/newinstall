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
sys.path.insert(0, str(APP_DIR if (APP_DIR / "channel_network.py").exists() else Path(__file__).resolve().parent))
from channel_network import channel_network, channel_slot, ensure_network_slots, managed_address
from channel_policy import provider_rejection as channel_provider_rejection, failure_record, ip_type_rank as shared_ip_type_rank, effective_ip_type
SOURCE_DATA = Path(os.environ.get("VPNGATE_DATA_DIR", "/var/lib/aimilivpn"))
try:
    if not (SOURCE_DATA / "nodes.json").exists() and Path("/opt/aimilivpn/vpngate_data/nodes.json").exists():
        SOURCE_DATA = Path("/opt/aimilivpn/vpngate_data")
except PermissionError:
    # Importing diagnostics/tests as a non-root user must not require live data.
    pass
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
CHANNEL_HISTORY_MAX_ENTRIES = 256
LEGACY_HISTORY_MAX_ENTRIES = 512
DEEP_FAILURE_MAX_ENTRIES = 512
DEEP_FAILURE_RETENTION_SECONDS = 7 * 24 * 3600
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


def bounded_failure_records(records, now=None):
    """Drop expired failure history and cap disk growth on small gateways."""
    now = time.time() if now is None else float(now)
    active = []
    for key, value in records.items() if isinstance(records, dict) else []:
        if not isinstance(value, dict):
            continue
        failed_at = float(value.get("failed_at") or 0)
        blocked_until = float(value.get("blocked_until") or 0)
        if blocked_until > now or failed_at >= now - DEEP_FAILURE_RETENTION_SECONDS:
            active.append((max(failed_at, blocked_until), str(key), value))
    active.sort(reverse=True)
    return {key: value for _stamp, key, value in active[:DEEP_FAILURE_MAX_ENTRIES]}


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


def mark_deep_failure(node_id, error, channel_id=""):
    """Record that a reachable endpoint failed the complete VPN exit test."""
    node_id = str(node_id or "")
    if not node_id:
        return
    records = bounded_failure_records(deep_failure_records())
    key = f"{channel_id}:{node_id}" if channel_id else node_id
    previous = dict(records.get(key) or {})
    failures = int(previous.get("failures") or 0) + 1
    now = time.time()
    records[key] = {
        "channel_id": channel_id,
        "status": "deep_unavailable",
        "failures": failures,
        "failed_at": now,
        "blocked_until": now + FAILURE_BACKOFF_SECONDS[min(failures - 1, len(FAILURE_BACKOFF_SECONDS) - 1)],
        "error": str(error or "完整 VPN 出口验证失败")[-500:],
    }
    write_json(DEEP_FAILURES_FILE, records)
    # One channel's failure must not erase another channel's verified exit.


def clear_deep_failure(node_id, channel_id=""):
    records = deep_failure_records()
    node_id = str(node_id or "")
    keys = {node_id, f"{channel_id}:{node_id}"} if channel_id else {node_id}
    if any(key in records for key in keys):
        for key in keys:
            records.pop(key, None)
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


def country_identity(value):
    country = str(value or "").strip()
    return COUNTRY_CODES.get(country, country.casefold())


def compact_history_map(history, country_code="", protected=None, limit=CHANNEL_HISTORY_MAX_ENTRIES):
    """Retain only relevant/recent node history instead of cloning every country."""
    country_code = str(country_code or "").upper()
    protected = {str(value) for value in (protected or []) if value}
    ranked = []
    for node_id, record in history.items() if isinstance(history, dict) else []:
        node_id = str(node_id or "")
        if not node_id or not isinstance(record, dict):
            continue
        if country_code and node_id not in protected and not node_id.upper().startswith(country_code + "_"):
            continue
        activity = max(
            float(record.get("last_success_at") or 0),
            float(record.get("last_failure_at") or 0),
            float(record.get("last_connected_at") or 0),
            float(record.get("last_disconnected_at") or 0),
        )
        ranked.append((node_id in protected, activity, int(record.get("successful_connections") or 0), node_id, record))
    ranked.sort(reverse=True)
    return {node_id: record for _protected, _activity, _successes, node_id, record in ranked[:max(1, int(limit))]}


def compact_state_histories(state, configured_channels):
    state["node_history"] = compact_history_map(
        state.get("node_history", {}), limit=LEGACY_HISTORY_MAX_ENTRIES,
    )
    runtimes = state.get("channels", {}) if isinstance(state.get("channels"), dict) else {}
    histories = state.get("channel_node_history", {})
    if not isinstance(histories, dict):
        histories = {}
    configured = {str(channel.get("id") or ""): channel for channel in configured_channels}
    compacted = {}
    for channel_id, history in histories.items():
        channel = configured.get(str(channel_id), {})
        code = COUNTRY_CODES.get(str(channel.get("country") or "").strip(), "")
        runtime = runtimes.get(channel_id, {}) if isinstance(runtimes, dict) else {}
        protected = [runtime.get("node_id"), *(runtime.get("recent_failures") or [])]
        compacted[channel_id] = compact_history_map(history, code, protected)
    state["channel_node_history"] = compacted
    return state


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
    changed = ensure_network_slots(cfg)
    # Older releases stored the first automatically detected node as if it was
    # a manual pin.  With several protocols for one country this commonly made
    # every line stick to the same node forever.  On the one-time v6 migration,
    # retain the first pin but release exact duplicate pins for sibling lines.
    if int(cfg.get("version") or 0) < 6:
        seen_country_pins = set()
        for item in channels:
            preferred = str(item.get("preferred_node_id") or "").strip()
            if not preferred:
                continue
            country_key = country_identity(item.get("country"))
            key = (country_key, preferred)
            if key in seen_country_pins:
                item["preferred_node_id"] = ""
                changed = True
            else:
                seen_country_pins.add(key)
        cfg["version"] = 6
        changed = True
    if changed:
        write_json(CONFIG_FILE, cfg)
    return cfg


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


def reconcile_interface_address(prefix, interface, address):
    result = run([*prefix, "ip", "-j", "-4", "addr", "show", "dev", interface], capture=True)
    for link in json.loads(result.stdout or "[]"):
        for info in link.get("addr_info", []):
            old = str(info.get("local") or "")
            if managed_address(old) and (old != address or info.get("prefixlen") != 30):
                run([*prefix, "ip", "addr", "del", f"{old}/{info['prefixlen']}", "dev", interface])
    run([*prefix, "ip", "addr", "replace", f"{address}/30", "dev", interface])


def ensure_namespace(channel, index):
    ns = ns_name(channel)
    slot = channel_slot(channel, index)
    _, host_ip, ns_ip = channel_network(slot)
    host_if = ("vh-" + channel["id"])[:15]
    ns_if = ("vn-" + channel["id"])[:15]
    existing = run(["ip", "netns", "list"], check=False, capture=True).stdout
    if ns not in existing.split():
        run(["ip", "netns", "add", ns])
    if run(["ip", "link", "show", host_if], check=False).returncode != 0:
        run(["ip", "link", "add", host_if, "type", "veth", "peer", "name", ns_if])
        run(["ip", "link", "set", ns_if, "netns", ns])
    reconcile_interface_address([], host_if, host_ip)
    run(["ip", "link", "set", host_if, "up"])
    run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])
    reconcile_interface_address(["ip", "netns", "exec", ns], ns_if, ns_ip)
    run(["ip", "netns", "exec", ns, "ip", "link", "set", ns_if, "up"])
    run(["ip", "netns", "exec", ns, "ip", "route", "replace", "default", "via", host_ip])
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
    subnet, _, _ = channel_network(slot)
    check_nat = run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"], check=False)
    if check_nat.returncode != 0:
        run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"])
    for direction in (("-i", host_if), ("-o", host_if)):
        check_fwd = run(["iptables", "-C", "FORWARD", direction[0], direction[1], "-j", "ACCEPT"], check=False)
        if check_fwd.returncode != 0:
            run(["iptables", "-A", "FORWARD", direction[0], direction[1], "-j", "ACCEPT"])
    route = run(["ip", "-j", "route", "get", ns_ip], capture=True)
    routes = json.loads(route.stdout or "[]")
    if not routes or routes[0].get("dev") != host_if:
        raise RuntimeError("本机通道内部路由冲突，已停止连接尝试；请执行后台升级修复网段")
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
    return shared_ip_type_rank(node, mode)


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


def node_known_exit_ip(node):
    return str(node.get("exit_ip") or node.get("ip") or node.get("remote_host") or "").strip()


def occupied_country_exits(channel, state, configured_channels):
    """Return nodes/exits already reserved by sibling lines of this country."""
    node_ids = set()
    exit_ips = set()
    runtimes = state.get("channels", {}) if isinstance(state, dict) else {}
    for sibling in configured_channels if isinstance(configured_channels, list) else []:
        if not sibling.get("enabled") or sibling.get("id") == channel.get("id"):
            continue
        if country_identity(sibling.get("country")) != country_identity(channel.get("country")):
            continue
        runtime = runtimes.get(sibling.get("id"), {})
        node_id = str(runtime.get("node_id") or "").strip()
        exit_ip = str(runtime.get("exit_ip") or "").strip()
        if node_id:
            node_ids.add(node_id)
        if exit_ip:
            exit_ips.add(exit_ip)
    return node_ids, exit_ips


def select_candidates(channel, exclude=None, history=None, recovery=False,
                      occupied_node_ids=None, occupied_exit_ips=None):
    exclude = set(exclude or [])
    occupied_node_ids = set(occupied_node_ids or [])
    occupied_exit_ips = set(occupied_exit_ips or [])
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
        if channel_provider_rejection(channel, node=node):
            continue
        deep_failure = failure_record(deep_failures, nid, str(channel.get("id") or ""))
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
        occupied_rank = 1 if (
            nid in occupied_node_ids or node_known_exit_ip(node) in occupied_exit_ips
        ) else 0
        selected.append((
            0 if nid == preferred else 1,
            rank,
            status_rank,
            occupied_rank,
            verified_rank,
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
        for key in ("country", "ip_type", "restart_token", "enabled", "network_slot")
    }
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:16]


def start_proxy(ns, work_dir):
    log_path = work_dir / "proxy.log"
    if log_path.exists() and log_path.stat().st_size > 1024 * 1024:
        oldest = work_dir / "proxy.log.2"
        previous = work_dir / "proxy.log.1"
        oldest.unlink(missing_ok=True)
        if previous.exists():
            previous.replace(oldest)
        log_path.replace(previous)
    log = open(log_path, "ab", buffering=0)
    code = "import proxy_server; proxy_server.start_proxy_server('0.0.0.0',1080)"
    env = os.environ.copy()
    env.update({"PYTHONPATH": str(APP_DIR), "LOCAL_PROXY_HOST": "0.0.0.0", "LOCAL_PROXY_PORT": str(PROXY_PORT)})
    allowed_env = {
        "PYTHONPATH", "LOCAL_PROXY_HOST", "LOCAL_PROXY_PORT",
        "LOCAL_PROXY_DNS_CACHE_SIZE", "LOCAL_PROXY_DNS_CACHE_TTL",
        "LOCAL_PROXY_MAX_CONNECTIONS",
    }
    return subprocess.Popen(["ip", "netns", "exec", ns, "env", *[f"{k}={v}" for k, v in env.items() if k in allowed_env], "python3", "-c", code], stdout=log, stderr=subprocess.STDOUT)


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
    if effective_ip_type({"ip": exit_ip, "ip_type": info.get("ip_type")}) == "hosting" and info.get("ip_type") != "hosting":
        info["ip_type"] = "hosting"
        info["classification_source"] = "known-hosting-override"
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


def connect_channel(channel, index, previous, history, occupied_node_ids=None, occupied_exit_ips=None):
    work = DATA_DIR / channel["id"]
    work.mkdir(parents=True, exist_ok=True)
    ns, ns_ip = ensure_namespace(channel, index)
    stop_namespace_processes(ns)
    failed = list(previous.get("recent_failures") or [])[-8:]
    candidates = select_candidates(
        channel, history=history,
        occupied_node_ids=occupied_node_ids, occupied_exit_ips=occupied_exit_ips,
    )
    if not candidates:
        # Do not leave an offline country waiting hours for historical backoff.
        # Live retries remain rate-limited by last_failure_at.
        candidates = select_candidates(
            channel, history=history, recovery=True,
            occupied_node_ids=occupied_node_ids, occupied_exit_ips=occupied_exit_ips,
        )
    if not candidates:
        pool = [n for n in read_json(NODES_FILE, []) if country_matches(n, channel['country'])]
        policy = [n for n in pool if not channel_provider_rejection(channel, node=n) and ip_type_rank(n, channel.get('ip_type', 'all')) < 99]
        available = [n for n in policy if n.get('probe_status') == 'available']
        raise RuntimeError(
            f"{channel['country']}候选共 {len(pool)} 个，符合服务商/IP策略 {len(policy)} 个，"
            f"其中探测可用 {len(available)} 个；当前无可尝试节点（待检测或完整连接失败冷却中）"
        )
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
            clear_deep_failure(node.get("id"), channel["id"])
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
            mark_deep_failure(failed_id, last_error, channel["id"])
    raise RuntimeError(last_error or "所有候选节点连接失败")


def daemon():
    signal.signal(signal.SIGUSR1, lambda _signum, _frame: WAKE_EVENT.set())
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    state = read_json(STATE_FILE, {"channels": {}})
    state.setdefault("channels", {})
    if int(state.get("history_policy_version") or 0) < 1:
        state["node_history"] = {}
        state["history_policy_version"] = 1
    legacy_history = state.setdefault("node_history", {})
    channel_histories = state.setdefault("channel_node_history", {})
    first_pass = True
    while True:
        cfg = load_config()
        if first_pass:
            compact_state_histories(state, cfg["channels"])
        desired = {c["id"]: c for c in cfg["channels"] if c.get("enabled")}
        for cid, runtime in list(state.get("channels", {}).items()):
            if cid not in desired:
                history = channel_histories.setdefault(cid, {})
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
            if channel["id"] not in channel_histories:
                code = COUNTRY_CODES.get(str(channel.get("country") or "").strip(), "")
                channel_histories[channel["id"]] = compact_history_map(
                    json.loads(json.dumps(legacy_history)), code,
                )
            history = channel_histories[channel["id"]]
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
                mark_deep_failure(runtime.get("node_id"), provider_rejection, channel["id"])
                record_runtime_end(history, runtime, failed=False)
                healthy = False
                runtime.update({"status": "switching", "error": provider_rejection})
            provider_rejection = korea_kt_rejection(
                channel,
                provider=runtime.get("exit_provider", ""),
                asn=runtime.get("exit_asn", ""),
            )
            if healthy and provider_rejection:
                mark_deep_failure(runtime.get("node_id"), provider_rejection, channel["id"])
                record_runtime_end(history, runtime, failed=False)
                healthy = False
                runtime.update({"status": "switching", "error": provider_rejection})
            forced_exit_rejection = (
                str(channel.get("ip_type") or "") == "residential_only"
                and str(runtime.get("exit_ip") or "") in FORCED_HOSTING_EXIT_IPS
            )
            if healthy and forced_exit_rejection:
                reason = f"真实出口 {runtime.get('exit_ip')} 已按 Ping0 精确规则判定为机房IP"
                mark_deep_failure(runtime.get("node_id"), reason, channel["id"])
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
                        clear_deep_failure(runtime.get("node_id"), channel["id"])
                        mark_exit_verified(
                            runtime.get("node_id"), detail, runtime.get("exit_country_code", ""),
                            runtime.get("exit_provider", ""), runtime.get("exit_ip_type", ""),
                        )
                    except Exception as exc:
                        healthy = False
                        mark_deep_failure(runtime.get("node_id"), str(exc), channel["id"])
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
                        mark_deep_failure(runtime.get("node_id"), detail, channel["id"])
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
                        mark_deep_failure(previous.get("node_id"), "VPN 进程异常退出", channel["id"])
                        record_runtime_end(history, previous, failed=True)
                stop_runtime(runtime)
                stop_namespace_processes(ns_name(channel))
                runtime.update({"status": "connecting", "error": "", "exit_ip": "", "exit_country_code": "", "node_id": "", "openvpn_pid": 0, "proxy_pid": 0, "checked_at": time.time()})
                write_json(STATE_FILE, state)
                try:
                    occupied_node_ids, occupied_exit_ips = occupied_country_exits(
                        channel, state, cfg["channels"],
                    )
                    state["channels"][channel["id"]] = connect_channel(
                        channel, index, previous, history,
                        occupied_node_ids=occupied_node_ids,
                        occupied_exit_ips=occupied_exit_ips,
                    )
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
