#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import select
import shlex
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid
import secrets

# Prefer IPv4 resolution to avoid slow AAAA DNS timeouts (e.g. in WSL),
# but fall back to system default (IPv6) if IPv4 resolution fails.
# This ensures pure-IPv6 VPS (with NAT64/clatd) can still function.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        if isinstance(host, str) and ":" in host:
            return _orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        # Try IPv4 first for speed; fall back to system default (allows IPv6/NAT64)
        try:
            results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if results:
                return results
        except socket.gaierror:
            pass
        return _orig_getaddrinfo(host, port, 0, type, proto, flags)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET

        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
                # 关闭第一次失败时可能已创建的 socket
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

import vpn_utils
import proxy_server

def env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        print(f"[配置警告] 环境变量 {name}={raw!r} 不是有效整数，使用默认值 {default}", flush=True)
        value = default
    if min_value is not None and value < min_value:
        print(f"[配置警告] 环境变量 {name}={value} 小于允许值 {min_value}，使用默认值 {default}", flush=True)
        return default
    if max_value is not None and value > max_value:
        print(f"[配置警告] 环境变量 {name}={value} 大于允许值 {max_value}，使用默认值 {default}", flush=True)
        return default
    return value

def bounded_int(value: Any, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None and parsed < min_value:
        return default
    if max_value is not None and parsed > max_value:
        return default
    return parsed

API_URL = "https://www.vpngate.net/api/iphone/"
MIRROR_LIST_URL = "https://www.vpngate.net/en/sites.aspx"
FETCH_INTERVAL_SECONDS = env_int("FETCH_INTERVAL_SECONDS", 1800, 1)
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 1800, 1)
AUTO_CONNECT_RETRY_SECONDS = env_int("AUTO_CONNECT_RETRY_SECONDS", 10, 5, 300)
UNAVAILABLE_REFRESH_SECONDS = env_int("UNAVAILABLE_REFRESH_SECONDS", 120, 30, 1800)
TARGET_VALID_NODES = env_int("TARGET_VALID_NODES", 3, 1)
MAX_SCAN_ROWS = env_int("MAX_SCAN_ROWS", 300, 1)
VPNGATE_MIRROR_SOURCES = env_int("VPNGATE_MIRROR_SOURCES", 20, 0, 40)
VPNGATE_MIRROR_WORKERS = env_int("VPNGATE_MIRROR_WORKERS", 2, 1, 5)
NODE_RETENTION_SECONDS = env_int("NODE_RETENTION_SECONDS", 48 * 3600, 3600, 7 * 24 * 3600)
CACHED_CONFIG_RECOVERY_TARGET = env_int("CACHED_CONFIG_RECOVERY_TARGET", 500, 100, 1000)
TARGET_COUNTRY_MIN_NODES = env_int("TARGET_COUNTRY_MIN_NODES", 5, 1, 100)
VPNGATE_EXTRA_API_URLS = os.environ.get("VPNGATE_EXTRA_API_URLS", "")
OPENVPN_TEST_TIMEOUT_SECONDS = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 35, 1)
MANUAL_TEST_NODE_LIMIT = env_int("MANUAL_TEST_NODE_LIMIT", 5, 1, 20)
INITIAL_CONNECT_TEST_LIMIT = env_int("INITIAL_CONNECT_TEST_LIMIT", 10, 1, 50)
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = env_int("LOCAL_PROXY_PORT", 7928, 1, 65535)
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = env_int("UI_PORT", 8787, 1, 65535)
BUNDLE_PORT = env_int("BUNDLE_PORT", 2097, 1, 65535)
INVALID_BACKOFF_SECONDS = env_int("INVALID_BACKOFF_SECONDS", 30 * 60, 1)
STANDBY_MANAGER_INTERVAL_SECONDS = env_int("STANDBY_MANAGER_INTERVAL_SECONDS", 30, 10, 300)
HOT_STANDBY_TARGET = env_int("HOT_STANDBY_TARGET", 3, 1, 10)
NORMAL_STANDBY_TARGET = env_int("NORMAL_STANDBY_TARGET", 2, 0, 10)
HOT_STANDBY_RECHECK_SECONDS = env_int("HOT_STANDBY_RECHECK_SECONDS", 10 * 60, 60)
NORMAL_STANDBY_RECHECK_SECONDS = env_int("NORMAL_STANDBY_RECHECK_SECONDS", 30 * 60, 60)
CANDIDATE_RECHECK_SECONDS = env_int("CANDIDATE_RECHECK_SECONDS", 6 * 3600, 600)
STANDBY_TEST_BATCH_SIZE = env_int("STANDBY_TEST_BATCH_SIZE", 3, 1, 20)
BOOTSTRAP_TEST_BATCH_SIZE = env_int("BOOTSTRAP_TEST_BATCH_SIZE", 3, 1, 10)
AVAILABILITY_TEST_WORKERS = env_int("AVAILABILITY_TEST_WORKERS", 2, 1, 5)
STANDBY_STARTUP_DELAY_SECONDS = env_int("STANDBY_STARTUP_DELAY_SECONDS", 5 * 60, 30, 1800)
MULTI_RECOVERY_POLL_SECONDS = env_int("MULTI_RECOVERY_POLL_SECONDS", 5, 3, 60)
MULTI_RECOVERY_FAILURE_GRACE_SECONDS = env_int("MULTI_RECOVERY_FAILURE_GRACE_SECONDS", 20, 10, 300)
MULTI_RECOVERY_COUNTRY_RECHECK_SECONDS = env_int("MULTI_RECOVERY_COUNTRY_RECHECK_SECONDS", 5 * 60, 60, 3600)
MULTI_RECOVERY_CATALOG_REFRESH_SECONDS = env_int("MULTI_RECOVERY_CATALOG_REFRESH_SECONDS", 10 * 60, 120, 7200)
CONFIG_CACHE_RETENTION_SECONDS = env_int("CONFIG_CACHE_RETENTION_SECONDS", 3 * 24 * 3600, 24 * 3600)

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
UPSTREAM_PROXY_AUTH_FILE = DATA_DIR / "upstream_proxy_auth.txt"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"
MIRROR_URLS_FILE = DATA_DIR / "working_mirrors.json"
METADATA_PAUSE_FILE = DATA_DIR / "metadata_refresh_paused"

lock = threading.RLock()
maintenance_lock = threading.Lock()
multi_config_lock = threading.Lock()
metadata_cancel_event = threading.Event()
active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = False
last_active_ping_time = 0.0
last_active_latency = 0

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0
last_pinger_heartbeat = 0.0
server_start_time = time.time()
last_no_connection_refresh_at = server_start_time


class CatalogRefreshCancelled(RuntimeError):
    pass


def metadata_refresh_paused() -> bool:
    return METADATA_PAUSE_FILE.exists()


def pause_metadata_refresh() -> None:
    ensure_dirs()
    metadata_cancel_event.set()
    METADATA_PAUSE_FILE.write_text(str(time.time()), encoding="utf-8")
    set_state(
        metadata_refresh_paused=True,
        refresh_cancel_requested=True,
        last_check_message="已请求停止节点资料拉取；自动拉取保持暂停，现有国家出口不受影响。",
    )


def resume_metadata_refresh() -> None:
    metadata_cancel_event.clear()
    try:
        METADATA_PAUSE_FILE.unlink()
    except FileNotFoundError:
        pass
    set_state(metadata_refresh_paused=False, refresh_cancel_requested=False)

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def upstream_proxy_auth_file() -> str | None:
    username, password = vpn_utils.get_upstream_proxy_auth()
    if username is None:
        return None
    try:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        UPSTREAM_PROXY_AUTH_FILE.write_text(f"{username}\n{password or ''}\n", encoding="utf-8")
        try:
            UPSTREAM_PROXY_AUTH_FILE.chmod(0o600)
        except OSError:
            pass
        return str(UPSTREAM_PROXY_AUTH_FILE)
    except Exception as exc:
        print(f"[上游代理认证] 写入认证文件失败: {exc}", flush=True)
        return None

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default


_direct_ip_cache = {"value": "", "time": 0.0}


def get_direct_node_status() -> dict[str, Any]:
    """Return non-secret details for the original 3x-ui inbound routed directly."""
    result: dict[str, Any] = {
        "name": "VPS 直连节点", "status": "unavailable", "routing": "unknown",
        "exit_ip": "", "port": 0, "protocol": "", "remark": "",
    }
    database = Path("/etc/x-ui/x-ui.db")
    if not database.exists():
        return result
    try:
        db = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=2)
        db.row_factory = sqlite3.Row
        row = db.execute(
            """select remark,port,protocol,tag from inbounds
            where enable=1 and protocol in ('vless','trojan','hysteria')
            and remark not like 'COUNTRY:%'
            order by case when remark in ('AUTO-GATEWAY','VPS-DIRECT','服务器直连')
                or remark like '%.服务器直连' then 0 else 1 end,id limit 1"""
        ).fetchone()
        setting = db.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
        db.close()
        if not row:
            return result
        result.update({"remark": row["remark"], "port": row["port"], "protocol": row["protocol"]})
        config = json.loads(setting[0]) if setting else {}
        route = next((rule for rule in config.get("routing", {}).get("rules", [])
                      if row["tag"] in (rule.get("inboundTag") or [])), {})
        result["routing"] = route.get("outboundTag", "default")
        active = subprocess.run(
            ["systemctl", "is-active", "x-ui"], capture_output=True, text=True, timeout=3
        ).stdout.strip() == "active"
        result["status"] = "connected" if active and result["routing"] == "direct" else "misconfigured"
        now = time.time()
        if now - float(_direct_ip_cache["time"]) > 3600 or not _direct_ip_cache["value"]:
            try:
                with urllib.request.urlopen("https://api.ipify.org", timeout=4) as response:
                    value = response.read(80).decode("ascii", "ignore").strip()
                    if value:
                        _direct_ip_cache.update({"value": value, "time": now})
            except Exception:
                pass
        result["exit_ip"] = _direct_ip_cache["value"]
    except Exception as exc:
        result["error"] = str(exc)
    return result


def server_node_prefix() -> str:
    """Return the last octet of this server's public IPv4 for client node names."""
    candidates = [str(_direct_ip_cache.get("value") or "").strip()]
    try:
        candidates.append((DATA_DIR / "public_ip.txt").read_text(encoding="utf-8").strip())
    except OSError:
        pass
    candidates.append(str(xui_subscription_settings().get("subDomain") or "").strip())
    for value in candidates:
        parts = value.split(".")
        if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            return parts[-1]
    direct_ip = str(get_direct_node_status().get("exit_ip") or "").strip()
    parts = direct_ip.split(".")
    if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
        return parts[-1]
    return ""


def server_node_name(base_name: str) -> str:
    prefix = server_node_prefix()
    return f"{prefix}.{base_name}" if prefix else base_name


MULTI_EXIT_DIR = Path("/var/lib/aimilivpn-multiexit")
MULTI_EXIT_DEEP_FAILURES_FILE = MULTI_EXIT_DIR / "deep_failures.json"
MULTI_EXIT_VERIFIED_EXITS_FILE = MULTI_EXIT_DIR / "verified_exits.json"
BUNDLE_TOKEN_FILE = MULTI_EXIT_DIR / "bundle_token"
_xui_content_cache: dict[tuple[str, str], tuple[float, str]] = {}


def read_multi_exit_config() -> dict[str, Any]:
    return read_json(MULTI_EXIT_DIR / "channels.json", {"version": 2, "direct_protocol": "hysteria", "channels": []})


def migrate_xui_direct_display_name() -> None:
    """Rename an existing direct inbound without changing its port or credentials."""
    display_name = server_node_name("服务器直连")
    database = Path("/etc/x-ui/x-ui.db")
    if database.exists():
        try:
            db = sqlite3.connect(database, timeout=5)
            db.execute(
                """update inbounds set remark=? where remark in ('VPS-DIRECT','AUTO-GATEWAY','服务器直连')
                or remark like '%.服务器直连'""",
                (display_name,),
            )
            db.commit()
            db.close()
        except Exception as exc:
            print(f"[name migration] direct inbound rename deferred: {exc}", flush=True)
    result_file = Path("/etc/x-ui/multi-exit-result.json")
    result = read_json(result_file, {})
    if isinstance(result.get("direct"), dict) and result["direct"].get("name") != display_name:
        result["direct"]["name"] = display_name
        write_json(result_file, result)


def xui_subscription_settings() -> dict[str, str]:
    database = Path("/etc/x-ui/x-ui.db")
    if not database.exists():
        return {}
    try:
        db = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=3)
        rows = db.execute("select key,value from settings where key like 'sub%'").fetchall()
        db.close()
        return {str(key): str(value or "") for key, value in rows}
    except Exception:
        return {}


def public_subscription_host() -> str:
    settings = xui_subscription_settings()
    return settings.get("subDomain", "").strip() or str(get_direct_node_status().get("exit_ip") or "").strip()


def rewrite_xui_node_name(value: str, kind: str, display_name: str) -> str:
    """Rewrite only client-visible names; x-ui keeps its unique internal email."""
    name = str(display_name or "").strip()
    if not name:
        return value
    if kind == "universal":
        encoded = urllib.parse.quote(name, safe="")
        lines = []
        for line in value.splitlines():
            if "://" in line:
                line = line.rsplit("#", 1)[0] + "#" + encoded
            lines.append(line)
        return "\n".join(lines)
    match = re.search(r"(?m)^\s*-?\s*name:\s*['\"]?(.+?)['\"]?\s*$", value)
    if not match:
        return value
    old_name = match.group(1).strip().strip("'\"")
    return value.replace(old_name, name)


def normalize_hysteria2_client_tls(value: str, kind: str, public_host: str) -> str:
    """Emit explicit, verifiable TLS settings for modern Xray/v2rayNG clients."""
    host = str(public_host or "").strip()
    if not host:
        return value
    if kind == "universal":
        normalized: list[str] = []
        for line in value.splitlines():
            stripped = line.strip()
            if not stripped:
                normalized.append(line)
                continue
            try:
                parsed = urllib.parse.urlsplit(stripped)
            except Exception:
                normalized.append(line)
                continue
            if parsed.scheme.casefold() not in {"hysteria2", "hy2"}:
                normalized.append(line)
                continue
            blocked = {
                "insecure", "allowinsecure", "sni", "ech",
                "pinsha256", "pinnedca256", "pinnedpeercertsha256",
                "security",
            }
            pairs = [
                (key, item)
                for key, item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                if key.casefold() not in blocked
            ]
            pairs.extend((
                ("security", "tls"),
                ("sni", host),
                ("insecure", "0"),
            ))
            normalized.append(urllib.parse.urlunsplit((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urllib.parse.urlencode(pairs, doseq=True),
                parsed.fragment,
            )))
        return "\n".join(normalized)

    if kind != "clash":
        return value
    section = re.search(r"(?ms)^(proxies:\s*\n)(.*?)(?=^proxy-groups:)", value)
    if not section or not re.search(r"(?mi)^\s*type:\s*hysteria2\s*$", section.group(2)):
        return value
    lines = section.group(2).splitlines()
    cleaned: list[str] = []
    insert_at = None
    for source_line in lines:
        stripped = source_line.strip().lstrip("- ").strip()
        key = stripped.split(":", 1)[0].strip().casefold() if ":" in stripped else ""
        if key in {
            "sni", "servername", "skip-cert-verify", "insecure", "ech",
            "pinsha256", "pinnedca256", "pinnedpeercertsha256",
        }:
            continue
        cleaned.append(source_line)
        if key == "server":
            indent = source_line[:len(source_line) - len(source_line.lstrip())]
            insert_at = (len(cleaned), indent)
    tls_lines = [f"  sni: {host}", "  skip-cert-verify: false"]
    if insert_at:
        position, indent = insert_at
        tls_lines = [f"{indent}sni: {host}", f"{indent}skip-cert-verify: false"]
        cleaned[position:position] = tls_lines
    else:
        cleaned.extend(tls_lines)
    replacement = section.group(1) + "\n".join(cleaned) + "\n"
    return value[:section.start()] + replacement + value[section.end():]


def xui_node_content(sub_id: str, kind: str, public_host: str, display_name: str = "") -> str:
    """Read one node from x-ui locally while making it emit the public server address."""
    if not sub_id or kind not in ("universal", "clash"):
        return ""
    cache_key = (sub_id, kind, display_name)
    cached = _xui_content_cache.get(cache_key)
    if cached and time.time() - cached[0] < 60:
        return cached[1]
    settings = xui_subscription_settings()
    port = bounded_int(settings.get("subPort"), 2096, 1, 65535)
    path = settings.get("subClashPath" if kind == "clash" else "subPath", "/clash/" if kind == "clash" else "/sub/")
    path = "/" + path.strip("/") + "/" + urllib.parse.quote(sub_id, safe="")
    request = urllib.request.Request(
        f"https://127.0.0.1:{port}{path}",
        headers={"Host": f"{public_host}:{port}", "User-Agent": "AimiliVPN-Manager/1.0"},
    )
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(request, context=context, timeout=8) as response:
        raw = response.read(1024 * 1024).decode("utf-8", "replace").strip()
    if kind == "universal":
        try:
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace").strip()
            value = decoded
        except Exception:
            value = raw
    else:
        value = raw
    # x-ui derives the node host from the HTTP Host header; retain a defensive replacement.
    value = value.replace("server: localhost", f"server: {public_host}")
    value = value.replace("@localhost:", f"@{public_host}:")
    value = rewrite_xui_node_name(value, kind, display_name)
    value = normalize_hysteria2_client_tls(value, kind, public_host)
    _xui_content_cache[cache_key] = (time.time(), value)
    return value


def ensure_bundle_token() -> str:
    MULTI_EXIT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        token = BUNDLE_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        token = ""
    if len(token) < 24:
        token = secrets.token_urlsafe(32)
        BUNDLE_TOKEN_FILE.write_text(token + "\n", encoding="utf-8")
        try:
            BUNDLE_TOKEN_FILE.chmod(0o600)
        except OSError:
            pass
    return token


def provisioned_subscription_ids() -> list[str]:
    result = read_json(Path("/etc/x-ui/multi-exit-result.json"), {"channels": []})
    ids: list[str] = []
    direct_id = str((result.get("direct") or {}).get("subId") or "")
    if direct_id:
        ids.append(direct_id)
    enabled_ids = {str(c.get("id") or "") for c in read_multi_exit_config().get("channels", []) if c.get("enabled", True)}
    for item in result.get("channels", []):
        if str(item.get("id") or "") in enabled_ids:
            sub_id = str(item.get("subId") or "")
            if sub_id and sub_id not in ids:
                ids.append(sub_id)
    return ids


def provisioned_subscription_names() -> dict[str, str]:
    result = read_json(Path("/etc/x-ui/multi-exit-result.json"), {"channels": []})
    config = read_multi_exit_config()
    channel_names = {str(c.get("id") or ""): channel_display_name(c) for c in config.get("channels", [])}
    names: dict[str, str] = {}
    direct = result.get("direct") or {}
    if direct.get("subId"):
        names[str(direct["subId"])] = server_node_name("服务器直连")
    for item in result.get("channels", []):
        sub_id = str(item.get("subId") or "")
        if sub_id:
            names[sub_id] = channel_names.get(str(item.get("id") or "")) or str(item.get("name") or "")
    return names


def aggregate_universal_subscription() -> bytes:
    host = public_subscription_host()
    display_names = provisioned_subscription_names()
    links: list[str] = []
    for sub_id in provisioned_subscription_ids():
        content = xui_node_content(sub_id, "universal", host, display_names.get(sub_id, ""))
        links.extend(line.strip() for line in content.splitlines() if "://" in line)
    return base64.b64encode(("\n".join(links) + "\n").encode("utf-8"))


def aggregate_clash_subscription() -> bytes:
    host = public_subscription_host()
    display_names = provisioned_subscription_names()
    proxy_blocks: list[str] = []
    names: list[str] = []
    for sub_id in provisioned_subscription_ids():
        content = xui_node_content(sub_id, "clash", host, display_names.get(sub_id, ""))
        match = re.search(r"(?ms)^proxies:\s*\n(.*?)(?=^proxy-groups:)", content)
        if not match:
            continue
        block = match.group(1).rstrip()
        if block:
            proxy_blocks.append(block)
            name_match = re.search(r"(?m)^\s{2}name:\s*(.+?)\s*$", block)
            if name_match:
                names.append(name_match.group(1).strip())
    lines = ["proxies:"] + proxy_blocks + ["proxy-groups:", "- name: PROXY", "  proxies:"]
    lines.extend(f"  - {name}" for name in names)
    lines.extend(["  - DIRECT", "  type: select", "rules:", "- MATCH,PROXY", ""])
    return "\n".join(lines).encode("utf-8")


def bundle_subscription_info() -> dict[str, str]:
    host = public_subscription_host()
    if not host:
        return {}
    token = ensure_bundle_token()
    return {
        "universal": f"https://{host}:{BUNDLE_PORT}/all/{token}",
        "clash": f"https://{host}:{BUNDLE_PORT}/all-clash/{token}",
    }


def find_multi_channel(config: dict[str, Any], channel_id: str) -> tuple[int, dict[str, Any]]:
    for index, channel in enumerate(config.get("channels", [])):
        if str(channel.get("id") or "") == channel_id:
            return index, channel
    raise ValueError("未找到指定的国家线路")


def channel_candidate_nodes(channel: dict[str, Any], source: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    if source is None:
        with lock:
            source = read_nodes()
    candidates = []
    deep_failures = read_json(MULTI_EXIT_DEEP_FAILURES_FILE, {})
    if not isinstance(deep_failures, dict):
        deep_failures = {}
    verified_exits = read_json(MULTI_EXIT_VERIFIED_EXITS_FILE, {})
    if not isinstance(verified_exits, dict):
        verified_exits = {}
    now = time.time()
    for node in source:
        if not country_matches(node.get("country"), channel.get("country")):
            continue
        candidate = {
            "id": str(node.get("id") or ""),
            "ip": str(node.get("exit_ip") or node.get("ip") or node.get("remote_host") or ""),
            "entry_ip": str(node.get("ip") or node.get("remote_host") or ""),
            "host_name": str(node.get("host_name") or ""),
            "country": normalized_country_name(node.get("country")),
            "owner": str(node.get("owner") or node.get("as_name") or node.get("org") or ""),
            "ip_type": effective_node_ip_type(node) or "unknown",
            "probe_status": str(node.get("probe_status") or "not_checked"),
            "probe_message": str(node.get("probe_message") or ""),
            "latency_ms": parse_int(node.get("latency_ms")) or parse_int(node.get("ping")),
            "score": parse_int(node.get("score")),
        }
        deep_failure = deep_failures.get(candidate["id"]) or {}
        if float(deep_failure.get("blocked_until") or 0) > now:
            candidate["probe_status"] = "unavailable"
            candidate["probe_message"] = "端口可达但完整 VPN 出口失败：" + str(deep_failure.get("error") or "验证失败")
            candidate["deep_failure"] = True
            candidate["deep_blocked_until"] = float(deep_failure.get("blocked_until") or 0)
        verified = verified_exits.get(candidate["id"]) or {}
        candidate["exit_verified_at"] = float(verified.get("verified_at") or 0)
        candidate["exit_verified"] = time.time() - candidate["exit_verified_at"] <= 20 * 60
        candidates.append(candidate)
    status_order = {"available": 0, "not_checked": 1, "testing": 2, "unavailable": 3}
    candidates.sort(key=lambda n: (
        status_order.get(n["probe_status"], 2),
        0 if n["ip_type"] in ("residential", "mobile") else 1,
        n["latency_ms"] or 999999,
        -n["score"],
    ))
    return candidates


def channel_ip_type_rank(node: dict[str, Any], channel: dict[str, Any]) -> int:
    mode = str(channel.get("ip_type") or "all")
    value = effective_node_ip_type(node) or "unknown"
    residential = value in ("residential", "mobile")
    hosting = value == "hosting"
    if mode == "residential_only":
        return 0 if residential else 99
    if mode == "hosting_only":
        return 0 if hosting else 99
    if mode == "residential_preferred":
        return 0 if residential else (2 if hosting else 1)
    return 0


def channel_source_candidates(channel: dict[str, Any]) -> list[dict[str, Any]]:
    """Return policy-compatible source nodes in deterministic failover order."""
    with lock:
        source = [dict(node) for node in read_nodes()]
    preferred = str(channel.get("preferred_node_id") or "")
    candidates = [
        node for node in source
        if country_matches(node.get("country"), channel.get("country"))
        and channel_ip_type_rank(node, channel) < 99
    ]
    candidates.sort(key=lambda node: (
        0 if str(node.get("id") or "") == preferred else 1,
        channel_ip_type_rank(node, channel),
        0 if node.get("probe_status") == "available" else 1,
        -float(node.get("last_available_at") or 0),
        parse_int(node.get("latency_ms")) or parse_int(node.get("ping")) or 999999,
        -parse_int(node.get("score")),
    ))
    return candidates


def mark_channel_ready(channel_id: str, preferred_node_id: str = "") -> None:
    """Release one country as soon as its first usable exit has been found."""
    with multi_config_lock:
        config = read_multi_exit_config()
        try:
            index, channel = find_multi_channel(config, channel_id)
        except ValueError:
            return
        if not channel.get("awaiting_initial_test"):
            return
        channel["awaiting_initial_test"] = False
        channel["tested_only"] = True
        if preferred_node_id:
            channel["preferred_node_id"] = preferred_node_id
        channel["initial_test_completed_at"] = time.time()
        channel["restart_token"] = time.time()
        config["channels"][index] = channel
        config["version"] = max(4, int(config.get("version") or 1))
        write_json(MULTI_EXIT_DIR / "channels.json", config)


def multi_exit_payload() -> dict[str, Any]:
    config = read_multi_exit_config()
    runtime = read_json(MULTI_EXIT_DIR / "state.json", {"channels": {}})
    result = read_json(Path("/etc/x-ui/multi-exit-result.json"), {"channels": []})
    subscriptions = {str(item.get("id") or ""): item for item in result.get("channels", [])}
    host = public_subscription_host()
    runtime_channels = runtime.get("channels", {})
    with lock:
        source_nodes = read_nodes()
    provider_probes: list[dict[str, Any]] = []
    for state in runtime_channels.values():
        exit_ip = str(state.get("exit_ip") or "")
        if exit_ip:
            provider_probes.append({"ip": exit_ip})
    if provider_probes:
        vpn_utils.enrich_ip_info(provider_probes)
    providers = {
        str(item.get("ip") or ""): str(item.get("owner") or item.get("as_name") or "")
        for item in provider_probes
    }
    for channel in config.get("channels", []):
        cid = str(channel.get("id") or "")
        channel["candidates"] = channel_candidate_nodes(channel, source_nodes)
        state = runtime_channels.get(cid, {})
        current = next((node for node in channel["candidates"] if node.get("id") == state.get("node_id")), {})
        state["entry_ip"] = str(current.get("entry_ip") or current.get("ip") or "")
        state["entry_provider"] = str(current.get("owner") or "")
        # The live tunnel lookup describes the real exit and must take priority
        # over the older catalog/cache provider attached to the entry IP.
        state["exit_provider"] = str(state.get("exit_provider") or "") or providers.get(str(state.get("exit_ip") or ""), "") or state["entry_provider"]
        info = subscriptions.get(cid, {})
        channel["sub_id"] = str(info.get("subId") or "")
        if host and channel["sub_id"]:
            try:
                channel["universal_node"] = xui_node_content(channel["sub_id"], "universal", host, channel.get("name", ""))
                channel["clash_node"] = xui_node_content(channel["sub_id"], "clash", host, channel.get("name", ""))
            except Exception as exc:
                channel["node_content_error"] = str(exc)
    direct = get_direct_node_status()
    direct_info = result.get("direct") or {}
    direct["sub_id"] = str(direct_info.get("subId") or "")
    if host and direct["sub_id"]:
        try:
            direct["universal_node"] = xui_node_content(direct["sub_id"], "universal", host, direct.get("name", "VPS-Direct"))
            direct["clash_node"] = xui_node_content(direct["sub_id"], "clash", host, direct.get("name", "VPS-Direct"))
        except Exception as exc:
            direct["node_content_error"] = str(exc)
    main_state = read_json(STATE_FILE, {})
    maintenance = {
        "running": bool(maintenance_lock.locked()),
        "task": str(main_state.get("maintenance_task") or ""),
        "channel_id": str(main_state.get("maintenance_channel_id") or ""),
        "message": str(main_state.get("last_check_message") or ""),
        "last_completed_channel_id": str(main_state.get("last_completed_channel_id") or ""),
        "last_completed_channel_message": str(main_state.get("last_completed_channel_message") or ""),
        "channel_results": main_state.get("channel_test_results") or {},
    }
    return {
        "ok": True, "direct": direct, "config": config, "state": runtime,
        "bundle": bundle_subscription_info(), "maintenance": maintenance,
    }


def fast_multi_exit_bootstrap_payload() -> dict[str, Any]:
    """Small, local-only payload used to render saved channel cards immediately."""
    config = read_multi_exit_config()
    runtime = read_json(MULTI_EXIT_DIR / "state.json", {"channels": {}})
    result = read_json(Path("/etc/x-ui/multi-exit-result.json"), {})
    direct_info = result.get("direct") or {}
    try:
        public_ip = (DATA_DIR / "public_ip.txt").read_text(encoding="utf-8").strip()
    except OSError:
        public_ip = ""
    direct = {
        "status": "loading", "routing": "direct", "exit_ip": public_ip,
        "port": direct_info.get("port", 0), "protocol": direct_info.get("protocol", config.get("direct_protocol", "hysteria")),
    }
    return {"ok": True, "direct": direct, "config": config, "state": runtime, "bundle": {}}


def run_channel_availability(channel_id: str) -> str:
    config = read_multi_exit_config()
    _, channel = find_multi_channel(config, channel_id)
    ids = [node["id"] for node in channel_candidate_nodes(channel) if node.get("id")]
    if not ids:
        raise RuntimeError(f"{channel.get('country')} 暂无候选节点，请先更新节点资料")
    message = test_node_availability_only(
        ids,
        trigger_legacy_auto=False,
        task_label=str(channel.get("country") or channel_id),
        channel_id=channel_id,
    )
    with lock:
        available_ids = {
            str(node.get("id") or "") for node in read_nodes()
            if str(node.get("id") or "") in set(ids) and node.get("probe_status") == "available"
        }
    if available_ids:
        mark_channel_ready(channel_id)
    return message


def policy_available_channel_nodes(channel: dict[str, Any]) -> list[dict[str, Any]]:
    deep_failures = read_json(MULTI_EXIT_DEEP_FAILURES_FILE, {})
    if not isinstance(deep_failures, dict):
        deep_failures = {}
    now = time.time()
    return [
        node for node in channel_source_candidates(channel)
        if node.get("probe_status") == "available"
        and float((deep_failures.get(str(node.get("id") or "")) or {}).get("blocked_until") or 0) <= now
    ]


def wake_channel_after_recovery(channel_id: str, available_nodes: list[dict[str, Any]]) -> None:
    """Apply freshly tested results to one channel without rebuilding others."""
    available_ids = {str(node.get("id") or "") for node in available_nodes}
    with multi_config_lock:
        config = read_multi_exit_config()
        try:
            index, channel = find_multi_channel(config, channel_id)
        except ValueError:
            return
        if str(channel.get("preferred_node_id") or "") not in available_ids:
            channel["preferred_node_id"] = ""
        channel["restart_token"] = time.time()
        config["channels"][index] = channel
        write_json(MULTI_EXIT_DIR / "channels.json", config)


def multi_exit_auto_recovery_loop() -> None:
    """Escalate a failed country: standby -> country probe -> catalog refresh."""
    first_failed_at: dict[str, float] = {}
    last_country_test_at: dict[str, float] = {}
    last_catalog_refresh_at: dict[str, float] = {}
    time.sleep(15)
    while True:
        try:
            config = read_multi_exit_config()
            runtime = read_json(MULTI_EXIT_DIR / "state.json", {"channels": {}}).get("channels", {})
            enabled = {
                str(channel.get("id") or ""): channel
                for channel in config.get("channels", []) if channel.get("enabled", True)
            }
            now = time.time()
            for channel_id in list(first_failed_at):
                if channel_id not in enabled or str((runtime.get(channel_id) or {}).get("status") or "") == "connected":
                    first_failed_at.pop(channel_id, None)
                    last_country_test_at.pop(channel_id, None)

            for channel_id, channel in enabled.items():
                channel_runtime = runtime.get(channel_id) or {}
                if str(channel_runtime.get("status") or "") != "failed":
                    continue
                first_failed_at.setdefault(channel_id, now)
                if now - first_failed_at[channel_id] < MULTI_RECOVERY_FAILURE_GRACE_SECONDS:
                    continue
                if now - last_country_test_at.get(channel_id, 0) < MULTI_RECOVERY_COUNTRY_RECHECK_SECONDS:
                    continue
                if maintenance_lock.locked() or is_connecting:
                    continue

                last_country_test_at[channel_id] = now
                country = str(channel.get("country") or channel_id)
                set_state(last_check_message=f"{country}出口无可连接备用节点，正在自动检测本国全部节点...")
                run_channel_availability(channel_id)
                latest_config = read_multi_exit_config()
                try:
                    _, latest_channel = find_multi_channel(latest_config, channel_id)
                except ValueError:
                    continue
                available = policy_available_channel_nodes(latest_channel)
                if available:
                    wake_channel_after_recovery(channel_id, available)
                    set_state(last_check_message=f"{country}已重新找到 {len(available)} 个符合策略的可用节点，正在恢复出口...")
                    continue

                now = time.time()
                # A manual pause suppresses routine catalog pulls, but it must
                # not leave an already configured country offline forever.
                # force=True below resumes one rate-limited emergency refresh.
                if now - last_catalog_refresh_at.get(channel_id, 0) < MULTI_RECOVERY_CATALOG_REFRESH_SECONDS:
                    set_state(last_check_message=f"{country}本国节点检测后全部不可用；等待下一次节点资料更新窗口")
                    continue

                last_catalog_refresh_at[channel_id] = now
                set_state(last_check_message=f"{country}本国节点全部不可用，正在拉取全部最新节点资料...")
                refresh_node_catalog_only(force=True)
                run_channel_availability(channel_id)
                latest_config = read_multi_exit_config()
                try:
                    _, latest_channel = find_multi_channel(latest_config, channel_id)
                except ValueError:
                    continue
                available = policy_available_channel_nodes(latest_channel)
                if available:
                    wake_channel_after_recovery(channel_id, available)
                    set_state(last_check_message=f"节点资料更新后，{country}找到 {len(available)} 个可用节点，正在恢复出口...")
                else:
                    set_state(last_check_message=f"节点资料已更新，但{country}仍没有符合策略的可用节点")
        except Exception as exc:
            print(f"[multi-exit recovery] automatic recovery failed: {exc}", flush=True)
            log_to_json("WARNING", "MultiExitRecovery", f"自动恢复国家出口失败: {exc}")
        time.sleep(MULTI_RECOVERY_POLL_SECONDS)


bootstrap_workers: dict[str, threading.Thread] = {}
bootstrap_workers_lock = threading.Lock()


def ensure_channel_bootstrap(channel_id: str) -> None:
    """Start at most one bootstrap worker per country, including late installs."""
    if not channel_id:
        return
    with bootstrap_workers_lock:
        for cid, worker in list(bootstrap_workers.items()):
            if not worker.is_alive():
                bootstrap_workers.pop(cid, None)
        if channel_id in bootstrap_workers:
            return
        worker = threading.Thread(target=bootstrap_new_channel, args=(channel_id,), daemon=True)
        bootstrap_workers[channel_id] = worker
        worker.start()


def bootstrap_supervisor_loop() -> None:
    """Discover channels created after the web manager was already started."""
    while True:
        try:
            for channel in read_multi_exit_config().get("channels", []):
                if channel.get("enabled", True) and channel.get("awaiting_initial_test"):
                    ensure_channel_bootstrap(str(channel.get("id") or ""))
        except Exception as exc:
            print(f"[bootstrap supervisor] retrying: {exc}", flush=True)
        time.sleep(5)


def bootstrap_new_channel(channel_id: str) -> None:
    """Release a new country after its first verified node; fill reserves later."""
    attempted: set[str] = set()
    exhausted_at = 0.0
    while True:
        config = read_multi_exit_config()
        try:
            _, channel = find_multi_channel(config, channel_id)
        except ValueError:
            return
        if not channel.get("enabled", True) or not channel.get("awaiting_initial_test"):
            return
        if maintenance_lock.locked() or is_connecting:
            time.sleep(2)
            continue
        try:
            candidates = channel_source_candidates(channel)
            now = time.time()
            eligible = [
                node for node in candidates
                if str(node.get("id") or "") not in attempted
                and float(node.get("next_probe_at") or 0) <= now
            ]
            if not eligible:
                if not exhausted_at:
                    exhausted_at = now
                if now - exhausted_at >= 30 * 60:
                    attempted.clear()
                    exhausted_at = 0.0
                time.sleep(10)
                continue
            batch = eligible[:BOOTSTRAP_TEST_BATCH_SIZE]
            batch_ids = [str(node.get("id") or "") for node in batch]
            started = time.time()
            test_node_availability_only(
                batch_ids,
                trigger_legacy_auto=False,
                task_label=f"{channel.get('country')}首次快速检测",
                channel_id=channel_id,
            )
            with lock:
                latest_nodes = read_nodes()
            tested = [
                node for node in latest_nodes
                if str(node.get("id") or "") in set(batch_ids)
                and float(node.get("probed_at") or 0) >= started - 1
            ]
            if not tested:
                time.sleep(2)
                continue
            attempted.update(str(node.get("id") or "") for node in tested)
            winner = next((node for node in tested if node.get("probe_status") == "available"), None)
            if winner:
                mark_channel_ready(channel_id, str(winner.get("id") or ""))
                print(
                    f"[new channel] {channel.get('country')} first usable node "
                    f"{winner.get('id')} verified; country exit released immediately.",
                    flush=True,
                )
                return
        except Exception as exc:
            print(f"[new channel] {channel.get('country')} bootstrap failed; retrying: {exc}", flush=True)
            time.sleep(10)


def migrate_multi_exit_channels() -> None:
    """Make old channels fail closed: automatic switching uses verified nodes only."""
    with multi_config_lock:
        config = read_multi_exit_config()
        changed = False
        for channel in config.get("channels", []):
            if not float(channel.get("created_at") or 0):
                date_match = re.search(r"(20\d{6})", str(channel.get("name") or ""))
                if date_match:
                    try:
                        channel["created_at"] = time.mktime(time.strptime(date_match.group(1), "%Y%m%d"))
                    except ValueError:
                        channel["created_at"] = time.time()
                else:
                    channel["created_at"] = time.time()
                changed = True
            expected_name = channel_display_name(channel)
            if channel.get("name") != expected_name:
                channel["name"] = expected_name
                changed = True
            if channel.get("tested_only") is not True:
                channel["tested_only"] = True
                changed = True
            if "standby_hot_target" not in channel:
                channel["standby_hot_target"] = HOT_STANDBY_TARGET
                channel["standby_normal_target"] = NORMAL_STANDBY_TARGET
                changed = True
        if changed:
            config["version"] = max(4, int(config.get("version") or 1))
            write_json(MULTI_EXIT_DIR / "channels.json", config)


def standby_maintenance_loop() -> None:
    """Keep a small, fresh per-country reserve without probing every node at once."""
    cursor = 0
    last_emergency_refresh_at = 0.0
    time.sleep(STANDBY_STARTUP_DELAY_SECONDS)
    while True:
        try:
            config = read_multi_exit_config()
            channels = [
                channel for channel in config.get("channels", [])
                if channel.get("enabled", True) and not channel.get("awaiting_initial_test")
            ]
            if not channels or maintenance_lock.locked() or is_connecting:
                time.sleep(STANDBY_MANAGER_INTERVAL_SECONDS)
                continue
            runtime = read_json(MULTI_EXIT_DIR / "state.json", {"channels": {}}).get("channels", {})
            if any(
                str((runtime.get(str(channel.get("id") or "")) or {}).get("status") or "")
                in {"connecting", "switching", "testing"}
                for channel in channels
            ):
                time.sleep(STANDBY_MANAGER_INTERVAL_SECONDS)
                continue
            ordered_channels = channels[cursor % len(channels):] + channels[:cursor % len(channels)]
            cursor = (cursor + 1) % len(channels)
            task_started = False
            now = time.time()
            for channel in ordered_channels:
                current_id = str((runtime.get(str(channel.get("id") or "")) or {}).get("node_id") or "")
                candidates = [
                    node for node in channel_source_candidates(channel)
                    if str(node.get("id") or "") != current_id
                ]
                if not candidates:
                    continue
                available = [node for node in candidates if node.get("probe_status") == "available"]
                available.sort(key=lambda node: (
                    -float(node.get("last_available_at") or node.get("probed_at") or 0),
                    parse_int(node.get("latency_ms")) or 999999,
                ))
                fresh_normal = [
                    node for node in available
                    if now - float(node.get("probed_at") or 0) <= NORMAL_STANDBY_RECHECK_SECONDS
                ]
                due: list[dict[str, Any]] = []
                target_total = HOT_STANDBY_TARGET + NORMAL_STANDBY_TARGET
                if len(fresh_normal) < target_total:
                    due = [
                        node for node in candidates
                        if node not in fresh_normal
                        and float(node.get("next_probe_at") or 0) <= now
                    ]
                else:
                    hot = available[:HOT_STANDBY_TARGET]
                    normal = available[HOT_STANDBY_TARGET:target_total]
                    due.extend(
                        node for node in hot
                        if now - float(node.get("probed_at") or 0) >= HOT_STANDBY_RECHECK_SECONDS
                    )
                    due.extend(
                        node for node in normal
                        if now - float(node.get("probed_at") or 0) >= NORMAL_STANDBY_RECHECK_SECONDS
                    )
                    if not due:
                        due.extend(
                            node for node in candidates[target_total:]
                            if now - float(node.get("probed_at") or 0) >= CANDIDATE_RECHECK_SECONDS
                            and float(node.get("next_probe_at") or 0) <= now
                        )
                ids = list(dict.fromkeys(str(node.get("id") or "") for node in due if node.get("id")))[:STANDBY_TEST_BATCH_SIZE]
                if not ids:
                    if len(fresh_normal) < HOT_STANDBY_TARGET and now - last_emergency_refresh_at >= 10 * 60:
                        refresh_node_catalog_only()
                        last_emergency_refresh_at = time.time()
                        task_started = True
                        break
                    continue
                test_node_availability_only(
                    ids,
                    trigger_legacy_auto=False,
                    task_label=f"{channel.get('country')}备用池维护",
                    channel_id=str(channel.get("id") or ""),
                )
                task_started = True
                break
            time.sleep(STANDBY_MANAGER_INTERVAL_SECONDS if task_started else min(60, STANDBY_MANAGER_INTERVAL_SECONDS * 2))
        except Exception as exc:
            print(f"[standby] maintenance error: {exc}", flush=True)
            time.sleep(STANDBY_MANAGER_INTERVAL_SECONDS)

import hashlib
import random

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": UI_HOST,
            "port": UI_PORT,
            "proxy_port": LOCAL_PROXY_PORT,
            "routing_mode": "auto",
            "force_country": "",
            "routing_ip_type": "all",
            "connection_enabled": True,
            "fixed_node_id": "",
            "favorite_node_ids": [],
            "fav_fail_fallback": False
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["host", "port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback"]:
                    if key not in data:
                        updated = True
            except Exception:
                pass

        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True

        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True

        normalized_port = bounded_int(config.get("port"), UI_PORT, 1, 65535)
        if normalized_port != config.get("port"):
            config["port"] = normalized_port
            updated = True

        normalized_proxy_port = bounded_int(config.get("proxy_port"), LOCAL_PROXY_PORT, 1024, 65535)
        if normalized_proxy_port == normalized_port:
            fallback_proxy_port = LOCAL_PROXY_PORT if LOCAL_PROXY_PORT != normalized_port else 7928
            if fallback_proxy_port == normalized_port:
                fallback_proxy_port = 7929
            normalized_proxy_port = fallback_proxy_port
        if normalized_proxy_port != config.get("proxy_port"):
            config["proxy_port"] = normalized_proxy_port
            updated = True

        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                write_json(auth_file, config)
            except Exception:
                pass

        return config

# 初始化时优先从 ui_auth.json 加载保存的代理出站端口和网页端口配置以覆盖环境变量
try:
    _init_cfg = load_ui_config()
    if "proxy_port" in _init_cfg:
        LOCAL_PROXY_PORT = bounded_int(_init_cfg["proxy_port"], LOCAL_PROXY_PORT, 1024, 65535)
    if "port" in _init_cfg:
        UI_PORT = bounded_int(_init_cfg["port"], UI_PORT, 1, 65535)
    if "host" in _init_cfg:
        UI_HOST = _init_cfg["host"]
except Exception:
    pass

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "aimilivpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

_last_cleanup_time = 0.0
_last_config_cleanup_time = 0.0

def cleanup_old_logs(logs_dir: Path) -> None:
    global _last_cleanup_time
    now = time.time()
    with lock:
        if now - _last_cleanup_time < 3600:
            return
        _last_cleanup_time = now
    try:
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        with lock:
                            path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        with lock:
                            path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def cleanup_stale_config_cache() -> int:
    """Daily removal of old, unreferenced and reproducible OVPN cache files."""
    global _last_config_cleanup_time
    now = time.time()
    with lock:
        if now - _last_config_cleanup_time < 24 * 3600:
            return 0
        _last_config_cleanup_time = now
        referenced = {
            Path(str(node.get("config_file") or "")).name
            for node in read_nodes() if node.get("config_file")
        }
    removed = 0
    try:
        for path in CONFIG_DIR.glob("*.ovpn"):
            if path.name in referenced:
                continue
            try:
                if now - path.stat().st_mtime >= CONFIG_CACHE_RETENTION_SECONDS:
                    path.unlink()
                    removed += 1
            except OSError:
                continue
    except OSError as exc:
        print(f"[config cache] cleanup failed: {exc}", flush=True)
    if removed:
        print(f"[config cache] removed {removed} stale unreferenced OVPN files", flush=True)
    return removed


def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)

def read_nodes() -> list[dict[str, Any]]:
    raw = read_json(NODES_FILE, [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def node_config_text(node: dict[str, Any]) -> str:
    inline = str(node.get("config_text") or "")
    if inline:
        return inline
    path_value = str(node.get("config_file") or "")
    if not path_value:
        return ""
    try:
        return Path(path_value).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def compact_node_catalog_configs() -> int:
    """Move inline OVPN text to files so the frequently-read catalog stays small."""
    with lock:
        nodes = read_nodes()
        changed = 0
        for node in nodes:
            inline = str(node.get("config_text") or "")
            if not inline:
                continue
            path_value = str(node.get("config_file") or "")
            if path_value:
                path = Path(path_value)
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if not path.exists() or path.stat().st_size < 100:
                        path.write_text(inline, encoding="utf-8")
                except OSError:
                    continue
            node.pop("config_text", None)
            changed += 1
        if changed:
            write_json(NODES_FILE, nodes)
        return changed

def reset_stale_testing_nodes(message: str = "等待下次检测") -> int:
    """Return interrupted probe records to a stable state."""
    with lock:
        nodes = read_nodes()
        reset_count = 0
        for node in nodes:
            if node.get("probe_status") == "testing":
                node["probe_status"] = "not_checked"
                node["probe_message"] = message
                reset_count += 1
        if reset_count:
            write_json(NODES_FILE, sort_all_nodes(nodes))
        return reset_count

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state.pop("password", None)
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state["maintenance_running"] = maintenance_lock.locked()
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    _proxy_display = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
    state["local_proxy"] = f"http://{_proxy_display}:{LOCAL_PROXY_PORT}"
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)
    state["metadata_refresh_paused"] = metadata_refresh_paused()

    # Pre-populate settings inputs in UI
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    state["password_set"] = bool(ui_cfg.get("password"))
    state["proxy_port"] = ui_cfg.get("proxy_port", 7928)
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["fixed_node_id"] = ui_cfg.get("fixed_node_id", "")
    state["favorite_node_ids"] = ui_cfg.get("favorite_node_ids", [])
    state["fav_fail_fallback"] = False

    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def clear_active_connection_state(message: str) -> None:
    global active_openvpn_process, active_openvpn_node_id
    stop_process(active_openvpn_process)
    active_openvpn_process = None
    active_openvpn_node_id = ""
    with lock:
        nodes = read_nodes()
        for item in nodes:
            item["active"] = False
        write_json(NODES_FILE, nodes)
    set_state(
        active_openvpn_node_id="",
        is_connecting=False,
        active_node_latency="无活动连接",
        last_check_message=message,
    )

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def proxy_basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"

def recv_exact_from_socket(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Unexpected EOF while reading proxy response")
        data += chunk
    return data

def read_http_response_head(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("Proxy response header too large")
    if b"\r\n\r\n" not in data:
        raise RuntimeError("Incomplete HTTP proxy response header")
    return data

def socks5_address_bytes(host: str) -> tuple[int, bytes]:
    try:
        return 1, socket.inet_aton(host)
    except OSError:
        pass
    try:
        return 4, socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        pass
    host_bytes = host.encode("idna")
    if len(host_bytes) > 255:
        raise RuntimeError("SOCKS5 target host name is too long")
    return 3, bytes([len(host_bytes)]) + host_bytes

def read_socks5_connect_reply(sock: socket.socket) -> None:
    header = recv_exact_from_socket(sock, 4)
    if header[0] != 5:
        raise RuntimeError("Invalid SOCKS5 reply version")
    atyp = header[3]
    if atyp == 1:
        recv_exact_from_socket(sock, 4)
    elif atyp == 3:
        domain_len = recv_exact_from_socket(sock, 1)[0]
        recv_exact_from_socket(sock, domain_len)
    elif atyp == 4:
        recv_exact_from_socket(sock, 16)
    else:
        raise RuntimeError(f"Invalid SOCKS5 reply address type: {atyp}")
    recv_exact_from_socket(sock, 2)
    if header[1] != 0:
        raise RuntimeError(f"SOCKS5 connection request rejected, code={header[1]}")

def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"

def fetch_api_text_via_proxy(url: str, ptype: str, phost: str, pport: int, use_ssl_verify: bool = True) -> str:
    import socket
    import ssl
    import urllib.parse

    parsed = urllib.parse.urlsplit(url)
    domain = parsed.hostname or "www.vpngate.net"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    is_ipv6 = ":" in phost
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(12)
        s.connect((phost, pport))
        proxy_user, proxy_pass = vpn_utils.get_upstream_proxy_auth()
        if ptype == "socks":
            # SOCKS5 Handshake
            if proxy_user is not None:
                s.sendall(b"\x05\x02\x00\x02")
            else:
                s.sendall(b"\x05\x01\x00")
            resp = recv_exact_from_socket(s, 2)
            if len(resp) < 2 or resp[0] != 5:
                raise RuntimeError("SOCKS5 authentication failed or unsupported")
            if resp[1] == 2:
                if proxy_user is None:
                    raise RuntimeError("SOCKS5 proxy requires username/password authentication")
                user_bytes = proxy_user.encode("utf-8")
                pass_bytes = (proxy_pass or "").encode("utf-8")
                if len(user_bytes) > 255 or len(pass_bytes) > 255:
                    raise RuntimeError("SOCKS5 proxy credentials are too long")
                s.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes)
                auth_resp = recv_exact_from_socket(s, 2)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    raise RuntimeError("SOCKS5 username/password authentication failed")
            elif resp[1] != 0:
                raise RuntimeError("SOCKS5 authentication method unsupported")
            # SOCKS5 Connect
            atyp, addr_bytes = socks5_address_bytes(domain)
            req = b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + port.to_bytes(2, 'big')
            s.sendall(req)
            read_socks5_connect_reply(s)
            # If HTTPS, wrap socket with SSL
            if is_https:
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
        else: # http proxy
            if is_https:
                # HTTP CONNECT tunnel
                authority = format_host_port(domain, port)
                auth_header = proxy_basic_auth_header(proxy_user, proxy_pass or "") if proxy_user is not None else ""
                req_str = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n{auth_header}Proxy-Connection: Keep-Alive\r\n\r\n"
                s.sendall(req_str.encode('ascii'))
                resp = read_http_response_head(s)
                status_line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                status_parts = status_line.split()
                status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
                if status_code != 200:
                    raise RuntimeError(f"HTTP CONNECT tunnel failed: {status_line}")
                # Wrap socket with SSL
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
            else:
                # Direct HTTP request through proxy: request URI must be absolute
                pass

        # Send HTTP GET request
        if ptype == "http" and not is_https:
            request_uri = url
        else:
            request_uri = path

        req_headers = (
            f"GET {request_uri} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n"
            f"Accept: text/plain,*/*\r\n"
            f"{proxy_basic_auth_header(proxy_user, proxy_pass or '') if ptype == 'http' and not is_https and proxy_user is not None else ''}"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req_headers.encode('utf-8'))

        # Read response with an absolute deadline. A peer sending a few bytes at
        # a time must not hold the whole node-management lock for minutes.
        response_data = b""
        read_deadline = time.monotonic() + 30
        while True:
            remaining = read_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("VPN Gate response timed out after 30 seconds")
            s.settimeout(min(12, max(1, remaining)))
            chunk = s.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if len(response_data) > 10 * 1024 * 1024: # max 10MB safety guard
                break
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # Parse HTTP response
    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        raise RuntimeError("Invalid HTTP response format")

    headers_part = response_data[:header_end].decode('utf-8', errors='replace')
    body_part = response_data[header_end+4:]

    # Check for HTTP status code
    lines = headers_part.splitlines()
    if not lines:
        raise RuntimeError("Empty response headers")
    status_line = lines[0]
    status_parts = status_line.split()
    if len(status_parts) >= 2:
        try:
            status_code = int(status_parts[1])
            if status_code != 200:
                raise RuntimeError(f"HTTP Server returned status {status_code}: {status_line}")
        except ValueError:
            pass

    # Handle chunked transfer encoding
    is_chunked = False
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
                is_chunked = True
                break

    if is_chunked:
        decoded = b""
        idx = 0
        while idx < len(body_part):
            c_end = body_part.find(b"\r\n", idx)
            if c_end == -1:
                break
            chunk_size_str = body_part[idx:c_end].split(b";")[0].strip()
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            idx = c_end + 2
            decoded += body_part[idx : idx + chunk_size]
            idx += chunk_size + 2
        body_part = decoded

    return body_part.decode('utf-8', errors='replace')

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None:
        url = API_URL

    ptype, phost, pport = vpn_utils.get_upstream_proxy()
    if ptype and phost and pport:
        try:
            print(f"[fetch_api_text] 监测到上游代理 ({ptype}://{phost}:{pport})，尝试通过代理获取 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify)
        except Exception as e:
            print(f"[fetch_api_text] 通过代理获取 API 失败: {e}，尝试使用直连/默认系统代理...", flush=True)
            log_to_json("WARNING", "Main", f"使用代理 {ptype}://{phost}:{pport} 获取 API 失败: {e}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0",
            "Accept": "text/plain,*/*",
        },
    )
    if url.startswith("https://") and not use_ssl_verify:
        import ssl
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=12, context=ctx) as response:
            return response.read().decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.read().decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def load_blacklist() -> dict[str, dict[str, Any]]:
    now = time.time()
    raw = read_json(BLACKLIST_FILE, {})
    if not isinstance(raw, dict):
        return {}
    cleaned: dict[str, dict[str, Any]] = {}
    changed = False
    for key, entry in raw.items():
        if not isinstance(entry, dict):
            changed = True
            continue
        until = float(entry.get("until", 0) or 0)
        if until and until > now:
            cleaned[str(key)] = entry
        else:
            changed = True
    if changed:
        write_json(BLACKLIST_FILE, cleaned)
    return cleaned

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    node_id = str(node.get("id") or "").strip()
    if not node_id:
        return
    blacklist = load_blacklist()
    now = time.time()
    blacklist[node_id] = {
        "id": node_id,
        "ip": node.get("ip") or node.get("remote_host") or "",
        "country": node.get("country", ""),
        "reason": message,
        "marked_at": now,
        "until": now + INVALID_BACKOFF_SECONDS,
    }
    write_json(BLACKLIST_FILE, blacklist)

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"

    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "exit_ip": "",
        "exit_country": "",
        "exit_country_short": "",
        "exit_location": "",
        "exit_owner": "",
        "exit_asn": "",
        "exit_as_name": "",
        "exit_ip_type": "",
        "exit_quality": "",
        "exit_checked_at": 0,
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def fetch_mirror_api_urls() -> list[str]:
    if VPNGATE_MIRROR_SOURCES <= 0:
        return []

    api_urls: list[str] = []
    seen: set[str] = set()
    for configured_url in VPNGATE_EXTRA_API_URLS.split(","):
        configured_url = configured_url.strip()
        if not configured_url or not re.match(r"^https?://", configured_url, flags=re.IGNORECASE):
            continue
        if not configured_url.endswith("/"):
            configured_url += "/"
        if configured_url == API_URL or configured_url in seen:
            continue
        seen.add(configured_url)
        api_urls.append(configured_url)
        if len(api_urls) >= VPNGATE_MIRROR_SOURCES:
            return api_urls

    # Reuse mirrors that succeeded recently before trying newly advertised ones.
    cached_mirrors = read_json(MIRROR_URLS_FILE, [])
    if isinstance(cached_mirrors, list):
        for cached_url in cached_mirrors:
            cached_url = str(cached_url or "").strip()
            if not re.match(r"^https?://", cached_url, flags=re.IGNORECASE):
                continue
            if cached_url == API_URL or cached_url in seen:
                continue
            seen.add(cached_url)
            api_urls.append(cached_url)
            if len(api_urls) >= VPNGATE_MIRROR_SOURCES:
                return api_urls

    try:
        mirror_html = fetch_api_text(MIRROR_LIST_URL, True)
    except Exception as exc:
        print(f"[fetch_candidates] 获取官方镜像列表失败，将使用已缓存镜像: {exc}", flush=True)
        log_to_json("WARNING", "Main", f"获取官方镜像列表失败: {exc}")
        return api_urls

    roots = re.findall(
        r"https?://[A-Za-z0-9.-]+(?::[0-9]+)?/en/",
        mirror_html,
        flags=re.IGNORECASE,
    )
    for root in roots:
        api_url = root.rsplit("/en/", 1)[0] + "/api/iphone/"
        if api_url == API_URL or api_url in seen:
            continue
        seen.add(api_url)
        api_urls.append(api_url)
        if len(api_urls) >= VPNGATE_MIRROR_SOURCES:
            break
    return api_urls

def fetch_candidates(aggregate_all_sources: bool = False) -> list[dict[str, Any]]:
    if metadata_cancel_event.is_set():
        raise CatalogRefreshCancelled("节点资料拉取已停止")
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_ips = set()
    source_stats: list[dict[str, Any]] = []
    successful_mirrors: list[str] = []
    ingest_lock = threading.Lock()
    ui_cfg = load_ui_config()
    preferred_country = ""
    if ui_cfg.get("routing_mode") == "fixed_region":
        preferred_country = str(ui_cfg.get("force_country") or "").strip()

    log_to_json("INFO", "Main", "开始拉取 VPN Gate 主站及官方镜像 API 节点列表...")
    last_err = None

    def preferred_count() -> int:
        if not preferred_country:
            return 0
        return sum(1 for node in candidates if country_matches(node.get("country"), preferred_country))

    def ingest_source(url: str, verify_ssl: bool = True) -> bool:
        nonlocal last_err
        if metadata_cancel_event.is_set():
            raise CatalogRefreshCancelled("节点资料拉取已停止")
        before = len(candidates)
        try:
            msg = f"尝试拉取 {url} (SSL验证: {verify_ssl})..."
            print(f"[fetch_candidates] {msg}", flush=True)
            log_to_json("INFO", "Main", msg)
            api_text = fetch_api_text(url, verify_ssl)
            if metadata_cancel_event.is_set():
                raise CatalogRefreshCancelled("节点资料拉取已停止")
            rows = parse_vpngate_rows(api_text)
            with ingest_lock:
                before = len(candidates)
                for row in rows[:MAX_SCAN_ROWS]:
                    if metadata_cancel_event.is_set():
                        raise CatalogRefreshCancelled("节点资料拉取已停止")
                    ip = row.get("IP", "")
                    if not ip or ip in seen_ips:
                        continue
                    encoded = row.get("OpenVPN_ConfigData_Base64", "")
                    if not encoded:
                        continue
                    try:
                        config_text = decode_config(encoded)
                        node = row_to_node(row, config_text)
                    except Exception as row_exc:
                        print(f"[fetch_candidates] 跳过损坏的节点配置记录: {row_exc}", flush=True)
                        log_to_json("WARNING", "Main", f"跳过损坏的节点配置记录: {row_exc}")
                        continue
                    entry = blacklist.get(node["id"])
                    if entry and float(entry.get("until", 0) or 0) > time.time():
                        continue
                    candidates.append(node)
                    seen_ips.add(ip)
                added = len(candidates) - before
                source_stats.append({"url": url, "rows": len(rows), "added": added})
                if url != API_URL and url not in successful_mirrors:
                    successful_mirrors.append(url)
            print(
                f"[fetch_candidates] 来源完成: 原始 {len(rows)} 条，新增 {added} 个唯一节点，"
                f"当前合计 {len(candidates)} 个，目标国家 {preferred_country or '-'}: {preferred_count()} 个",
                flush=True,
            )
            return True
        except CatalogRefreshCancelled:
            raise
        except Exception as exc:
            last_err = exc
            print(f"[fetch_candidates] 拉取失败 (URL: {url}, 验证: {verify_ssl}): {exc}", flush=True)
            log_to_json("WARNING", "Main", f"拉取失败 (URL: {url}, 验证: {verify_ssl}): {exc}")
            return False

    primary_ok = ingest_source(API_URL, True)
    primary_timed_out = (not primary_ok and last_err is not None and "timed out" in str(last_err).lower())
    if not primary_ok and not primary_timed_out:
        primary_ok = ingest_source(API_URL, False)
    if not primary_ok and not primary_timed_out and API_URL.startswith("https://"):
        ingest_source(API_URL.replace("https://", "http://"), True)

    if aggregate_all_sources or (preferred_country and preferred_count() < TARGET_COUNTRY_MIN_NODES):
        mirror_urls = fetch_mirror_api_urls()
        if aggregate_all_sources:
            print(f"[fetch_candidates] 正在并发聚合 {len(mirror_urls)} 个官方镜像，以获取完整国家节点列表。", flush=True)
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=min(VPNGATE_MIRROR_WORKERS, max(1, len(mirror_urls))))
            try:
                futures = [
                    executor.submit(ingest_source, mirror_url, mirror_url.lower().startswith("https://"))
                    for mirror_url in mirror_urls
                ]
                for future in concurrent.futures.as_completed(futures):
                    if metadata_cancel_event.is_set():
                        for pending in futures:
                            pending.cancel()
                        raise CatalogRefreshCancelled("节点资料拉取已停止")
                    try:
                        future.result()
                    except CatalogRefreshCancelled:
                        raise
                    except Exception:
                        pass
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
        else:
            print(
                f"[fetch_candidates] 主站中的【{preferred_country}】节点不足 {TARGET_COUNTRY_MIN_NODES} 个，"
                f"将聚合 {len(mirror_urls)} 个官方镜像。",
                flush=True,
            )
            for mirror_url in mirror_urls:
                if metadata_cancel_event.is_set():
                    raise CatalogRefreshCancelled("节点资料拉取已停止")
                ingest_source(mirror_url, mirror_url.lower().startswith("https://"))
                if preferred_count() >= TARGET_COUNTRY_MIN_NODES:
                    break

    if metadata_cancel_event.is_set():
        raise CatalogRefreshCancelled("节点资料拉取已停止")
    if not candidates:
        err_code, diag_msg = vpn_utils.diagnose_api_failure(API_URL)
        full_err_msg = f"获取官方 API 节点最终失败: {last_err} | 诊断结果: {diag_msg}"
        print(f"[错误代码 {err_code}] {full_err_msg}", flush=True)
        log_to_json("ERROR", "Main", f"[错误代码 {err_code}] {full_err_msg}")
        set_state(
            last_fetch_status="error",
            last_fetch_error_code=err_code,
            last_fetch_message=diag_msg
        )
        if last_err:
            raise RuntimeError(diag_msg) from last_err
        else:
            raise RuntimeError(diag_msg)

    if successful_mirrors:
        write_json(MIRROR_URLS_FILE, successful_mirrors[:VPNGATE_MIRROR_SOURCES])

    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok",
        last_fetch_message=(
            f"Fetched {len(candidates)} unique candidates from {len(source_stats)} official sources. "
            f"Target country {preferred_country or '-'}: {preferred_count()} nodes."
        ),
        blacklisted_nodes=len(blacklist),
    )
    log_to_json(
        "INFO",
        "Main",
        f"成功聚合 VPN Gate 官方来源，共 {len(candidates)} 个候选节点；来源统计: {source_stats}",
    )
    return candidates

def cached_nodes() -> list[dict[str, Any]]:
    return read_nodes()

_openvpn_version = None

def split_openvpn_command() -> list[str]:
    try:
        return shlex.split(OPENVPN_CMD, posix=(os.name != "nt")) or ["openvpn"]
    except ValueError as exc:
        raise RuntimeError(f"OPENVPN_CMD 配置无法解析: {exc}") from exc

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = split_openvpn_command()
        res = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    command = split_openvpn_command()
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(AUTH_FILE),
            "--auth-nocache",
        ]
    )

    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(["--verb", "3"])

    if os.path.exists("/etc/ssl/certs"):
        command.extend(["--capath", "/etc/ssl/certs"])

    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            auth_file = upstream_proxy_auth_file()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
    except Exception:
        pass

    if route_nopull:
        command.append("--route-nopull")
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        own_markers = [
            str(DATA_DIR),
            str(CONFIG_DIR),
            str(AUTH_FILE),
            str(UPSTREAM_PROXY_AUTH_FILE),
        ]
        killed_pids: list[int] = []
        proc_root = Path("/proc")
        if not proc_root.exists():
            return
        for proc_dir in proc_root.iterdir():
            if not proc_dir.name.isdigit():
                continue
            pid = int(proc_dir.name)
            if pid == os.getpid():
                continue
            try:
                raw = (proc_dir / "cmdline").read_bytes()
            except OSError:
                continue
            if not raw:
                continue
            args = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
            if not args:
                continue
            cmdline = " ".join(args)
            executable = Path(args[0]).name.lower()
            if "openvpn" not in executable and "openvpn" not in cmdline.lower():
                continue
            if any(marker and marker in cmdline for marker in own_markers):
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed_pids.append(pid)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    print(f"[Cleanup] No permission to terminate OpenVPN PID {pid}", flush=True)
        if killed_pids:
            time.sleep(0.5)
            for pid in killed_pids:
                try:
                    raw = (proc_root / str(pid) / "cmdline").read_bytes()
                    cmdline = " ".join(part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part)
                    if any(marker and marker in cmdline for marker in own_markers):
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except (OSError, PermissionError):
                    pass
            print(f"[Cleanup] Terminated AimiliVPN OpenVPN processes: {killed_pids}", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0") -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "[错误代码 2001] [ERR_OVPN_CMD_NOT_FOUND] 未找到 openvpn 命令。原因: 系统未安装 openvpn，或 PATH 环境变量不正确。", None
    except OSError as exc:
        return False, f"[错误代码 2002] [ERR_OVPN_START_FAILED] openvpn 启动失败: {exc}。原因: 系统权限不足或配置冲突。", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]
    openvpn_logs: list[str] = []

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            line_str = line.rstrip()
            if not startup_done[0]:
                openvpn_logs.append(line_str)
                lines.put(line_str)
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line_str}", flush=True)
                    level = "INFO"
                    line_lower = line_str.lower()
                    if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
                        level = "ERROR"
                    elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
                        level = "WARNING"
                    log_to_json(level, "VPN", f"[OpenVPN] {line_str}")
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-50:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    # Bulk write accumulated startup logs
    for line_str in openvpn_logs:
        level = "INFO"
        line_lower = line_str.lower()
        if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
            level = "ERROR"
        elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
            level = "WARNING"
        log_to_json(level, "VPN", f"[OpenVPN] {line_str}")

    if not ok:
        err_code, diag_msg = vpn_utils.diagnose_openvpn_failure(tail)
        message = f"[错误代码 {err_code}] {diag_msg} (原始日志尾部: {tail[-1][-100:] if tail else '无'})"
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    return ok, message, process


def setup_policy_routing(interface: str = "tun0") -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass

    success = False
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", "100"], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", "100"], check=True, timeout=2)
            # 配置反向路径过滤 rp_filter 为 loose 模式 (2)，防止回包被内核静默丢弃
            for proc_path in ["all", "default", interface]:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{proc_path}.rp_filter=2"], capture_output=True, timeout=2)
                except Exception:
                    pass
            print(f"[policy_routing] Enabled policy routing for interface {interface} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)

    if not success:
        print("[路由配置失败] [错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由，这可能会导致通过 VPN 接口的出站路由无法正常解析。请检查系统是否支持策略路由、iproute2 工具是否完整，以及是否具有 root 权限。", flush=True)
        log_to_json("ERROR", "Routing", "[错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由")

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
        print("[policy_routing] Cleared policy routing table 100", flush=True)
    except Exception:
        pass

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    with lock:
        cleanup_policy_routing()
        config_to_delete = None
        if active_openvpn_node_id:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
            if node:
                config_to_delete = node.get("config_file")

        stop_process(active_openvpn_process)
        active_openvpn_process = None
        active_openvpn_node_id = ""
        kill_existing_openvpn_processes()

        if config_to_delete:
            try:
                path = Path(config_to_delete)
                if path.exists():
                    path.unlink()
            except Exception:
                pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def effective_node_ip_type(node: dict[str, Any]) -> str:
    """Prefer IPPure-verified egress type, then conservative entry-IP type."""
    if node.get("exit_classification_source") == "ippure" and node.get("exit_ip_type"):
        return str(node.get("exit_ip_type") or "")
    return str(node.get("ip_type") or "")

def ip_type_priority(node: dict[str, Any]) -> int:
    return 0 if effective_node_ip_type(node) in ("residential", "mobile") else 1

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "available" or n.get("active")],
        key=lambda n: (
            ip_type_priority(n),
            parse_int(n.get("latency_ms")) or 999999,
            -parse_int(n.get("score"))
        )
    )
    untested_nodes = sorted(
        [n for n in nodes if n.get("probe_status") in ("not_checked", "testing") and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "unavailable" and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes

def apply_routing_filters(
    nodes: list[dict[str, Any]],
    ui_cfg: dict[str, Any],
    include_unknown_ip_type: bool = False,
) -> list[dict[str, Any]]:
    candidates = list(nodes)
    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_region" and target_country:
        candidates = [
            n for n in candidates
            if country_matches(n.get("country"), target_country)
        ]
    elif routing_mode == "favorites":
        fav_ids = set(ui_cfg.get("favorite_node_ids", []))
        candidates = [n for n in candidates if n.get("id") in fav_ids]

    routing_ip_type = ui_cfg.get("routing_ip_type", "all")
    if routing_ip_type == "residential":
        candidates = [
            n for n in candidates
            if n.get("exit_ip_type") in ("residential", "mobile")
            or not n.get("exit_ip")
            or (include_unknown_ip_type and not n.get("exit_ip_type"))
        ]
    elif routing_ip_type == "hosting":
        candidates = [
            n for n in candidates
            if n.get("exit_ip_type") == "hosting"
            or not n.get("exit_ip")
            or (include_unknown_ip_type and not n.get("exit_ip_type"))
        ]

    return candidates

def normalized_country_name(country: Any) -> str:
    value = str(country or "").strip()
    value = vpn_utils.COUNTRY_TRANSLATIONS.get(value, value)
    aliases = {
        "俄罗斯联邦": "俄罗斯", "大韩民国": "韩国", "韩国共和国": "韩国",
        "美利坚合众国": "美国", "越南社会主义共和国": "越南",
    }
    return aliases.get(value, value)


COUNTRY_DISPLAY_NAMES = {
    "US": "UnitedStates", "JP": "Japan", "KR": "SouthKorea", "TH": "Thailand",
    "VN": "Vietnam", "CA": "Canada", "GB": "UnitedKingdom", "RU": "Russia",
    "CN": "China", "TW": "Taiwan", "HK": "HongKong", "SG": "Singapore",
    "MY": "Malaysia", "ID": "Indonesia", "IN": "India", "PH": "Philippines",
    "AU": "Australia", "NZ": "NewZealand", "UA": "Ukraine", "FR": "France",
    "DE": "Germany", "NL": "Netherlands", "SE": "Sweden", "NO": "Norway",
    "ES": "Spain", "TR": "Turkey", "ZA": "SouthAfrica", "BR": "Brazil",
    "AR": "Argentina", "CL": "Chile", "MX": "Mexico", "PL": "Poland",
    "RO": "Romania", "IT": "Italy", "CH": "Switzerland", "BE": "Belgium",
    "AT": "Austria", "DK": "Denmark", "FI": "Finland", "PT": "Portugal",
    "IE": "Ireland", "IL": "Israel", "AE": "UnitedArabEmirates",
}


def channel_display_name(channel: dict[str, Any]) -> str:
    """Return server suffix, Chinese country name and its creation date."""
    country = normalized_country_name(channel.get("country")) or "国家"
    created_at = float(channel.get("created_at") or time.time())
    return server_node_name(f"{country}-{time.strftime('%Y%m%d', time.localtime(created_at))}")


def generated_channel_name(country: Any, country_nodes: list[dict[str, Any]]) -> str:
    """Return a Chinese country name plus today's creation date."""
    return channel_display_name({"country": country, "created_at": time.time()})


def normalize_node_country_catalog() -> int:
    with lock:
        nodes = read_nodes()
        changed = 0
        for node in nodes:
            normalized = normalized_country_name(node.get("country"))
            if normalized and normalized != node.get("country"):
                node["country"] = normalized
                changed += 1
        if changed:
            write_json(NODES_FILE, sort_all_nodes(nodes))
        return changed

def country_matches(node_country: Any, target_country: Any) -> bool:
    return bool(target_country) and normalized_country_name(node_country) == normalized_country_name(target_country)

def should_prefer_residential_us(
    active_node: dict[str, Any], nodes: list[dict[str, Any]], ui_cfg: dict[str, Any]
) -> bool:
    if ui_cfg.get("routing_ip_type", "all") != "all":
        return False
    target_country = str(ui_cfg.get("force_country") or "").strip()
    fixed_us = ui_cfg.get("routing_mode") == "fixed_region" and country_matches(target_country, "美国")
    active_us = country_matches(active_node.get("exit_country") or active_node.get("country"), "美国")
    if not (fixed_us or active_us) or effective_node_ip_type(active_node) in ("residential", "mobile"):
        return False
    return any(
        n.get("id") != active_node.get("id")
        and n.get("probe_status") == "available"
        and country_matches(n.get("country"), "美国")
        and effective_node_ip_type(n) in ("residential", "mobile")
        for n in nodes
    )

def inspect_exit_ip(exit_ip: str) -> dict[str, Any]:
    """Classify the public address observed through the active VPN tunnel."""
    exit_ip = str(exit_ip or "").strip()
    if not exit_ip:
        return {}
    probe: dict[str, Any] = {"ip": exit_ip}
    try:
        vpn_utils.enrich_ip_info([probe])
    except Exception as exc:
        print(f"[exit validation] IP classification failed for {exit_ip}: {exc}", flush=True)

    ippure_age = time.time() - float(probe.get("ippure_checked_at") or 0)
    if probe.get("classification_source") != "ippure" or ippure_age > 6 * 3600:
        try:
            ippure = vpn_utils.query_ippure_current_ip(
                f"http://127.0.0.1:{LOCAL_PROXY_PORT}", timeout=12
            )
            if ippure.get("ip") == exit_ip and ippure.get("ip_type"):
                for key in (
                    "owner", "asn", "as_name", "location", "ip_type", "quality",
                    "geo_country", "geo_country_short", "classification_source",
                    "risk_score", "ippure_checked_at",
                ):
                    if ippure.get(key) not in (None, ""):
                        probe[key] = ippure.get(key)
                vpn_utils.cache_authoritative_ip_info(exit_ip, probe)
                print(
                    f"[exit validation] IPPure classified {exit_ip} as {probe.get('ip_type')} "
                    f"(risk {probe.get('risk_score', 0)})",
                    flush=True,
                )
        except Exception as exc:
            print(f"[exit validation] IPPure query failed for {exit_ip}: {exc}", flush=True)
    return {
        "exit_ip": exit_ip,
        "exit_country": probe.get("geo_country", ""),
        "exit_country_short": probe.get("geo_country_short", ""),
        "exit_location": probe.get("location", ""),
        "exit_owner": probe.get("owner", ""),
        "exit_asn": probe.get("asn", ""),
        "exit_as_name": probe.get("as_name", ""),
        "exit_ip_type": probe.get("ip_type", ""),
        "exit_quality": probe.get("quality", ""),
        "exit_classification_source": probe.get("classification_source", ""),
        "exit_risk_score": probe.get("risk_score", 0),
        "exit_checked_at": time.time(),
    }

def apply_exit_metadata_to_node(node: dict[str, Any], exit_metadata: dict[str, Any]) -> None:
    node.update(exit_metadata)
    node_ip = str(node.get("ip") or node.get("remote_host") or "").strip()
    exit_ip = str(exit_metadata.get("exit_ip") or "").strip()
    if node_ip and exit_ip == node_ip:
        mapping = {
            "exit_owner": "owner",
            "exit_asn": "asn",
            "exit_as_name": "as_name",
            "exit_location": "location",
            "exit_ip_type": "ip_type",
            "exit_quality": "quality",
            "exit_classification_source": "classification_source",
            "exit_risk_score": "risk_score",
        }
        for source_key, target_key in mapping.items():
            if exit_metadata.get(source_key) not in (None, ""):
                node[target_key] = exit_metadata.get(source_key)

def validate_exit_allowed_by_routing(node: dict[str, Any], ui_cfg: dict[str, Any]) -> None:
    """Enforce country and address-type locks against the real egress IP."""
    exit_ip = str(node.get("exit_ip") or "").strip()
    if not exit_ip:
        raise RuntimeError("无法获取真实出口 IP，不能确认节点是否符合锁定规则")

    if ui_cfg.get("routing_mode") == "fixed_region":
        target_country = str(ui_cfg.get("force_country") or "").strip()
        exit_country = str(node.get("exit_country") or "").strip()
        exit_country_short = str(node.get("exit_country_short") or "").strip().upper()
        target_short = target_country.upper()
        matches = country_matches(exit_country, target_country) or (
            len(target_short) == 2 and target_short == exit_country_short
        )
        if target_country and not matches:
            actual = exit_country or exit_country_short or "未知国家"
            raise RuntimeError(
                f"入口标记为 {node.get('country') or '-'}，但真实出口 {exit_ip} 位于 {actual}，不符合锁定国家 {target_country}"
            )

    routing_ip_type = ui_cfg.get("routing_ip_type", "all")
    exit_ip_type = str(node.get("exit_ip_type") or "").strip()
    if routing_ip_type == "residential" and exit_ip_type not in ("residential", "mobile"):
        raise RuntimeError(f"真实出口 {exit_ip} 的 IP 类型为 {exit_ip_type or '未知'}，不符合住宅 IP 锁定")
    if routing_ip_type == "hosting" and exit_ip_type != "hosting":
        raise RuntimeError(f"真实出口 {exit_ip} 的 IP 类型为 {exit_ip_type or '未知'}，不符合机房 IP 锁定")

def probe_priority_key(node: dict[str, Any]) -> tuple[int, int, int, int, int]:
    ping = parse_int(node.get("ping")) or 999999
    return (
        ip_type_priority(node),
        ping,
        -parse_int(node.get("score")),
        -parse_int(node.get("speed")),
        parse_int(node.get("sessions")),
    )

def current_fixed_node_id(ui_cfg: dict[str, Any]) -> str:
    if active_openvpn_node_id:
        return active_openvpn_node_id
    nodes = read_nodes()
    active_node = next((n for n in nodes if n.get("active") and n.get("id")), None)
    if active_node:
        return str(active_node.get("id") or "")
    return str(ui_cfg.get("fixed_node_id") or "").strip()

def validate_node_allowed_by_routing(node: dict[str, Any], ui_cfg: dict[str, Any]) -> None:
    routing_mode = ui_cfg.get("routing_mode", "auto")
    node_id = str(node.get("id") or "")

    if routing_mode == "fixed_region":
        target_country = ui_cfg.get("force_country", "")
        if target_country and not country_matches(node.get("country"), target_country):
            raise RuntimeError(f"当前已锁定国家【{target_country}】，不能连接其他国家节点")
    elif routing_mode == "favorites":
        fav_ids = set(ui_cfg.get("favorite_node_ids", []))
        if node_id not in fav_ids:
            raise RuntimeError("当前处于仅用收藏模式，不能连接未收藏节点")

    routing_ip_type = ui_cfg.get("routing_ip_type", "all")
    exit_ip = node.get("exit_ip")
    node_ip_type = node.get("exit_ip_type")
    if exit_ip and routing_ip_type == "residential" and node_ip_type not in ("residential", "mobile"):
        raise RuntimeError("当前已锁定住宅 IP 出站，不能连接非住宅节点")
    if exit_ip and routing_ip_type == "hosting" and node_ip_type != "hosting":
        raise RuntimeError("当前已锁定机房 IP 出站，不能连接非机房节点")

def enforce_active_node_allowed_by_routing(ui_cfg: dict[str, Any], reason: str = "路由规则已更新") -> str | None:
    active_id = active_openvpn_node_id
    if not active_id:
        return None

    nodes = read_nodes()
    active_node = next((item for item in nodes if item.get("id") == active_id), None)
    if not active_node:
        clear_active_connection_state(f"{reason}，当前活动节点已不在节点列表中，已断开连接")
        return "当前活动节点已不在节点列表中，已断开连接"

    try:
        validate_node_allowed_by_routing(active_node, ui_cfg)
        return None
    except Exception as exc:
        msg = f"{reason}，当前活动节点 {active_id} 不符合新规则，已断开连接: {exc}"
        print(f"[路由规则] {msg}", flush=True)
        log_to_json("WARNING", "Routing", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(
            active_openvpn_node_id="",
            active_node_latency="无活动连接",
            proxy_ok=False,
            proxy_ip="-",
            proxy_latency_ms=0,
            proxy_error=msg,
            last_check_message=msg,
        )

        if ui_cfg.get("connection_enabled", True) and ui_cfg.get("routing_mode") != "fixed_ip":
            threading.Thread(target=auto_switch_node, daemon=True).start()
        return msg

def reconnect_fixed_node_if_needed(ui_cfg: dict[str, Any]) -> bool:
    global is_connecting
    if ui_cfg.get("routing_mode") != "fixed_ip" or active_openvpn_running():
        return False
    target_id = current_fixed_node_id(ui_cfg)
    if not target_id:
        return False
    nodes = read_nodes()
    if not any(n.get("id") == target_id for n in nodes):
        return False

    print(f"[维护线程] 固定 IP 模式下 OpenVPN 未运行，正在重新拉起同一节点: {target_id}", flush=True)
    previous_connecting = is_connecting
    is_connecting = False
    try:
        connect_node(target_id)
        return active_openvpn_running()
    except Exception as e:
        print(f"[维护线程] 重新拉起固定节点 {target_id} 失败: {e}", flush=True)
        return False
    finally:
        is_connecting = previous_connecting

active_test_indexes = set()
test_indexes_lock = threading.Lock()


def cleanup_stale_probe_processes(max_age_seconds: int = 90) -> int:
    """Kill only abandoned OpenVPN processes created from our .test_ profiles."""
    cleaned = 0
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid=,etimes=,args="],
            text=True, capture_output=True, check=False, timeout=5,
        )
        for raw in result.stdout.splitlines():
            parts = raw.strip().split(None, 2)
            if len(parts) != 3:
                continue
            pid_text, age_text, command = parts
            if not pid_text.isdigit() or not age_text.isdigit():
                continue
            if int(age_text) < max_age_seconds or "openvpn" not in command or ".test_" not in command:
                continue
            try:
                os.kill(int(pid_text), signal.SIGTERM)
                cleaned += 1
            except (ProcessLookupError, PermissionError):
                pass
    except Exception as exc:
        print(f"[probe cleanup] failed: {exc}", flush=True)
    try:
        cutoff = time.time() - max_age_seconds
        for path in CONFIG_DIR.glob(".test_*.ovpn"):
            if path.stat().st_mtime < cutoff:
                path.unlink(missing_ok=True)
    except Exception:
        pass
    return cleaned

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        raise RuntimeError("没有可用的 OpenVPN 测试网卡编号，请稍后重试")

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def test_config_path(node_id: str) -> Path:
    safe_id = safe_name(node_id)
    return CONFIG_DIR / f".test_{safe_id}_{uuid.uuid4().hex}.ovpn"

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_text = node_config_text(node)
        h = str(node.get("remote_host") or node.get("ip"))
        p = parse_int(node.get("remote_port"))
        fallback_ping = parse_int(node.get("ping"))

    temp_path = test_config_path(node_id)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}")

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)

    idx = None
    try:
        idx = get_free_test_index()
        ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=f"tun{idx}")
    finally:
        if idx is not None:
            release_test_index(idx)
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

    temp_node = {
        "id": node_id,
        "ip": h,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                node["owner"] = temp_node["owner"]
                node["asn"] = temp_node["asn"]
                node["as_name"] = temp_node["as_name"]
                node["location"] = temp_node["location"]
                node["ip_type"] = temp_node["ip_type"]
                node["quality"] = temp_node["quality"]

            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def test_multiple_nodes(node_ids: list[str], progress_label: str = "", on_result=None) -> list[dict[str, Any]]:
    cleanup_stale_probe_processes()
    with lock:
        nodes = read_nodes()
        to_test = [n for n in nodes if n.get("id") in node_ids and not n.get("active")]
        now = time.time()
        for n in nodes:
            if n.get("id") in node_ids and not n.get("active") and n.get("probe_status") != "unavailable":
                n["probe_status"] = "testing"
                n["probe_message"] = "正在检测节点连通性..."
                n["probed_at"] = now
        write_json(NODES_FILE, sort_all_nodes(nodes))

    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        node_id = n_info["id"]
        config_text = node_config_text(n_info)
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        fallback_ping = parse_int(n_info.get("ping"))

        temp_path = test_config_path(node_id)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            return {
                "id": node_id,
                "latency_ms": 0,
                "probe_status": "unavailable",
                "probe_message": f"Failed to write configuration: {e}",
                "probed_at": time.time(),
                "owner": n_info.get("owner", ""),
                "asn": n_info.get("asn", ""),
                "as_name": n_info.get("as_name", ""),
                "location": n_info.get("location", ""),
                "ip_type": n_info.get("ip_type", ""),
                "quality": n_info.get("quality", ""),
            }

        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        tun_idx = None
        try:
            tun_idx = get_free_test_index()
            dev_name = f"tun{tun_idx}"
            ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=dev_name)
        finally:
            if tun_idx is not None:
                release_test_index(tun_idx)
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass

        temp_node = {
            "id": node_id,
            "ip": n_info.get("ip") or h,
            "remote_host": h,
            "remote_port": p,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": n_info.get("owner", ""),
            "asn": n_info.get("asn", ""),
            "as_name": n_info.get("as_name", ""),
            "location": n_info.get("location", ""),
            "ip_type": n_info.get("ip_type", ""),
            "quality": n_info.get("quality", ""),
        }
        return temp_node

    updated_nodes_map = {}
    max_workers = min(AVAILABILITY_TEST_WORKERS, max(1, len(to_test)))
    flush_step = max(4, max_workers * 4)
    progress_step = max(2, max_workers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_worker, (idx, n)): n["id"] for idx, n in enumerate(to_test)}
        completed_count = 0
        available_so_far = 0
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            previous = next((node for node in to_test if node.get("id") == nid), {})
            try:
                res = future.result()
            except Exception as e:
                res = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": f"Test exception: {e}",
                    "latency_ms": 0,
                    "probed_at": time.time(),
                }
            if res.get("probe_status") == "available":
                available_so_far += 1
                res["availability_failures"] = 0
                res["next_probe_at"] = 0
                res["last_available_at"] = time.time()
            else:
                failures = int(previous.get("availability_failures") or 0) + 1
                backoff = (10 * 60, 30 * 60, 2 * 3600, 6 * 3600)[min(failures - 1, 3)]
                res["availability_failures"] = failures
                res["next_probe_at"] = time.time() + backoff
            updated_nodes_map[nid] = res
            completed_count += 1
            should_flush = (
                (on_result is not None and res.get("probe_status") == "available")
                or completed_count % flush_step == 0
                or completed_count == len(to_test)
            )
            if should_flush:
                with lock:
                    current_nodes = read_nodes()
                    for current in current_nodes:
                        current_id = current.get("id")
                        if current_id in updated_nodes_map:
                            current.update(updated_nodes_map[current_id])
                    write_json(NODES_FILE, sort_all_nodes(current_nodes))
            if on_result:
                try:
                    on_result(res)
                except Exception as callback_exc:
                    print(f"[test_multiple_nodes] 结果回调失败: {callback_exc}", flush=True)
            if progress_label and (
                completed_count % progress_step == 0 or completed_count == len(to_test)
            ):
                set_state(
                    last_check_message=(
                        f"正在检测{progress_label}：已完成 {completed_count}/{len(to_test)}，"
                        f"当前可用 {available_so_far} 个"
                    )
                )

    # 批量查询并丰富可用节点的地理及 ISP 信息，防止并发时被定位 API 接口限流
    successful_nodes = [res for res in updated_nodes_map.values() if res.get("probe_status") == "available"]
    if successful_nodes:
        try:
            vpn_utils.enrich_ip_info(successful_nodes)
        except Exception as ee:
            print(f"[test_multiple_nodes] 批量富化 IP 失败: {ee}", flush=True)

    with lock:
        current_nodes = read_nodes()
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map:
                n.update(updated_nodes_map[nid])
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)

    return list(updated_nodes_map.values())

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        return

    ui_cfg = load_ui_config()
    connection_enabled = ui_cfg.get("connection_enabled", True)
    if not connection_enabled:
        print("[自动切换] 连接已禁用，不进行自动切换。", flush=True)
        return

    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_ip":
        print("[自动切换] 当前处于固定 IP 模式，不进行自动连接或切换。", flush=True)
        return

    # Find the next best available node
    with lock:
        nodes = read_nodes()
        candidates = [
            n for n in nodes
            if n.get("probe_status") == "available"
            and not n.get("active")
        ]
        candidates = apply_routing_filters(candidates, ui_cfg)

        candidates.sort(
            key=lambda n: (
                ip_type_priority(n),
                parse_int(n.get("latency_ms")) or 999999,
                -parse_int(n.get("score")),
            )
        )

    if candidates:
        next_node = candidates[0]
        msg = f"当前连接已失效或代理连通性检测失败，正在自动切换至最佳备用节点: {next_node['id']}"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        try:
            connect_node(next_node["id"])
        except Exception as e:
            err_msg = f"切换到备用节点 {next_node['id']} 失败: {e}，将尝试下一个..."
            print(f"[自动切换] {err_msg}", flush=True)
            log_to_json("WARNING", "VPN", err_msg)
            with lock:
                failed_nodes = read_nodes()
                for failed_node in failed_nodes:
                    if failed_node.get("id") == next_node.get("id"):
                        failed_node["active"] = False
                        failed_node["probe_status"] = "unavailable"
                        failed_node["probe_message"] = f"自动连接失败: {e}"
                        failed_node["probed_at"] = time.time()
                        break
                write_json(NODES_FILE, sort_all_nodes(failed_nodes))
            auto_switch_node(attempt + 1)
    else:
        msg = "没有可用的备选节点，将自动断开并清理当前连接状态，同时在后台异步获取新节点..."
        if routing_mode == "fixed_region" and target_country:
            msg = f"没有可用的【{target_country}】备选节点，已断开连接，将在后台持续尝试获取新节点..."
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", last_check_message=msg)

        def bg_fetch_and_switch():
            try:
                # 避免所有节点不可用时连续拉取/测试导致 CPU 与 tun 网卡风暴。
                time.sleep(60)
                maintain_valid_nodes(force=False)
                auto_switch_node(attempt + 1)
            except Exception as e:
                print(f"[自动切换后台补齐] 获取并测试节点失败: {e}", flush=True)

        threading.Thread(target=bg_fetch_and_switch, daemon=True).start()

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("Node id is required")
    stopped_existing = False
    with lock:
        if is_connecting:
            print("[连接] 正在建立其他连接中，跳过此请求", flush=True)
            raise RuntimeError("当前已有连接或节点检测任务正在运行，请稍后再试")
        is_connecting = True
        set_state(is_connecting=True, active_node_latency="正在连接", last_check_message=f"正在初始化连接配置: {node_id}")

    try:
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")

        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")

        ui_cfg = load_ui_config()
        validate_node_allowed_by_routing(node, ui_cfg)
        ui_cfg["connection_enabled"] = True
        if ui_cfg.get("routing_mode") == "fixed_ip":
            ui_cfg["fixed_node_id"] = node_id
        auth_file = DATA_DIR / "ui_auth.json"
        with lock:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            write_json(auth_file, ui_cfg)

        set_state(active_node_latency="清理连接", last_check_message="正在关闭与清理旧的 VPN 连接及网卡...")
        stop_active_openvpn()
        stopped_existing = True

        set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_text = node_config_text(node)
            if not config_text:
                raise RuntimeError("OpenVPN configuration is missing")
            config_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...")
        ok, message, process = run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True)
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            print(f"[连接核心失败] 无法与 VPN 节点 {node_id} 建立隧道连接！详情: {message}", flush=True)
            set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", last_check_message=f"连接失败: {message}")
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)

        with lock:
            active_openvpn_process = process
            active_openvpn_node_id = node_id

        set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        setup_policy_routing("tun0")

        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time()
        last_active_latency = 0

        set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass

        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                _ph = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
                item["probe_message"] = f"Active node. HTTP proxy: http://{_ph}:{LOCAL_PROXY_PORT}"
        write_json(NODES_FILE, nodes)

        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if res["ok"]:
            exit_metadata = inspect_exit_ip(res["ip"])
            apply_exit_metadata_to_node(node, exit_metadata)
            for item in nodes:
                if item.get("id") == node_id:
                    apply_exit_metadata_to_node(item, exit_metadata)
            write_json(NODES_FILE, nodes)
            set_state(
                proxy_ok=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                proxy_error="",
                exit_country=exit_metadata.get("exit_country", ""),
                exit_country_short=exit_metadata.get("exit_country_short", ""),
                exit_location=exit_metadata.get("exit_location", ""),
                exit_ip_type=exit_metadata.get("exit_ip_type", ""),
            )
            try:
                validate_exit_allowed_by_routing(node, ui_cfg)
            except Exception as exit_exc:
                mismatch_message = str(exit_exc)
                node["probe_status"] = "unavailable"
                node["probe_message"] = mismatch_message
                node["active"] = False
                for item in nodes:
                    if item.get("id") == node_id:
                        item.update(node)
                    item["active"] = False
                write_json(NODES_FILE, nodes)
                mark_blacklisted(node, mismatch_message)
                log_to_json("WARNING", "ExitValidation", f"节点 {node_id} 被拒绝: {mismatch_message}")
                raise RuntimeError(mismatch_message)
        else:
            set_state(
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
                proxy_error=res.get("error", "未知错误")
            )
            if ui_cfg.get("routing_mode") == "fixed_region" or ui_cfg.get("routing_ip_type", "all") != "all":
                raise RuntimeError(f"无法检测真实出口，不能确认锁定规则: {res.get('error', '出口测试失败')}")

        latency_str = f"{last_active_latency} ms" if last_active_latency > 0 else "检测超时"
        set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message=f"Connected {node_id}", active_node_latency=latency_str)
        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        return f"Connected {node_id}"
    except Exception as exc:
        if stopped_existing or (active_openvpn_node_id == node_id and not active_openvpn_running()):
            clear_active_connection_state(f"连接失败: {exc}")
        else:
            set_state(is_connecting=False, last_check_message=f"连接失败: {exc}")
        raise
    finally:
        with lock:
            is_connecting = False

RECOVERY_COUNTRY_NAMES = {
    "US": "美国", "JP": "日本", "KR": "韩国", "RU": "俄罗斯", "VN": "越南",
    "TH": "泰国", "TW": "台湾", "HK": "香港", "SG": "新加坡", "MY": "马来西亚",
    "ID": "印度尼西亚", "IN": "印度", "PH": "菲律宾", "AU": "澳大利亚", "NZ": "新西兰",
    "CA": "加拿大", "UA": "乌克兰", "GB": "英国", "FR": "法国", "DE": "德国",
    "NL": "荷兰", "SE": "瑞典", "NO": "挪威", "ES": "西班牙", "TR": "土耳其",
    "BR": "巴西", "AR": "阿根廷", "CL": "智利", "MX": "墨西哥", "RO": "罗马尼亚",
    "PL": "波兰", "KZ": "哈萨克斯坦", "GE": "格鲁吉亚", "MN": "蒙古", "IT": "意大利",
    "CH": "瑞士", "BE": "比利时", "AT": "奥地利", "DK": "丹麦", "FI": "芬兰",
    "PT": "葡萄牙", "GR": "希腊", "CZ": "捷克", "HU": "匈牙利", "IE": "爱尔兰",
    "ZA": "南非", "EG": "埃及", "CO": "哥伦比亚", "KH": "柬埔寨", "IL": "以色列",
}


def recover_nodes_from_config_cache(seen_ids: set[str], blacklist: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    """Rebuild pending candidates from previously downloaded official OVPN files."""
    if limit <= 0 or not CONFIG_DIR.exists():
        return []
    try:
        cache = vpn_utils.load_ip_cache()
    except Exception:
        cache = {}
    try:
        paths = sorted(CONFIG_DIR.glob("*.ovpn"), key=lambda path: path.stat().st_mtime, reverse=True)
    except OSError:
        return []
    recovered: list[dict[str, Any]] = []
    now = time.time()
    for path in paths:
        if len(recovered) >= limit:
            break
        node_id = path.stem
        if node_id in seen_ids or node_id in blacklist:
            continue
        match = re.match(r"^([A-Za-z]{2})_([0-9A-Fa-f:.]+)_([0-9]+)_(tcp|udp)$", node_id)
        if not match:
            continue
        country_short, file_ip, file_port, file_proto = match.groups()
        try:
            config_text = path.read_text(encoding="utf-8", errors="replace")
            remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, file_ip)
        except OSError:
            continue
        ip = file_ip or remote_host
        cached = dict(cache.get(ip) or {})
        country_long = str(cached.get("geo_country") or "").strip()
        country = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, country_long) or RECOVERY_COUNTRY_NAMES.get(country_short.upper(), country_short.upper())
        recovered.append({
            "id": node_id, "country": country, "country_short": country_short.upper(),
            "host_name": "", "ip": ip, "score": 0, "ping": 0, "speed": 0, "sessions": 0,
            "owner": cached.get("owner", ""), "asn": cached.get("asn", ""),
            "as_name": cached.get("as_name", ""), "location": cached.get("location", ""),
            "ip_type": cached.get("ip_type", "unknown"), "quality": cached.get("quality", ""),
            "geo_country": cached.get("geo_country", ""), "geo_country_short": cached.get("geo_country_short", country_short.upper()),
            "classification_source": cached.get("classification_source", "cache-recovery"),
            "risk_score": cached.get("risk_score", 0), "exit_ip": "", "exit_country": "",
            "exit_country_short": "", "exit_location": "", "exit_owner": "", "exit_asn": "",
            "exit_as_name": "", "exit_ip_type": "", "exit_quality": "", "exit_checked_at": 0,
            "latency_ms": 0, "config_file": str(path),
            "proto": proto or file_proto, "remote_host": remote_host or ip,
            "remote_port": remote_port or int(file_port), "fetched_at": now,
            "probe_status": "not_checked", "probe_message": "从近期本地节点缓存恢复，等待可用性检测",
            "probed_at": 0, "recovered_from_cache": True,
        })
        seen_ids.add(node_id)
    return recovered


def enrich_and_store_candidates(candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Resolve provider/type for every candidate before any OpenVPN probing."""
    set_state(last_check_message=f"已获取 {len(candidates)} 个节点，正在批量识别服务商和 IP 类型...")
    vpn_utils.enrich_ip_info(candidates)

    metadata_keys = [
        "owner", "asn", "as_name", "location", "ip_type", "quality",
        "classification_source", "risk_score", "ippure_checked_at",
    ]
    probe_keys = [
        "probe_status", "probe_message", "latency_ms", "probed_at",
        "availability_failures", "next_probe_at", "last_available_at",
    ]
    exit_keys = [
        "exit_ip", "exit_country", "exit_country_short", "exit_location",
        "exit_owner", "exit_asn", "exit_as_name", "exit_ip_type",
        "exit_quality", "exit_classification_source", "exit_risk_score", "exit_checked_at",
    ]

    retained_recent = 0
    recovered_cached = 0
    with lock:
        current_nodes = read_nodes()
        current_by_id = {str(n.get("id")): n for n in current_nodes if n.get("id")}
        active_node = None
        if active_openvpn_node_id:
            active_node = next((n for n in current_nodes if n.get("id") == active_openvpn_node_id), None)

        merged: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        if active_node:
            refreshed_active = next((c for c in candidates if c.get("id") == active_node.get("id")), None)
            if refreshed_active:
                for key in metadata_keys:
                    if refreshed_active.get(key) not in (None, ""):
                        active_node[key] = refreshed_active.get(key)
            merged.append(active_node)
            seen_ids.add(active_node["id"])

        for candidate in candidates:
            if candidate["id"] in seen_ids:
                continue
            previous = current_by_id.get(str(candidate["id"]))
            if previous:
                for key in probe_keys + exit_keys:
                    if previous.get(key) not in (None, ""):
                        candidate[key] = previous.get(key)
                for key in metadata_keys:
                    if candidate.get(key) in (None, "") and previous.get(key) not in (None, ""):
                        candidate[key] = previous.get(key)
            merged.append(candidate)
            seen_ids.add(candidate["id"])

        # A temporary main-site/mirror outage must not collapse a healthy catalog.
        # Keep recently seen nodes; the separate availability check remains the
        # authority for whether they can actually be selected.
        now = time.time()
        blacklist = load_blacklist()
        for previous in current_nodes:
            previous_id = str(previous.get("id") or "")
            if not previous_id or previous_id in seen_ids or previous_id in blacklist:
                continue
            fetched_at = float(previous.get("fetched_at") or 0)
            if fetched_at <= 0 or now - fetched_at > NODE_RETENTION_SECONDS:
                continue
            merged.append(previous)
            seen_ids.add(previous_id)
            retained_recent += 1

        if len(merged) < CACHED_CONFIG_RECOVERY_TARGET:
            recovered = recover_nodes_from_config_cache(
                seen_ids, blacklist, CACHED_CONFIG_RECOVERY_TARGET - len(merged)
            )
            merged.extend(recovered)
            recovered_cached = len(recovered)

        if len(merged) > 1000:
            merged = merged[:1000]

        for node in merged:
            config_path = Path(node["config_file"])
            inline_config = str(node.pop("config_text", "") or "")
            if inline_config:
                try:
                    config_path.write_text(inline_config, encoding="utf-8")
                except Exception:
                    pass

        write_json(NODES_FILE, sort_all_nodes(merged))

    missing_metadata = sum(
        1 for node in merged
        if not (node.get("owner") or node.get("as_name")) or not node.get("ip_type")
    )
    classified = len(merged) - missing_metadata
    set_state(
        node_metadata_total=len(merged),
        node_metadata_ready=classified,
        node_metadata_missing=missing_metadata,
        last_check_message=f"节点资料更新完成：{classified}/{len(merged)} 个已识别服务商和 IP 类型；保留近期节点 {retained_recent} 个，本地缓存恢复 {recovered_cached} 个",
    )
    return merged, missing_metadata

def refresh_node_catalog_only(force: bool = False) -> str:
    """Refresh addresses and metadata without running OpenVPN availability probes."""
    global is_connecting
    ensure_dirs()
    if force:
        resume_metadata_refresh()
    elif metadata_refresh_paused() or metadata_cancel_event.is_set():
        message = "节点资料自动拉取已暂停；点击“更新节点资料”可恢复并手动更新。"
        set_state(metadata_refresh_paused=True, refresh_cancel_requested=False, last_check_message=message)
        return message
    if not maintenance_lock.acquire(blocking=False):
        return "节点任务正在运行，请稍后再试"
    with lock:
        if is_connecting:
            maintenance_lock.release()
            return "当前已有连接或检测任务正在运行，请稍后再试"
        is_connecting = True
    try:
        reset_stale_testing_nodes("等待单独执行可用性检测")
        set_state(maintenance_task="metadata", is_connecting=True, last_check_message="正在并发拉取主站和官方镜像节点...")
        fetch_error = ""
        try:
            candidates = fetch_candidates(aggregate_all_sources=True)
        except CatalogRefreshCancelled:
            message = "节点资料拉取已停止；现有节点清单和国家出口保持不变。"
            set_state(
                metadata_refresh_paused=True,
                refresh_cancel_requested=False,
                last_check_message=message,
            )
            return message
        except Exception as exc:
            fetch_error = str(exc)
            if not read_nodes() and not any(CONFIG_DIR.glob("*.ovpn")):
                raise
            candidates = []
            print(f"[节点资料] 官方来源暂不可用，改用近期目录和本地配置缓存: {exc}", flush=True)
        if metadata_cancel_event.is_set():
            message = "节点资料拉取已停止；现有节点清单和国家出口保持不变。"
            set_state(metadata_refresh_paused=True, refresh_cancel_requested=False, last_check_message=message)
            return message
        merged, missing = enrich_and_store_candidates(candidates)
        if metadata_cancel_event.is_set():
            message = "节点资料拉取已停止；已完成的资料已保留，后续自动拉取保持暂停。"
            set_state(metadata_refresh_paused=True, refresh_cancel_requested=False, last_check_message=message)
            return message
        cleanup_stale_config_cache()
        source_note = "；官方来源本轮不可用，已使用近期/本地缓存" if fetch_error else ""
        message = f"节点资料更新完成：共 {len(merged)} 个，服务商和 IP 类型待补充 {missing} 个；尚未执行可用性检测{source_note}"
        set_state(last_fetch_at=time.time(), last_check_at=time.time(), last_check_message=message)
        log_to_json("INFO", "Metadata", message)
        return message
    finally:
        set_state(maintenance_task="")
        is_connecting = False
        maintenance_lock.release()

def test_node_availability_only(
    node_ids: list[str] | None = None,
    trigger_legacy_auto: bool = True,
    task_label: str = "",
    channel_id: str = "",
) -> str:
    """Probe availability for the exact node list selected by the UI."""
    global is_connecting
    ensure_dirs()
    if not maintenance_lock.acquire(blocking=False):
        message = "节点任务正在运行，请稍后再试"
        if channel_id:
            set_state(
                maintenance_task="", maintenance_channel_id="",
                last_completed_channel_id=channel_id,
                last_completed_channel_message=message,
                last_check_message=message,
            )
        return message
    with lock:
        if is_connecting:
            maintenance_lock.release()
            message = "当前已有连接或检测任务正在运行，请稍后再试"
            if channel_id:
                set_state(
                    maintenance_task="", maintenance_channel_id="",
                    last_completed_channel_id=channel_id,
                    last_completed_channel_message=message,
                    last_check_message=message,
                )
            return message
        is_connecting = True
    should_auto_connect = False
    try:
        reset_stale_testing_nodes("等待重新检测可用性")
        with lock:
            nodes = read_nodes()
            known_ids = {str(n.get("id") or "") for n in nodes}
            requested_ids = list(dict.fromkeys(str(node_id or "").strip() for node_id in (node_ids or [])))
            requested_ids = [node_id for node_id in requested_ids if node_id and node_id in known_ids]
            active_ids = {str(n.get("id") or "") for n in nodes if n.get("active")}
            runtime_channels = read_json(MULTI_EXIT_DIR / "state.json", {"channels": {}}).get("channels", {})
            active_ids.update(
                str(item.get("node_id") or "")
                for item in runtime_channels.values()
                if str(item.get("status") or "") in {"connected", "connecting", "switching"}
            )

        channel_was_awaiting = False
        release_node_id = ""
        if channel_id:
            try:
                _, current_channel = find_multi_channel(read_multi_exit_config(), channel_id)
                channel_was_awaiting = bool(current_channel.get("awaiting_initial_test"))
            except ValueError:
                channel_was_awaiting = False
        if channel_was_awaiting:
            cached_available = next((
                node for node in nodes
                if str(node.get("id") or "") in requested_ids
                and node.get("probe_status") == "available"
            ), None)
            if cached_available:
                release_node_id = str(cached_available.get("id") or "")
                active_ids.add(release_node_id)
                mark_channel_ready(channel_id, release_node_id)

        test_ids = [node_id for node_id in requested_ids if node_id not in active_ids]
        channel_released = bool(release_node_id) or not channel_was_awaiting

        def release_on_first_available(result: dict[str, Any]) -> None:
            nonlocal channel_released
            if channel_id and not channel_released and result.get("probe_status") == "available":
                mark_channel_ready(channel_id, str(result.get("id") or ""))
                channel_released = True

        set_state(
            maintenance_task="channel_availability" if task_label else "availability",
            maintenance_channel_id=channel_id,
            is_connecting=True,
            last_check_message=f"正在检测{task_label or '当前筛选结果'}：共 {len(requested_ids)} 个节点，实际测试 {len(test_ids)} 个...",
        )
        tested_nodes = test_multiple_nodes(
            test_ids,
            progress_label=task_label,
            on_result=release_on_first_available if channel_was_awaiting else None,
        )
        available_count = sum(1 for n in tested_nodes if n.get("probe_status") == "available") + len(active_ids.intersection(requested_ids))
        message = f"可用性检测完成：筛选结果 {len(requested_ids)} 个，实际测试 {len(test_ids)} 个，可用 {available_count} 个"
        channel_test_results = read_json(STATE_FILE, {}).get("channel_test_results") or {}
        if channel_id:
            channel_test_results[channel_id] = {
                "message": message,
                "completed_at": time.time(),
            }
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            last_completed_channel_id=channel_id,
            last_completed_channel_message=message if channel_id else "",
            channel_test_results=channel_test_results,
        )
        log_to_json("INFO", "Availability", message)
        ui_cfg = load_ui_config()
        should_auto_connect = (
            available_count > 0
            and trigger_legacy_auto
            and ui_cfg.get("connection_enabled", True)
            and ui_cfg.get("routing_mode", "auto") != "fixed_ip"
            and not active_openvpn_running()
        )
        return message
    finally:
        reset_stale_testing_nodes("可用性检测已结束")
        set_state(maintenance_task="", maintenance_channel_id="")
        is_connecting = False
        maintenance_lock.release()
        if should_auto_connect:
            set_state(last_check_message="检测到符合规则的可用节点，正在自动连接...")
            threading.Thread(target=auto_switch_node, daemon=True).start()

def maintain_valid_nodes(force: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    ensure_dirs()
    if not maintenance_lock.acquire(blocking=False):
        msg = "节点维护任务正在运行，请稍后再试"
        set_state(last_check_message=msg)
        return msg
    with lock:
        if is_connecting:
            maintenance_lock.release()
            msg = "当前已有连接或节点测试任务正在运行，请稍后再试"
            set_state(last_check_message=msg)
            return msg
        is_connecting = True
    try:
        set_state(maintenance_task="full")
        reset_count = reset_stale_testing_nodes("上次检测已中断，等待重新检测")
        if reset_count:
            print(f"[节点状态] 已复位 {reset_count} 个遗留的检测中状态", flush=True)
            log_to_json("INFO", "Main", f"已复位 {reset_count} 个遗留的检测中状态")

        if force:
            with lock:
                stop_active_openvpn()
            reconnect_fixed_node_if_needed(load_ui_config())
        elif not active_openvpn_running():
            ui_cfg = load_ui_config()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            connection_enabled = ui_cfg.get("connection_enabled", True)
            if connection_enabled:
                if routing_mode == "fixed_ip":
                    reconnect_fixed_node_if_needed(ui_cfg)
                else:
                    has_active_id = False
                    with lock:
                        if active_openvpn_node_id:
                            has_active_id = True
                            stop_active_openvpn()
                    if has_active_id:
                        print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                        is_connecting = False
                        auto_switch_node()
                        is_connecting = True

        try:
            set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates(aggregate_all_sources=True)
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            diag_msg = str(exc)
            if not any(token in diag_msg for token in ["[ERR_", "错误代码"]):
                err_code, raw_diag = vpn_utils.diagnose_api_failure(API_URL)
                diag_msg = f"[错误代码 {err_code}] 获取节点失败: {exc} | 诊断结果: {raw_diag}"
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=diag_msg)
            candidates = []

        if not candidates:
            return "没有拉取到新节点"

        enrich_and_store_candidates(candidates)

        initial_tested_ids: set[str] = set()
        ui_cfg = load_ui_config()
        should_fast_connect = (
            ui_cfg.get("connection_enabled", True)
            and ui_cfg.get("routing_mode", "auto") != "fixed_ip"
            and not active_openvpn_running()
        )
        if should_fast_connect:
            with lock:
                current_nodes = read_nodes()
                fast_candidates = [
                    n for n in current_nodes
                    if not n.get("active") and n.get("probe_status") != "unavailable"
                ]
                fast_candidates = apply_routing_filters(fast_candidates, ui_cfg, include_unknown_ip_type=True)
                fast_candidates.sort(key=probe_priority_key)
                fast_test_ids = [
                    n["id"] for n in fast_candidates
                    if n.get("id")
                ][:INITIAL_CONNECT_TEST_LIMIT]

            if fast_test_ids:
                initial_tested_ids = set(fast_test_ids)
                msg = f"首次快速连接模式：优先测试 {len(fast_test_ids)} 个高优先级节点，发现可用节点后立即连接"
                print(f"[快速首连] {msg}", flush=True)
                log_to_json("INFO", "Main", msg)
                set_state(is_connecting=True, last_check_message=msg)
                test_multiple_nodes(fast_test_ids)

                with lock:
                    fast_nodes = read_nodes()
                    available_candidates = [
                        n for n in fast_nodes
                        if n.get("probe_status") == "available" and not n.get("active")
                    ]
                    available_candidates = apply_routing_filters(available_candidates, ui_cfg)

                if available_candidates:
                    is_connecting = False
                    set_state(is_connecting=False, last_check_message="快速首连已找到可用节点，正在建立连接...")
                    auto_switch_node()
                    if active_openvpn_running():
                        valid_nodes_count = len([n for n in read_nodes() if n.get("probe_status") == "available"])
                        message = f"Fetched {len(candidates)} nodes. Fast-tested {len(fast_test_ids)} nodes and connected."
                        set_state(
                            last_check_at=time.time(),
                            last_check_message=message,
                            active_openvpn_node_id=active_openvpn_node_id,
                            valid_nodes=valid_nodes_count,
                        )
                        return message
                    is_connecting = True

        # Test remaining non-active nodes from the list
        with lock:
            current_nodes = read_nodes()
            to_test = [
                n for n in current_nodes
                if not n.get("active") and n.get("id") not in initial_tested_ids
            ]
            to_test = apply_routing_filters(to_test, ui_cfg, include_unknown_ip_type=True)
            to_test_ids = [n["id"] for n in to_test]

        msg = f"开始对列表中所有候选节点进行周期连通性与延迟测试，待检测节点共 {len(to_test_ids)} 个"
        print(f"[周期检测] {msg}", flush=True)
        log_to_json("INFO", "Main", msg)

        target_country = str(ui_cfg.get("force_country") or "").strip() if ui_cfg.get("routing_mode") == "fixed_region" else ""
        if target_country:
            progress_message = f"正在并发检测【{target_country}】节点；其他国家节点保持待检测"
        else:
            progress_message = "正在并发检测所有候选节点可用性..."
        set_state(is_connecting=True, last_check_message=progress_message)
        test_multiple_nodes(to_test_ids)
        is_connecting = False

        with lock:
            merged = read_nodes()

            # Identify available, unavailable, and active nodes
            available_nodes = [n["id"] for n in merged if n.get("probe_status") == "available"]
            unavailable_nodes = [n["id"] for n in merged if n.get("probe_status") == "unavailable"]
            active_node = next((n["id"] for n in merged if n.get("active")), "无")

            status_report = (
                f"周期节点检测完成。实时同步状态: 获取到候选节点共 {len(merged)} 个。 "
                f"其中【可用节点】{len(available_nodes)} 个: {available_nodes[:15]}...; "
                f"【不可用节点】{len(unavailable_nodes)} 个; "
                f"当前【正在正常运行的活动连接节点】为: {active_node}。"
            )
            print(f"[周期检测] {status_report}", flush=True)
            log_to_json("INFO", "Main", status_report)

            if active_node != "无" and not active_openvpn_running():
                warn_msg = f"[诊断警告] 活动节点 {active_node} 被标记为活动状态，但 OpenVPN 进程实际并未正常运行！"
                print(warn_msg, flush=True)
                log_to_json("WARNING", "Main", warn_msg)

            if not active_openvpn_running():
                ui_cfg = load_ui_config()
                connection_enabled = ui_cfg.get("connection_enabled", True)
                if connection_enabled:
                    routing_mode = ui_cfg.get("routing_mode", "auto")

                    if routing_mode != "fixed_ip":
                        available_candidates = [n for n in merged if n.get("probe_status") == "available"]
                        available_candidates = apply_routing_filters(available_candidates, ui_cfg)

                        if available_candidates:
                            # This block still owns `lock`; run the switch after it is released.
                            threading.Thread(target=auto_switch_node, daemon=True).start()

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
        message = f"Fetched {len(candidates)} nodes. Tested {len(to_test_ids)} non-active nodes."
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            active_openvpn_node_id=active_openvpn_node_id,
            valid_nodes=valid_nodes_count,
        )
        return message
    except Exception as e:
        raise e
    finally:
        reset_stale_testing_nodes("检测任务已结束，等待下次检测")
        set_state(maintenance_task="")
        is_connecting = False
        maintenance_lock.release()


def collector_loop() -> None:
    global last_collector_heartbeat
    if read_nodes():
        # A service restart must not immediately combine mirror aggregation with
        # per-country tunnel recovery on small VPS instances.
        time.sleep(FETCH_INTERVAL_SECONDS)
    while True:
        last_collector_heartbeat = time.time()
        try:
            print("[守护线程] 开始执行节点资料更新；可用性检测由各国家卡片单独触发。", flush=True)
            log_to_json("INFO", "Main", "开始执行全局节点资料更新，不执行可用性检测。")
            res = refresh_node_catalog_only()
            log_to_json("INFO", "Main", f"周期节点资料更新完成: {res}")
        except Exception as exc:
            err_msg = f"周期节点资料更新异常: {exc}"
            print(f"[错误] {err_msg}", flush=True)
            log_to_json("ERROR", "Main", err_msg)
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")

        time.sleep(FETCH_INTERVAL_SECONDS)


def auto_connect_recovery_loop() -> None:
    """Recover an enabled non-fixed connection without waiting for the full refresh cycle."""
    global last_no_connection_refresh_at
    time.sleep(AUTO_CONNECT_RETRY_SECONDS)
    while True:
        try:
            ui_cfg = load_ui_config()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            if (
                ui_cfg.get("connection_enabled", True)
                and routing_mode != "fixed_ip"
                and not active_openvpn_running()
                and not is_connecting
                and not maintenance_lock.locked()
            ):
                with lock:
                    nodes = read_nodes()
                    eligible = apply_routing_filters(
                        [node for node in nodes if not node.get("active")],
                        ui_cfg,
                        include_unknown_ip_type=True,
                    )
                    available = [node for node in eligible if node.get("probe_status") == "available"]
                    retry_nodes = sorted(eligible, key=probe_priority_key)[:INITIAL_CONNECT_TEST_LIMIT]

                if available:
                    set_state(last_check_message="检测到可用节点，正在自动恢复连接...")
                    auto_switch_node()
                else:
                    now = time.time()
                    if now - last_no_connection_refresh_at >= UNAVAILABLE_REFRESH_SECONDS:
                        last_no_connection_refresh_at = now
                        set_state(last_check_message="当前规则内没有可用节点，正在提前刷新 VPNGate 节点列表...")
                        maintain_valid_nodes(force=False)
                    elif retry_nodes:
                        retry_ids = [node.get("id") for node in retry_nodes if node.get("id")]
                        set_state(last_check_message=f"连接未建立，正在重新检测 {len(retry_ids)} 个候选节点...")
                        test_node_availability_only(retry_ids)
        except Exception as exc:
            print(f"[自动恢复] 重试连接失败: {exc}", flush=True)
            log_to_json("WARNING", "Recovery", f"自动恢复连接失败: {exc}")
        time.sleep(AUTO_CONNECT_RETRY_SECONDS)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>节点管理系统 - 安全登录</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-surface: rgba(15, 23, 42, 0.45);
      --border-color: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --danger: #f43f5e;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image:
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%);
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 24px;
      box-sizing: border-box;
    }

    .login-card {
      background: var(--bg-surface);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px 32px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .brand-logo {
      width: 64px;
      height: 64px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px auto;
      color: var(--primary);
      position: relative;
    }

    .brand-logo::after {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 16px;
      border: 1px solid var(--success);
      opacity: 0.5;
      animation: ripple 2s infinite ease-out;
    }

    @keyframes ripple {
      0% { transform: scale(1); opacity: 0.5; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .login-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0 0 8px 0;
      letter-spacing: 0.5px;
    }

    .login-subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 32px 0;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }

    .input-wrapper {
      position: relative;
    }

    .input-field {
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 0 16px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 15px;
      outline: none;
      transition: all 0.2s ease;
    }

    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }

    .error-message {
      color: var(--danger);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      text-align: left;
      margin-left: 4px;
      display: none;
    }

    .login-btn {
      width: 100%;
      height: 48px;
      background: var(--primary-gradient);
      border: none;
      border-radius: 10px;
      color: white;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
    }

    .login-btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .login-btn:active {
      transform: translateY(1px);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="brand-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h2 class="login-title">节点管理系统</h2>
      <p class="login-subtitle">请输入您的管理账号和安全密码以继续</p>

      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">管理账号</label>
          <div class="input-wrapper">
            <input type="text" id="username" name="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">安全密码</label>
          <div class="input-wrapper">
            <input type="password" id="password" name="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>

        <button type="submit" id="submit_btn" class="login-btn">
          <span>登录</span>
        </button>
      </form>
    </div>
  </div>

  <script>
    async function handleLogin(e) {
      e.preventDefault();
      const uname = document.getElementById("username").value.trim();
      const pwd = document.getElementById("password").value.trim();
      const errorText = document.getElementById("error_text");
      const submitBtn = document.getElementById("submit_btn");

      errorText.style.display = "none";
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证...";

      try {
        const response = await fetch("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd })
        });

        const data = await response.json();
        if (response.ok && data.ok) {
          window.location.reload();
        } else {
          errorText.textContent = data.error || "账号或密码不正确，请重新输入";
          errorText.style.display = "block";
          submitBtn.disabled = false;
          submitBtn.querySelector("span").textContent = "登录";
        }
      } catch (err) {
        errorText.textContent = "连接服务器失败，请稍后重试";
        errorText.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "登录";
      }
    }
  </script>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>节点管理系统</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    :root {
      --bg-dark: #0b0f19;
      --bg-surface: rgba(22, 30, 49, 0.6);
      --bg-surface-hover: rgba(30, 41, 67, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-color-hover: rgba(99, 102, 241, 0.35);
      --text-primary: #f3f4f6;
      --text-secondary: #9ca3af;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --success-gradient: linear-gradient(135deg, #34d399 0%, #059669 100%);
      --danger: #f43f5e;
      --danger-gradient: linear-gradient(135deg, #fb7185 0%, #e11d48 100%);
      --warning: #f59e0b;
      --warning-gradient: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
      --active-row-bg: rgba(16, 185, 129, 0.06);
      --active-row-border: rgba(16, 185, 129, 0.25);
    }

    body {
      margin: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image:
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(79, 70, 229, 0.05) 0px, transparent 50%);
      background-attachment: fixed;
      color: var(--text-primary);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 16px 32px;
      background: rgba(11, 15, 25, 0.7);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      flex-direction: column;
    }

    .header-actions {
      position: absolute;
      left: 50%;
      transform: translateX(-50%);
      display: flex;
      gap: 12px;
      align-items: center;
    }

    .header-admin { margin-left: auto; }

    h1 {
      font-size: 20px;
      font-weight: 700;
      margin: 0;
      background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 10px var(--success);
      display: inline-block;
    }

    .btn-group {
      display: flex;
      gap: 12px;
    }

    button, .btn-telegram {
      height: 38px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
      white-space: nowrap;
      text-decoration: none;
      box-sizing: border-box;
    }

    button:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-telegram {
      background: rgba(43, 162, 223, 0.15);
      border: 1px solid rgba(43, 162, 223, 0.3);
      color: #2ba2df;
    }

    .btn-telegram:hover {
      background: rgba(43, 162, 223, 0.25);
      border-color: rgba(43, 162, 223, 0.5);
      color: #2ba2df;
      transform: translateY(-1px);
    }

    .btn-primary {
      background: var(--primary-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .btn-danger {
      background: var(--danger-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(244, 63, 94, 0.2);
    }

    .btn-danger:hover {
      opacity: 0.95;
      box-shadow: 0 6px 16px rgba(244, 63, 94, 0.35);
    }

    button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    main {
      padding: 24px 32px;
      max-width: 1400px;
      margin: 0 auto;
    }

    .active-card {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(79, 70, 229, 0.04) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      padding: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      box-shadow: 0 8px 32px rgba(99, 102, 241, 0.12);
      transition: all 0.3s ease;
      width: 100%;
      box-sizing: border-box;
    }

    .active-card-info {
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: wrap;
    }

    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .active-card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .active-card-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
    }

    .active-card-meta {
      display: flex;
      gap: 16px;
      font-size: 13px;
      color: var(--text-secondary);
      flex-wrap: wrap;
    }

    .active-card-meta span strong {
      color: var(--text-primary);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .stat:hover {
      background: var(--bg-surface-hover);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(99, 102, 241, 0.1);
    }

    .stat-info {
      display: flex;
      flex-direction: column;
    }

    .stat strong {
      font-size: 32px;
      font-weight: 700;
      display: block;
      margin-bottom: 4px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .stat span {
      font-size: 13px;
      color: var(--text-secondary);
      font-weight: 500;
    }

    .stat-icon-wrapper {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.04);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }

    .stat-icon {
      width: 22px;
      height: 22px;
      color: var(--primary);
    }

    .stat:nth-child(2) .stat-icon { color: var(--warning); }
    .stat:nth-child(3) .stat-icon { color: var(--success); }

    /* New style additions */
    .header-badge-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      height: 24px;
      box-sizing: border-box;
    }
    .header-badge-link:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: var(--border-color-hover);
      color: var(--text-primary);
      transform: translateY(-1px);
    }
    .flex-row-container {
      display: flex;
      gap: 20px;
      flex-wrap: wrap;
      margin-bottom: 24px;
    }
    .flex-row-container > * {
      flex: 1;
      min-width: 320px;
      margin-bottom: 0 !important;
    }

    .toolbar {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      align-items: center;
    }

    .toolbar select {
      width: 180px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .toolbar select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: #0f172a;
    }

    .filter-count {
      display: inline-flex;
      align-items: center;
      height: 42px;
      padding: 0 14px;
      border-radius: 10px;
      border: 1px solid rgba(99, 102, 241, 0.35);
      background: rgba(99, 102, 241, 0.12);
      color: #c7d2fe;
      font-size: 13px;
      font-weight: 700;
      white-space: nowrap;
    }

    .toolbar input {
      flex: 1;
      min-width: 250px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      transition: all 0.2s ease;
    }

    .toolbar input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.8);
    }

    .table-wrapper {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }

    .table-container {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      table-layout: fixed;
    }

    th, td {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
    }

    th {
      background: rgba(17, 24, 39, 0.4);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-secondary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    tr {
      transition: background 0.2s ease;
    }

    tr:hover {
      background: rgba(255, 255, 255, 0.015);
    }

    .active-row {
      background: var(--active-row-bg) !important;
      outline: 2px solid var(--success) !important;
      outline-offset: -2px;
      position: relative;
      z-index: 5;
    }

    .active-row td {
      border-bottom: 1px solid var(--active-row-border);
      border-top: 1px solid var(--active-row-border);
    }

    .badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
    }

    .badge-pulse {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      animation: pulse 1.5s infinite;
      display: inline-block;
    }

    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 1; }
      50% { transform: scale(1.6); opacity: 0.4; }
      100% { transform: scale(0.9); opacity: 1; }
    }

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .available {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.2);
    }

    .unavailable {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
      border-color: rgba(244, 63, 94, 0.2);
    }

    .not_checked {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.2);
    }

    .testing {
      background: rgba(59, 130, 246, 0.12);
      color: #93c5fd;
      border-color: rgba(59, 130, 246, 0.24);
    }

    .current-badge {
      background: rgba(99, 102, 241, 0.15);
      color: #818cf8;
      border-color: rgba(99, 102, 241, 0.3);
    }

    .table-actions {
      display: flex;
      gap: 8px;
    }

    .connect-btn {
      background: transparent;
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .connect-btn:hover:not(:disabled) {
      background: var(--primary-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3);
    }

    .connect-btn:disabled {
      opacity: 0.3;
      cursor: not-allowed;
    }

    .test-btn {
      background: transparent;
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .test-btn:hover:not(:disabled) {
      background: var(--success-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3);
    }

    .test-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 13px;
      color: #e2e8f0;
    }

    .latency-val {
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
    }

    .latency-good {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
    }

    .latency-medium {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
    }

    .latency-poor {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
    }

    @media (max-width: 768px) {
      header {
        flex-direction: column;
        align-items: flex-start;
        padding: 16px 20px;
      }
      .header-actions {
        position: static;
        transform: none;
        width: 100%;
        justify-content: center;
        flex-wrap: wrap;
      }
      .header-admin { margin-left: 0; }
      .btn-group {
        width: 100%;
        margin-top: 12px;
      }
      .btn-group button, .btn-group .btn-telegram {
        flex: 1;
      }
      .btn-group .dropdown {
        flex: 1;
        display: flex;
      }
      .btn-group .dropdown button {
        width: 100%;
        flex: 1;
      }
      main {
        padding: 16px 20px;
      }
      .active-card {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
      }
      .active-card button {
        width: 100%;
      }
    }

    /* Admin dropdown styles */
    .dropdown {
      position: relative;
      display: inline-block;
    }
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      margin-top: 6px;
      min-width: 140px;
      background: rgba(22, 30, 49, 0.95);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 1000;
      overflow: hidden;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    .dropdown-content a {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      color: var(--text-primary);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      transition: background 0.2s;
    }
    .dropdown-content a:hover {
      background: rgba(255,255,255,0.08);
    }

    /* Modal styles */
    .modal {
      display: none;
      position: fixed;
      z-index: 10000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      overflow: auto;
      background-color: rgba(9, 13, 22, 0.7);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      align-items: center;
      justify-content: center;
    }
    .modal-content {
      background: rgba(22, 30, 49, 0.9);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      width: 90%;
      max-width: 480px;
      padding: 32px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      position: relative;
      box-sizing: border-box;
      animation: modalFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    @keyframes modalFadeIn {
      from { transform: scale(0.95); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }

    /* Inputs in settings */
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }
    .input-field {
      width: 100%;
      height: 40px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }
    select option {
      background-color: #0f172a;
      color: #f8fafc;
    }

    /* Option Card Styles for Proxy/Routing Settings */
    .option-group {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-top: 6px;
    }

    @media (max-width: 480px) {
      .option-group {
        grid-template-columns: 1fr;
      }
    }

    .option-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 12px 14px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      user-select: none;
      position: relative;
      text-align: left;
    }

    .option-card:hover {
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(99, 102, 241, 0.25);
      transform: translateY(-1px);
    }

    .option-card.active {
      background: rgba(99, 102, 241, 0.08);
      border-color: var(--primary);
      box-shadow: 0 0 12px rgba(99, 102, 241, 0.15);
    }

    .option-card-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: 4px;
    }

    .option-card-desc {
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.3;
    }

    .quick-routing-panel {
      background: rgba(22, 30, 49, 0.88);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 18px 20px;
      margin-bottom: 20px;
      box-shadow: var(--shadow-sm);
    }

    .quick-routing-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 16px;
    }

    .quick-routing-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--text-primary);
      margin-bottom: 4px;
    }

    .quick-routing-summary {
      font-size: 12px;
      color: var(--text-secondary);
      line-height: 1.5;
    }

    .quick-routing-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
    }

    .quick-routing-group-label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-secondary);
      margin-bottom: 8px;
    }

    .quick-routing-buttons {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
    }

    .quick-route-btn {
      min-height: 42px;
      padding: 8px 10px;
      border: 1px solid var(--border-color);
      border-radius: 9px;
      background: rgba(255,255,255,0.025);
      color: var(--text-primary);
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      transition: all 0.2s ease;
    }

    .quick-route-btn:hover:not(:disabled) {
      border-color: rgba(99, 102, 241, 0.55);
      background: rgba(99, 102, 241, 0.08);
      transform: translateY(-1px);
    }

    .quick-route-btn.active {
      border-color: var(--primary);
      background: rgba(99, 102, 241, 0.16);
      color: #c7d2fe;
      box-shadow: 0 0 12px rgba(99, 102, 241, 0.16);
    }

    .quick-route-btn:disabled {
      opacity: 0.55;
      cursor: wait;
    }

    .quick-country-select {
      min-height: 42px;
      width: 100%;
      padding: 8px 30px 8px 10px;
      border: 1px solid var(--border-color);
      border-radius: 9px;
      background-color: rgba(255,255,255,0.025);
      color: var(--text-primary);
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      outline: none;
    }

    .quick-country-select.active {
      border-color: var(--primary);
      background-color: rgba(99, 102, 241, 0.16);
      color: #c7d2fe;
      box-shadow: 0 0 12px rgba(99, 102, 241, 0.16);
    }

    .quick-country-select:disabled {
      opacity: 0.55;
      cursor: wait;
    }

    .quick-routing-message {
      margin-top: 12px;
      min-height: 18px;
      font-size: 12px;
      color: var(--text-secondary);
    }

    @media (max-width: 760px) {
      .quick-routing-header,
      .quick-routing-grid {
        grid-template-columns: 1fr;
      }
      .quick-routing-header {
        flex-direction: column;
      }
    }
  </style>
</head>
<body>
<header>
  <div class="brand">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" style="width:24px; height:24px; color:#818cf8;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
      节点管理系统
    </h1>
    <div id="status" class="status" style="display: none;"><span class="status-dot"></span>服务加载中...</div>
  </div>
  <div class="btn-group header-actions">
    <button id="refresh" class="btn-primary" style="background: var(--success-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      更新节点资料
    </button>
    <button id="stop_refresh" class="btn-primary" style="background:rgba(239,68,68,.16);border:1px solid rgba(239,68,68,.55);color:#fecaca;">
      停止拉取节点
    </button>
    <button id="test_availability" class="btn-primary" style="display:none;background: rgba(99, 102, 241, 0.16); border: 1px solid rgba(99, 102, 241, 0.45); color: #c7d2fe;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      检测节点可用性
    </button>
  </div>
  <div class="btn-group header-admin">
    <div class="dropdown">
      <button id="admin_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
        管理员
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openCredentialsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </a>
        <a href="javascript:void(0)" onclick="openNetworkModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </a>
        <a href="javascript:void(0)" onclick="openGatewayModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置
        </a>
        <a href="javascript:void(0)" onclick="openLogsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          日志
        </a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" style="color: var(--danger); border-top: 1px solid rgba(255,255,255,0.05);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
          退出
        </a>
      </div>
    </div>
  </div>
</header>
<main>

    <!-- 当前连接活动节点卡片 -->
    <section class="active-node-section" id="active_node_card" style="display:none;margin-bottom: 24px;">
      <!-- Rendered dynamically by render() -->
    </section>

  <style>
    #multi_exit_panel {background:transparent;border:0;padding:0;box-shadow:none}
    #multi_exit_panel .quick-routing-header {padding:20px 0;border-bottom:1px solid var(--border-color)}
    #multi_exit_panel .quick-routing-title {font-size:24px;letter-spacing:-.5px}
    #direct_node_row>div {border-left:4px solid #60a5fa!important;background:rgba(59,130,246,.10)!important;border-radius:16px!important;padding:20px!important}
    #bundle_subscription_row>div {border-left:4px solid #a78bfa!important;background:rgba(139,92,246,.10)!important;border-radius:16px!important;padding:20px!important}
    #multi_exit_rows {gap:20px!important}
    .country-card {--channel-color:#fbbf24;border:1px solid var(--border-color);border-top:4px solid var(--channel-color);border-radius:16px;padding:22px;background:rgba(148,163,184,.04)}
    .country-card[data-health=connected] {--channel-color:#34d399;background:rgba(16,185,129,.045)}
    .country-card[data-health=failed] {--channel-color:#fb7185;background:rgba(244,63,94,.045)}
    .channel-facts {display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:18px 0}
    .channel-facts>div {background:rgba(148,163,184,.08);border:1px solid var(--border-color);padding:14px;border-radius:10px;font-size:13px;line-height:1.8}
    .channel-facts small,.channel-fields label {display:block;color:var(--text-secondary);font-size:12px}
    .channel-facts strong {display:block;font-size:18px;font-variant-numeric:tabular-nums;color:var(--text-primary)}
    .channel-fields {display:grid;grid-template-columns:1.2fr 110px 110px 1.2fr;gap:12px;margin:16px 0}
    .channel-fields .input-field {width:100%;margin-top:6px}
    .country-card details {margin-top:18px!important;background:rgba(148,163,184,.025)}
    .country-card details summary {padding:15px!important}
    .country-card .toolbar-btn {min-height:38px;border-radius:8px}
    .country-card button[onclick^="saveMultiExitChannel"] {background:#2563eb;color:white;border-color:#2563eb}
    .channel-state-note {font-size:12px;color:var(--text-secondary);margin:12px 0;line-height:1.7}
    .channel-overview {display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}
    .channel-overview span {padding:8px 14px;border-radius:9px;background:rgba(148,163,184,.1);font-size:13px}
    @media(max-width:760px){
      #direct_node_row>div {grid-template-columns:1fr 1fr!important}
      #bundle_subscription_row>div {flex-direction:column;align-items:flex-start!important}
      .channel-fields {grid-template-columns:1fr 1fr}
      .channel-facts {grid-template-columns:1fr}
      .country-card {padding:15px}
      .country-card details>div {min-width:0}
      .country-card details label {min-width:620px}
    }
  </style>
  <section class="quick-routing-panel" id="multi_exit_panel" style="margin-bottom:18px;">
    <div class="quick-routing-header">
      <div><div class="quick-routing-title">多国家独立出口</div><div class="quick-routing-summary">每个国家独立配置、检测和切换 IP；健康线路保持当前连接</div></div>
      <button type="button" class="toolbar-btn" onclick="addMultiExitRow()">添加通道</button>
    </div>
    <div id="direct_node_row" style="margin-top:14px;"></div>
    <div id="bundle_subscription_row" style="margin-top:10px;"></div>
    <div id="channel_overview" class="channel-overview"></div>
    <div style="font-size:17px;font-weight:700;margin-top:24px;">国家出口 <span style="font-size:12px;font-weight:400;color:var(--text-secondary)">绿色：已连接 · 黄色：检测 / 连接 · 红色：恢复中</span></div>
    <div id="multi_exit_rows" style="display:grid;gap:10px;margin-top:10px;"></div>
    <div id="multi_exit_message" class="quick-routing-message" style="margin-top:12px;">顶部更新按钮只更新节点资料；检测与切换请在对应国家卡片中操作。</div>
  </section>

  <section class="quick-routing-panel" id="quick_routing_panel" style="display:none;">
    <div class="quick-routing-header">
      <div>
        <div class="quick-routing-title">出站策略快捷设置</div>
        <div class="quick-routing-summary" id="quick_routing_summary">正在读取当前策略...</div>
      </div>
      <span class="badge available" id="quick_routing_badge">自动更新：约 21 分钟</span>
    </div>
    <div class="quick-routing-grid">
      <div>
        <span class="quick-routing-group-label">国家策略（自动或固定）</span>
        <div class="quick-routing-buttons">
          <button type="button" class="quick-route-btn" data-quick-country="auto" onclick="applyQuickCountry('auto')">自动选择</button>
          <button type="button" class="quick-route-btn" data-quick-country="美国" onclick="applyQuickCountry('美国')">🇺🇸 固定美国</button>
          <select id="quick_country_select" class="quick-country-select" onchange="applyQuickCountrySelect(this.value)">
            <option value="">选择其他国家...</option>
          </select>
        </div>
      </div>
      <div>
        <span class="quick-routing-group-label">固定 IP 类型</span>
        <div class="quick-routing-buttons">
          <button type="button" class="quick-route-btn" data-quick-ip-type="all" onclick="applyQuickIpType('all')">全部 IP</button>
          <button type="button" class="quick-route-btn" data-quick-ip-type="residential" onclick="applyQuickIpType('residential')">住宅 IP</button>
          <button type="button" class="quick-route-btn" data-quick-ip-type="hosting" onclick="applyQuickIpType('hosting')">机房 IP</button>
        </div>
      </div>
    </div>
    <div class="quick-routing-message" id="quick_routing_message">选择后会保存策略，并在后台重新获取和测试符合条件的节点。</div>
  </section>



  <section class="toolbar">
    <select id="status_filter">
      <option value="all">全部节点</option>
      <option value="not_checked">待检测</option>
      <option value="available">可用节点</option>
      <option value="testing">检测中</option>
      <option value="unavailable">失效节点</option>
    </select>
    <select id="country_filter">
      <option value="">所有国家</option>
    </select>
    <select id="ip_type_filter">
      <option value="">所有IP类型</option>
      <option value="residential">住宅IP</option>
      <option value="hosting">机房IP</option>
    </select>
    <span id="filter_result_count" class="filter-count">当前筛选：0 个节点</span>
    <button id="btn_favorites" class="toolbar-btn" type="button" onclick="toggleFavoritesView()" style="margin-left: auto; height: 42px; gap: 6px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.907c.961 0 1.371 1.24.588 1.81l-3.97 2.883a1 1 0 00-.364 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.971-2.883a1 1 0 00-1.175 0l-3.97 2.883c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.364-1.118l-3.97-2.883c-.783-.57-.372-1.81.588-1.81h4.906a1 1 0 00.951-.69l1.519-4.674z" />
      </svg>
      收藏菜单
    </button>
  </section>
  <div id="favorites_panel" style="display: none; background: rgba(22, 30, 49, 0.85); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); border: 1px solid var(--border-color); border-radius: 16px; padding: 20px; margin-bottom: 20px; animation: modalFadeIn 0.25s ease-out;">
    <div style="display: flex; flex-direction: column; gap: 16px;">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
        <div style="display: flex; flex-direction: column; gap: 4px;">
          <span style="font-size: 15px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 6px;">
            ⭐ 收藏专属管理面板
          </span>
          <span style="font-size: 13px; color: var(--text-secondary);">
            在这里管理您的收藏节点过滤，以及设置出站连接漂移策略。
          </span>
        </div>
        <div style="display: flex; gap: 12px; align-items: center;">
          <button id="btn_toggle_fav_routing" type="button" class="toolbar-btn" style="height: 36px; padding: 0 14px; font-size: 13px; border-radius: 6px;" onclick="toggleFavRouting()">
            启用仅用收藏出站
          </button>
        </div>
      </div>

      <div style="border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px;">
        <div style="padding: 10px 14px; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 8px; font-size: 12px; color: var(--warning); line-height: 1.5;">
          <strong>仅用收藏是强锁定模式。</strong>开启后只会连接收藏节点；如果收藏节点全部不可用，系统不会切换到非收藏节点。
        </div>
      </div>
    </div>
  </div>

  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 90px;">状态</th>
            <th style="width: 220px;">IP 地址 : 端口</th>
            <th>物理位置</th>
            <th>运营主体 / ISP</th>
            <th style="width: 110px;">IP 类型</th>
            <th style="width: 180px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>

    <!-- 分页控制栏 -->
    <div class="pagination-container" style="padding: 16px; display: none; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条备选节点
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div>

  <!-- Add country exit modal -->
  <div id="add_channel_modal" class="modal" onclick="if(event.target===this)closeAddChannelModal()">
    <div class="modal-content" style="max-width:520px;width:92%;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
        <div><h3 style="margin:0;font-size:18px;">添加国家独立出口</h3><div style="font-size:12px;color:var(--text-secondary);margin-top:5px;">从节点清单中的全部候选国家创建新出口</div></div>
        <button type="button" onclick="closeAddChannelModal()" style="background:transparent;border:none;color:var(--text-secondary);font-size:24px;cursor:pointer;">×</button>
      </div>
      <div style="display:grid;gap:14px;">
        <label style="display:grid;gap:6px;font-size:13px;"><span>节点清单国家（全部候选国家）</span><select id="new_channel_country" class="input-field" onchange="updateAddChannelCountryHint()"></select><small id="new_channel_country_hint" style="color:var(--text-secondary);"></small></label>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
          <label style="display:grid;gap:6px;font-size:13px;"><span>节点协议</span><select id="new_channel_protocol" class="input-field"><option value="hysteria">HY2</option><option value="vless">VLESS</option><option value="trojan">Trojan</option></select></label>
          <label style="display:grid;gap:6px;font-size:13px;"><span>入站端口（可修改）</span><input id="new_channel_port" type="number" min="1024" max="65535" class="input-field"></label>
        </div>
        <label style="display:grid;gap:6px;font-size:13px;"><span>出口 IP 策略</span><select id="new_channel_ip_type" class="input-field"><option value="all">全部 IP</option><option value="residential_preferred" selected>住宅优先</option><option value="residential_only">仅住宅</option><option value="hosting_only">仅机房</option></select></label>
        <div id="new_channel_error" style="display:none;color:var(--danger);font-size:13px;padding:9px 11px;background:rgba(239,68,68,.1);border-radius:7px;"></div>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:22px;">
        <button type="button" class="toolbar-btn" onclick="closeAddChannelModal()">取消</button>
        <button id="new_channel_create" type="button" class="toolbar-btn" onclick="createMultiExitChannel()">创建国家出口</button>
      </div>
    </div>
  </div>

  <!-- Credentials Modal (网页安全设置) -->
  <div id="credentials_modal" class="modal">
    <div class="modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </h3>
        <button type="button" onclick="closeCredentialsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <div id="credentials_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="credentials_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="credentials_form" onsubmit="saveCredentials(event)">
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_username">管理账号</label>
          <input type="text" id="cred_username" class="input-field" required placeholder="请输入管理账号">
        </div>

        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_password">安全密码</label>
          <input type="password" id="cred_password" class="input-field" placeholder="留空则保留当前密码">
        </div>

        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_port">网页管理端口</label>
          <input type="number" id="cred_port" class="input-field" required min="1" max="65535" placeholder="8787">
        </div>

        <div class="form-group" style="margin-bottom: 20px;">
          <label class="form-label" for="cred_suffix">登录安全后缀 (仅字母和数字)</label>
          <input type="text" id="cred_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeCredentialsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="credentials_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Network Modal (代理及网络设置，包括出站路由) -->
  <div id="network_modal" class="modal">
    <div class="modal-content" style="max-width: 480px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </h3>
        <button type="button" onclick="closeNetworkModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <div id="network_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="network_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="network_form" onsubmit="saveNetwork(event)">
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="net_proxy_port">HTTP/SOCKS5 代理出站端口</label>
          <input type="number" id="net_proxy_port" class="input-field" required min="1024" max="65535" placeholder="7928">
        </div>

        <div style="border-top: 1px dashed rgba(255,255,255,0.08); padding-top: 16px; margin-bottom: 16px;">
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站路由模式</label>
            <input type="hidden" id="net_routing_mode" value="auto">
            <div class="option-group" id="routing_mode_group">
              <div class="option-card active" data-value="auto" onclick="setRoutingMode('auto')">
                <div class="option-card-title">自动配置</div>
                <div class="option-card-desc">智能切换，最稳定</div>
              </div>
              <div class="option-card" data-value="fixed_ip" onclick="setRoutingMode('fixed_ip')">
                <div class="option-card-title">固定 IP</div>
                <div class="option-card-desc">锁定IP，不自动切换</div>
              </div>
              <div class="option-card" data-value="fixed_region" onclick="setRoutingMode('fixed_region')">
                <div class="option-card-title">固定地区</div>
                <div class="option-card-desc">锁定特定国家地区</div>
              </div>
            </div>
          </div>

          <div id="net_force_country_group" class="form-group" style="margin-bottom: 16px; display: none;">
            <label class="form-label" for="net_force_country">锁定国家地区</label>
            <select id="net_force_country" class="input-field" style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--border-color); color: var(--text-primary); outline: none; cursor: pointer; width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;">
              <option value="">正在加载节点国家...</option>
            </select>
          </div>

          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站类型过滤</label>
            <input type="hidden" id="net_routing_ip_type" value="all">
            <div class="option-group" id="routing_ip_type_group">
              <div class="option-card active" data-value="all" onclick="setRoutingIpType('all')">
                <div class="option-card-title">所有IP</div>
                <div class="option-card-desc">机房 + 住宅</div>
              </div>
              <div class="option-card" data-value="residential" onclick="setRoutingIpType('residential')">
                <div class="option-card-title">住宅IP</div>
                <div class="option-card-desc">静态家宽</div>
              </div>
              <div class="option-card" data-value="hosting" onclick="setRoutingIpType('hosting')">
                <div class="option-card-title">机房IP</div>
                <div class="option-card-desc">普通机房</div>
              </div>
            </div>
          </div>

          <div id="net_routing_warning" style="font-size: 12px; color: var(--text-secondary); line-height: 1.4; padding: 8px 12px; background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 6px; margin-top: 8px;">
            ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeNetworkModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="network_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Gateway Modal (网关自检与代理测试) -->
  <div id="gateway_modal" class="modal">
    <div class="modal-content" style="max-width: 600px; width: 90%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置与自检
        </h3>
        <button type="button" onclick="closeGatewayModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- 服务列表 -->
      <div id="gateway_services_list" style="display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px;">
        <div style="text-align: center; color: var(--text-secondary); padding: 20px 0;">
          <svg style="animation: spin 1s linear infinite; width: 20px; height: 20px; display: inline-block; margin-bottom: 8px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>
          <div>正在加载系统网关状态...</div>
        </div>
      </div>

      <!-- 分割线 -->
      <div style="border-top: 1px dashed rgba(255, 255, 255, 0.08); margin: 20px 0;"></div>

      <!-- 本地代理出口检测 -->
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 12px; padding: 16px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
          <div class="stat-icon-wrapper" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2); width: 36px; height: 36px; border-radius: 8px; flex-shrink: 0;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary); width: 18px; height: 18px;"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
          </div>
          <div>
            <h4 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-primary);">本地代理出口检测</h4>
            <p style="margin: 2px 0 0 0; font-size: 12px; color: var(--text-secondary);">检测 HTTP/SOCKS5 代理出站连通性与 IP</p>
          </div>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0, 0, 0, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
          <div style="font-size: 13px; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 13px; color: var(--text-secondary); text-align: right;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span>
            <span id="proxy_latency_val" style="margin-left: 6px;"></span>
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="btn_test_proxy" class="btn-primary" style="height: 36px; padding: 0 16px; font-size: 13px;">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            开始检测
          </button>
        </div>
      </div>

      <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
        <button type="button" onclick="closeGatewayModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>

  <!-- Logs Modal (日志监控与分类筛选) -->
  <div id="logs_modal" class="modal">
    <div class="modal-content" style="max-width: 800px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          今日运行日志
        </h3>

        <div style="display: flex; align-items: center; gap: 10px; margin-left: auto;">
          <label class="form-label" for="log_filter_select" style="margin: 0; font-size: 13px; color: var(--text-secondary);">日志筛选:</label>
          <select id="log_filter_select" class="input-field" style="width: 140px; height: 32px; font-size: 12px; border-radius: 6px; padding: 0 8px; background: rgba(255, 255, 255, 0.03);" onchange="filterAndRenderLogs()">
            <option value="all">全部日志</option>
            <option value="proxy">代理相关 (Proxy)</option>
            <option value="vpn">VPN 连接 (VPN)</option>
            <option value="system">系统运行 (Main/Route)</option>
          </select>
        </div>

        <button type="button" onclick="closeLogsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- Terminal Log Container -->
      <div id="log_terminal_container" style="background: #050811; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 10px; height: 400px; padding: 16px; overflow-y: auto; font-family: 'JetBrains Mono', Consolas, Courier, monospace; font-size: 12px; line-height: 1.5; text-align: left; white-space: pre-wrap; word-break: break-all; color: #a5b4fc; box-shadow: inset 0 4px 20px rgba(0,0,0,0.8); position: relative; margin-bottom: 20px;">
        <div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">
          暂无今日运行日志记录。
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; gap: 8px;">
          <button type="button" onclick="copyLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
            一键复制
          </button>
          <button type="button" onclick="exportLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            导出日志
          </button>
        </div>
        <button type="button" onclick="closeLogsModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>
</main>
<script>
let nodes=[], state={}, testingNodeIds = new Set();
let currentPage = 1;
const pageSize = 99999;
let currentPageNodes = [];

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP"};
  return dict[t] || t || "-";
};

const translateCountry = c => {
  const dict = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡"
  };
  return dict[c] || c || "-";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "testing": "检测中", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function matchesStatusAndIpType(n) {
  if (!n) return false;
  const selectedIpType = $("ip_type_filter").value;
  const selectedStatus = $("status_filter").value;
  if (selectedIpType === "residential" && !["residential", "mobile"].includes(n.ip_type)) return false;
  if (selectedIpType === "hosting" && n.ip_type !== "hosting") return false;
  if (selectedStatus === "available" && n.probe_status !== "available" && !n.active) return false;
  if (selectedStatus === "not_checked" && !["not_checked", ""].includes(n.probe_status || "")) return false;
  if (selectedStatus === "testing" && n.probe_status !== "testing") return false;
  if (selectedStatus === "unavailable" && (n.probe_status !== "unavailable" || n.active)) return false;
  return true;
}

function updateCountryFilter() {
  const select = $("country_filter");
  const selectedValue = select.value;
  const countries = Array.from(new Set(nodes.map(n => n ? translateCountry(n.country) : "").filter(Boolean))).sort();
  const scopedNodes = nodes.filter(matchesStatusAndIpType);
  const countryCounts = {};
  scopedNodes.forEach(n => {
    const country = translateCountry(n.country);
    if (country) countryCounts[country] = (countryCounts[country] || 0) + 1;
  });
  select.innerHTML = `<option value="">所有国家（${scopedNodes.length}）</option>` +
    countries.map(c => `<option value="${esc(c)}">${esc(c)}（${countryCounts[c] || 0}）</option>`).join("");
  select.value = countries.includes(selectedValue) ? selectedValue : "";

  const quickSelect = $("quick_country_select");
  if (quickSelect) {
    const allCountryCounts = {};
    nodes.forEach(n => {
      const country = n ? translateCountry(n.country) : "";
      if (country) allCountryCounts[country] = (allCountryCounts[country] || 0) + 1;
    });
    const desiredValue = state.routing_mode === "fixed_region" && translateCountry(state.force_country) !== "美国"
      ? translateCountry(state.force_country)
      : "";
    const quickCountries = countries.filter(c => c !== "美国");
    quickSelect.innerHTML = '<option value="">选择其他国家...</option>' +
      quickCountries.map(c => `<option value="${esc(c)}">${esc(c)}（${allCountryCounts[c] || 0} 个节点）</option>`).join("");
    quickSelect.value = quickCountries.includes(desiredValue) ? desiredValue : "";
  }
}

let multiExitData = __MULTI_EXIT_BOOTSTRAP_JSON__;
const multiExitExpandedCards = new Set();
const multiExitSelectedNodes = {};
function rememberMultiExitFold(id, isOpen){
  if(isOpen)multiExitExpandedCards.add(id);else multiExitExpandedCards.delete(id);
}
function rememberMultiExitCandidate(id, nodeId){multiExitSelectedNodes[id]=nodeId;}
async function loadMultiExit(){
  try { const r=await fetch("./api/multi_exit"); const d=await r.json(); if(d.ok){multiExitData=d;renderMultiExit();} } catch(e){}
}
function multiCountryOptions(selected){
  const list=Array.from(new Set(nodes.map(n=>n?translateCountry(n.country):"").filter(Boolean))).sort();
  if(selected && !list.includes(selected)) list.push(selected);
  return list.map(c=>`<option value="${esc(c)}" ${c===selected?'selected':''}>${esc(c)}</option>`).join("");
}
function multiProtocolLabel(value){return value==='hysteria'?'HY2':(value==='trojan'?'Trojan':'VLESS');}
function multiIpTypeLabel(value){return ({residential:'住宅',mobile:'移动',hosting:'机房',unknown:'未知'})[value]||value||'未知';}
function multiProbeLabel(value){return ({available:'可用',unavailable:'不可用',testing:'检测中',not_checked:'待检测'})[value]||'待检测';}
function multiRowBackground(value){return value==='available'?'rgba(34,197,94,.16)':(value==='unavailable'?'rgba(239,68,68,.16)':'rgba(245,158,11,.17)');}
function multiCandidateMatchesPolicy(node,policy){const t=node.ip_type||'unknown';if(policy==='residential_only')return t==='residential'||t==='mobile';if(policy==='hosting_only')return t==='hosting';return true;}
function renderMultiExit(){
  const directBox=$("direct_node_row");
  const direct=multiExitData.direct||{};
  if(directBox){
    const directOk=direct.status==="connected";
    const protocol=direct.protocol==="hysteria"?"Hysteria2":(direct.protocol||"-");
    directBox.innerHTML=`<div style="display:grid;grid-template-columns:1.4fr 120px 130px 1fr auto;gap:10px;align-items:center;padding:14px;border:1px solid var(--border-color);border-radius:10px;background:rgba(59,130,246,.06)">
      <div><strong>VPS 直连节点</strong><div style="font-size:12px;color:var(--text-secondary);margin-top:4px">不经过国家中转</div></div><span>端口 ${direct.port||'-'}</span><select id="direct_protocol" class="input-field"><option value="vless" ${direct.protocol==='vless'?'selected':''}>VLESS</option><option value="trojan" ${direct.protocol==='trojan'?'selected':''}>Trojan</option><option value="hysteria" ${direct.protocol==='hysteria'?'selected':''}>HY2</option></select>
      <span style="font-size:12px;color:${directOk?'var(--success)':'var(--warning)'}">${directOk?'已连接 '+esc(direct.exit_ip||''): '路由状态：'+esc(direct.routing||'未知')}</span><div style="display:flex;gap:6px;flex-wrap:wrap"><button class="toolbar-btn" onclick="saveDirectProtocol()">仅保存直连</button>${direct.universal_node?'<button class="toolbar-btn" onclick="copyDirectNode(\'universal_node\')">复制通用节点链接</button>':''}${direct.clash_node?'<button class="toolbar-btn" onclick="copyDirectNode(\'clash_node\')">复制 Clash/Mihomo 节点配置</button>':''}</div></div>`;
  }
  const bundleBox=$("bundle_subscription_row");const bundle=multiExitData.bundle||{};
  if(bundleBox)bundleBox.innerHTML=bundle.universal?`<div style="display:flex;justify-content:space-between;gap:12px;align-items:center;padding:12px 14px;border:1px solid var(--border-color);border-radius:10px;background:rgba(139,92,246,.07)"><div><strong>总节点订阅</strong><div style="font-size:12px;color:var(--text-secondary);margin-top:4px">包含 VPS 直连及全部已启用国家出口</div></div><div style="display:flex;gap:8px;flex-wrap:wrap"><button class="toolbar-btn" onclick="copyBundleSubscription('universal')">复制通用订阅链接</button><button class="toolbar-btn" onclick="copyBundleSubscription('clash')">复制 Clash/Mihomo 订阅链接</button></div></div>`:'';
  const box=$("multi_exit_rows"); if(!box)return;
  const runtime=(multiExitData.state&&multiExitData.state.channels)||{};
  const channels=multiExitData.config.channels||[];
  const connectedCount=channels.filter(c=>(runtime[c.id]||{}).status==='connected').length;
  if($('channel_overview'))$('channel_overview').innerHTML=`<span>国家出口 <b>${channels.length}</b></span><span style="color:#34d399">已连接 <b>${connectedCount}</b></span><span style="color:#fbbf24">待连接 <b>${channels.length-connectedCount}</b></span><span>自动检测已配置国家 · 健康出口保持原 IP</span>`;
  box.innerHTML=(multiExitData.config.channels||[]).map((c,i)=>{
    const s=runtime[c.id]||{}; const status=s.status||(c.awaiting_initial_test?'testing':'connecting'); const ok=status==="connected"; const pending=['connecting','switching','testing'].includes(status); const candidates=c.candidates||[];
    const available=candidates.filter(n=>n.probe_status==='available'&&multiCandidateMatchesPolicy(n,c.ip_type)).length;
    const selectedNodeId=multiExitSelectedNodes[c.id]||c.preferred_node_id||s.node_id||'';
    const rows=candidates.map(n=>{const current=n.id===s.node_id;const preferred=n.id===c.preferred_node_id;const checked=n.id===selectedNodeId;return `<label style="display:grid;grid-template-columns:28px 1.2fr .8fr 1.2fr .7fr .7fr;gap:8px;align-items:center;padding:8px 10px;border-bottom:1px solid var(--border-color);border-left:4px solid ${n.probe_status==='available'?'#22c55e':(n.probe_status==='unavailable'?'#ef4444':'#f59e0b')};font-size:12px;background:${multiRowBackground(n.probe_status)};${current?'font-weight:700;outline:1px solid rgba(59,130,246,.55);outline-offset:-1px;':''}">
      <input type="radio" name="candidate-${esc(c.id)}" value="${esc(n.id)}" ${checked?'checked':''} onchange="rememberMultiExitCandidate('${esc(c.id)}','${esc(n.id)}')">
      <span>${esc(n.ip||n.entry_ip||'-')}${current?' <b style="color:var(--success)">当前</b>':''}</span><span>${esc(multiIpTypeLabel(n.ip_type))}</span><span title="${esc(n.owner||'')}">${esc(n.owner||'-')}</span><span>${esc(multiProbeLabel(n.probe_status))}</span><span>${n.latency_ms?esc(n.latency_ms+' ms'):'-'}</span></label>`;}).join('');
    const stateLabel=ok?'已连接':(c.awaiting_initial_test?'等待 / 首次检测':status==='testing'?'正在检测':pending?'正在连接':'断线恢复中');
    return `<section class="country-card" data-health="${ok?'connected':pending?'pending':'failed'}" data-channel-card="${esc(c.id)}">
      <div style="display:flex;justify-content:space-between;gap:12px;align-items:center"><div><strong style="font-size:20px">${esc(c.country||c.name||c.id)}</strong><span style="font-size:12px;color:var(--text-secondary);margin-left:12px">${esc(multiProtocolLabel(c.protocol))} · ${esc(c.inbound_port)}</span></div><span class="badge ${ok?'available':(pending?'testing':'unavailable')}">${stateLabel}</span></div>
      <div class="channel-facts"><div><small>中转入口 · VPNGate 节点</small><strong>${esc(s.entry_ip||'尚未选定')}</strong>${esc(s.entry_provider||'选定节点后显示服务商')}</div><div><small>实际公网出口</small><strong>${esc(s.exit_ip||'尚未连接')}</strong>${esc(s.exit_provider||'连接验证后显示服务商')} · ${esc(multiIpTypeLabel(s.exit_ip_type))}</div></div>
      <div class="channel-state-note">${esc(c.awaiting_initial_test?'系统自动排队检测本国候选，找到首个合格节点后立即连接。':s.error||(ok?'出口正常，保持当前 IP；备用节点由后台维护。':'系统正在选择并验证本国出口。'))}</div>
      <div class="channel-fields"><label>出口国家<select data-field="country" class="input-field">${multiCountryOptions(c.country)}</select></label><label>入站端口<input data-field="inbound_port" type="number" min="1024" max="65535" class="input-field" value="${c.inbound_port}"></label><label>连接协议<select data-field="protocol" class="input-field"><option value="vless" ${c.protocol==='vless'?'selected':''}>VLESS</option><option value="trojan" ${c.protocol==='trojan'?'selected':''}>Trojan</option><option value="hysteria" ${(c.protocol||'hysteria')==='hysteria'?'selected':''}>HY2</option></select></label><label>IP 选择策略<select data-field="ip_type" class="input-field"><option value="all" ${c.ip_type==='all'?'selected':''}>全部 IP</option><option value="residential_preferred" ${c.ip_type==='residential_preferred'?'selected':''}>住宅优先</option><option value="residential_only" ${c.ip_type==='residential_only'?'selected':''}>仅住宅</option><option value="hosting_only" ${c.ip_type==='hosting_only'?'selected':''}>仅机房</option></select></label></div>
      <details style="margin-top:14px;border:1px solid var(--border-color);border-radius:8px;overflow:hidden"><summary style="cursor:pointer;padding:10px 12px;background:rgba(255,255,255,.04)"><b style="font-size:13px">${esc(c.country)}候选 IP：${candidates.length} 个（可用 ${available}）</b><span style="font-size:11px;color:var(--text-secondary);margin-left:12px">默认折叠；健康节点保持连接，异常后才选择同国备用</span></summary><div style="overflow:auto;max-height:330px"><div style="display:grid;grid-template-columns:28px 1.2fr .8fr 1.2fr .7fr .7fr;gap:8px;padding:8px 10px;background:rgba(255,255,255,.05);font-size:11px;color:var(--text-secondary)"><span></span><span>IP</span><span>类型</span><span>服务商</span><span>状态</span><span>延迟</span></div>${rows||'<div style="padding:16px;color:var(--text-secondary)">暂无该国节点，请先点击顶部“更新节点资料”</div>'}</div></details>
      <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:12px"><button class="toolbar-btn" onclick="saveMultiExitChannel('${esc(c.id)}')">保存并应用本线路</button><button class="toolbar-btn" onclick="testMultiExitChannel('${esc(c.id)}')">检测本国节点可用性</button><button class="toolbar-btn" onclick="switchMultiExitNode('${esc(c.id)}')">切换到所选 IP</button>${c.universal_node?`<button class="toolbar-btn" onclick="copyChannelNode('${esc(c.id)}','universal_node')">复制通用节点链接</button>`:''}${c.clash_node?`<button class="toolbar-btn" onclick="copyChannelNode('${esc(c.id)}','clash_node')">复制 Clash/Mihomo 节点配置</button>`:''}<button class="toolbar-btn" style="border-color:rgba(239,68,68,.7);color:#ef4444" onclick="deleteMultiExitChannel('${esc(c.id)}')">删除本国通道</button><span id="channel-message-${esc(c.id)}" style="font-size:12px;color:var(--text-secondary)"></span></div>
    </section>`;
  }).join("")||'<div style="color:var(--text-secondary)">尚未配置通道</div>';
  box.querySelectorAll('section[data-channel-card] details').forEach(details=>{
    const card=details.closest('section[data-channel-card]');const id=card&&card.dataset.channelCard;if(!id)return;
    details.open=multiExitExpandedCards.has(id);
    details.addEventListener('toggle',()=>rememberMultiExitFold(id,details.open));
  });
}
renderMultiExit();
loadMultiExit();
function addMultiExitRow(){
  openAddChannelModal();
}
function availableNewChannelCountries(){
  const configured=new Set((multiExitData.config.channels||[]).map(c=>translateCountry(c.country)));
  const counts={};
  nodes.forEach(n=>{if(!n)return;const country=translateCountry(n.country);if(!country||configured.has(country))return;if(!counts[country])counts[country]={total:0,available:0};counts[country].total++;if(n.active||n.probe_status==='available')counts[country].available++;});
  return Object.entries(counts).sort((a,b)=>(b[1].available-a[1].available)||a[0].localeCompare(b[0],'zh-CN'));
}
function randomAvailableChannelPort(){
  const used=new Set([80,443,2096,2097,7928,8787,Number((multiExitData.direct||{}).port||0),...(multiExitData.config.channels||[]).map(c=>Number(c.inbound_port||0))]);
  for(let i=0;i<300;i++){const port=10000+Math.floor(Math.random()*50001);if(!used.has(port))return port;}
  let port=10000;while(used.has(port)&&port<65535)port++;return port;
}
function renderAddChannelCountries(){
  const select=$("new_channel_country");if(!select)return;
  const countries=availableNewChannelCountries();
  select.innerHTML=countries.length?countries.map(([country,count])=>`<option value="${esc(country)}" data-available="${count.available}" data-total="${count.total}">${esc(country)}（可用 ${count.available} / 共 ${count.total}）</option>`).join(''):'<option value="">节点清单中没有尚未创建出口的国家</option>';
  $("new_channel_create").disabled=!countries.length;updateAddChannelCountryHint();
}
function updateAddChannelCountryHint(){
  const option=$("new_channel_country")?.selectedOptions?.[0];
  const hint=$("new_channel_country_hint");if(hint)hint.textContent=option&&option.value?`创建后会先检测 ${option.value} 的全部候选节点，再按所选 IP 类型策略自动连接；当前可用 ${option.dataset.available||0} 个，共 ${option.dataset.total||0} 个候选。`:'节点清单中没有可创建的新国家出口。';
}
function openAddChannelModal(){
  $("new_channel_port").value=randomAvailableChannelPort();$("new_channel_protocol").value='hysteria';$("new_channel_ip_type").value='residential_preferred';
  const error=$("new_channel_error");error.style.display='none';error.textContent='';renderAddChannelCountries();$("add_channel_modal").style.display='flex';
}
function closeAddChannelModal(){if($("add_channel_modal"))$("add_channel_modal").style.display='none';}
async function createMultiExitChannel(){
  const country=$("new_channel_country").value;const port=parseInt($("new_channel_port").value);const protocol=$("new_channel_protocol").value;const ipType=$("new_channel_ip_type").value;
  const error=$("new_channel_error");const button=$("new_channel_create");
  if(!country){error.textContent='请选择一个有候选节点的国家';error.style.display='block';return;}
  if(!Number.isInteger(port)||port<1024||port>65535){error.textContent='端口必须在 1024 至 65535 之间';error.style.display='block';return;}
  const id=('line'+Date.now().toString(36)).slice(0,12);button.disabled=true;button.textContent='正在创建...';error.style.display='none';
  try{
    const r=await fetch('./api/update_multi_exit_channel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,name:country+'线路',country,inbound_port:port,protocol,ip_type:ipType})});
    const d=await r.json();if(!r.ok||!d.ok)throw new Error(d.error||'创建失败');closeAddChannelModal();$("multi_exit_message").textContent=d.message;await loadMultiExit();
  }catch(e){error.textContent=e.message;error.style.display='block';}
  finally{button.disabled=false;button.textContent='创建国家出口';}
}
function removeMultiExitRow(i){multiExitData.config.channels.splice(i,1);renderMultiExit();}
async function deleteMultiExitChannel(id){
  const channel=(multiExitData.config.channels||[]).find(item=>item.id===id);if(!channel)return;
  const country=channel.country||channel.name||id;const port=channel.inbound_port||'-';
  if(!window.confirm(`确认删除 ${country} 通道？\n\n将同时删除：\n• 端口 ${port} 的 3x-ui 入站\n• 对应节点客户端和订阅记录\n• Xray 路由和该国家出站\n\n其他国家和 VPS 直连不受影响。`))return;
  channelMessage(id,'正在删除本国通道和 3x-ui 节点...');
  try{
    const r=await fetch('./api/delete_multi_exit_channel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({channel_id:id})});
    const d=await r.json();if(!r.ok||!d.ok)throw new Error(d.error||'删除失败');
    $("multi_exit_message").textContent=d.message;await loadMultiExit();
  }catch(e){channelMessage(id,e.message);}
}
function channelCard(id){return document.querySelector(`[data-channel-card="${CSS.escape(id)}"]`);}
function channelMessage(id,text){const el=$("channel-message-"+id);if(el)el.textContent=text;}
async function saveMultiExitChannel(id){
  const card=channelCard(id);if(!card)return;const country=card.querySelector('[data-field=country]').value;
  const payload={id,name:country+'线路',country,inbound_port:parseInt(card.querySelector('[data-field=inbound_port]').value),protocol:card.querySelector('[data-field=protocol]').value,ip_type:card.querySelector('[data-field=ip_type]').value};
  channelMessage(id,'正在仅保存当前线路...');try{const r=await fetch('./api/update_multi_exit_channel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const d=await r.json();if(!r.ok||!d.ok)throw new Error(d.error||'保存失败');channelMessage(id,d.message);await loadMultiExit();}catch(e){channelMessage(id,e.message);}
}
async function testMultiExitChannel(id){
  const startedAt=Date.now()/1000;channelMessage(id,'正在启动本国节点检测...');try{const r=await fetch('./api/test_multi_exit_channel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({channel_id:id})});const d=await r.json();if(!r.ok||!d.ok)throw new Error(d.error||'启动失败');channelMessage(id,d.message);monitorChannelAvailability(id,startedAt);}catch(e){channelMessage(id,e.message);}
}
async function monitorChannelAvailability(id,startedAt){
  let seen=false;
  for(let i=0;i<600;i++){
    await new Promise(resolve=>setTimeout(resolve,2000));
    await loadMultiExit();
    const m=multiExitData.maintenance||{};
    const active=Boolean(m.running)&&m.channel_id===id;
    if(active){seen=true;channelMessage(id,m.message||'正在检测...');continue;}
    const result=(m.channel_results||{})[id]||{};
    if(Number(result.completed_at||0)>=startedAt-2){channelMessage(id,result.message||'本国节点检测已完成');return;}
    if(i>=5){channelMessage(id,'检测任务未启动，请重试');return;}
  }
  channelMessage(id,'检测超时，请刷新页面查看状态');
}
async function switchMultiExitNode(id){
  const card=channelCard(id);const selected=card&&card.querySelector(`input[name="candidate-${CSS.escape(id)}"]:checked`);if(!selected){channelMessage(id,'请先选择一个候选 IP');return;}channelMessage(id,'正在切换当前国家出口...');try{const r=await fetch('./api/switch_multi_exit_node',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({channel_id:id,node_id:selected.value})});const d=await r.json();if(!r.ok||!d.ok)throw new Error(d.error||'切换失败');channelMessage(id,d.message);setTimeout(loadMultiExit,3000);}catch(e){channelMessage(id,e.message);}
}
let copyNoticeTimer;
function showCopyNotice(message, success){
  let notice=document.getElementById('copy-notice');
  if(!notice){
    notice=document.createElement('div');notice.id='copy-notice';
    notice.setAttribute('role','status');notice.setAttribute('aria-live','polite');
    notice.style.cssText='position:fixed;bottom:28px;left:50%;transform:translateX(-50%);z-index:100000;padding:12px 20px;border-radius:12px;color:white;box-shadow:0 8px 30px #0005;max-width:90vw;font-size:14px;pointer-events:none;text-align:center';
    document.body.appendChild(notice);
  }
  notice.textContent=message;notice.style.background=success?'#047857':'#92400e';notice.hidden=false;
  clearTimeout(copyNoticeTimer);copyNoticeTimer=setTimeout(()=>{notice.hidden=true;},3500);
}
function copyTextFallback(value){
  const previous=document.activeElement;
  const input=document.createElement('textarea');input.value=value;input.readOnly=true;
  input.style.cssText='position:fixed;left:-9999px;top:0;font-size:16px';
  document.body.appendChild(input);
  try{input.focus({preventScroll:true});input.select();input.setSelectionRange(0,input.value.length);return document.execCommand('copy')===true;}
  catch(e){return false;}
  finally{input.remove();if(previous&&previous.focus)previous.focus({preventScroll:true});}
}
async function copyText(value){
  if(!value){showCopyNotice('链接尚未生成，请稍后再试',false);return;}
  let copied=false;
  if(window.isSecureContext&&navigator.clipboard&&navigator.clipboard.writeText){
    try{await navigator.clipboard.writeText(value);copied=true;}catch(e){}
  }
  if(!copied)copied=copyTextFallback(value);
  if(copied){showCopyNotice('已复制到剪贴板',true);return;}
  window.prompt('浏览器禁止自动复制，请手动复制以下内容',value);
  showCopyNotice('未能自动复制，请手动复制',false);
}
function copyDirectNode(kind){copyText((multiExitData.direct||{})[kind]||'');}
function copyChannelNode(id,kind){const item=(multiExitData.config.channels||[]).find(c=>c.id===id);copyText((item||{})[kind]||'');}
function copyBundleSubscription(kind){copyText((multiExitData.bundle||{})[kind]||'');}
async function saveDirectProtocol(){const protocol=($("direct_protocol")||{}).value;if(!protocol)return;const msg=$("multi_exit_message");msg.textContent='正在仅保存 VPS 直连协议...';try{const r=await fetch('./api/update_direct_protocol',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({protocol})});const d=await r.json();if(!r.ok||!d.ok)throw new Error(d.error||'保存失败');msg.textContent=d.message;await loadMultiExit();}catch(e){msg.textContent=e.message;}}
async function saveMultiExit(){
  const first=(multiExitData.config.channels||[])[0];if(first)await saveMultiExitChannel(first.id);
}
// Keep the selected candidate in the same per-channel save operation.
async function saveMultiExitChannel(id){
  const card=channelCard(id);if(!card)return;
  const country=card.querySelector('[data-field=country]').value;
  const selected=card.querySelector(`input[name="candidate-${CSS.escape(id)}"]:checked`);
  const original=(multiExitData.config.channels||[]).find(item=>item.id===id);
  const preferredNodeId=original&&translateCountry(original.country)===translateCountry(country)&&selected?selected.value:'';
  const payload={
    id,name:country,country,
    inbound_port:parseInt(card.querySelector('[data-field=inbound_port]').value),
    protocol:card.querySelector('[data-field=protocol]').value,
    ip_type:card.querySelector('[data-field=ip_type]').value,
    preferred_node_id:preferredNodeId,
  };
  channelMessage(id,'\u6b63\u5728\u4fdd\u5b58\u5e76\u5207\u6362\u5f53\u524d\u7ebf\u8def...');
  try{
    const r=await fetch('./api/update_multi_exit_channel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    const d=await r.json();if(!r.ok||!d.ok)throw new Error(d.error||'\u4fdd\u5b58\u5931\u8d25');
    if(preferredNodeId)multiExitSelectedNodes[id]=preferredNodeId;
    channelMessage(id,d.message);await loadMultiExit();
  }catch(e){channelMessage(id,e.message);}
}
setInterval(loadMultiExit,15000);

let quickRoutingBusy = false;

function renderQuickRouting() {
  const summary = $("quick_routing_summary");
  const badge = $("quick_routing_badge");
  const countryKey = state.routing_mode === "fixed_region"
    ? translateCountry(state.force_country)
    : (state.routing_mode === "auto" ? "auto" : "");
  const ipType = state.routing_ip_type || "all";
  const routeNames = {
    auto: "自动选择",
    fixed_ip: "固定 IP",
    fixed_region: `固定国家：${translateCountry(state.force_country)}`,
    favorites: "仅用收藏"
  };
  const ipTypeNames = {all: "全部 IP", residential: "住宅 IP", hosting: "机房 IP"};
  const targetNodes = nodes.filter(n => {
    if (!n) return false;
    if (state.routing_mode === "fixed_region" && translateCountry(n.country) !== translateCountry(state.force_country)) return false;
    if (ipType === "residential" && !["residential", "mobile"].includes(n.ip_type)) return false;
    if (ipType === "hosting" && n.ip_type !== "hosting") return false;
    return true;
  });
  const availableCount = targetNodes.filter(n => n.active || n.probe_status === "available").length;

  if (summary) {
    summary.textContent = `当前：${routeNames[state.routing_mode] || "自定义策略"} · ${ipTypeNames[ipType] || ipType} · ${availableCount} 个可用候选`;
  }
  if (badge) {
    badge.className = state.maintenance_running ? "badge testing" : "badge available";
    badge.textContent = state.maintenance_running ? "正在更新节点" : "自动更新：约 21 分钟";
  }

  document.querySelectorAll("[data-quick-country]").forEach(btn => {
    const value = btn.getAttribute("data-quick-country");
    btn.classList.toggle("active", value === countryKey);
    btn.disabled = quickRoutingBusy;
  });
  const quickCountrySelect = $("quick_country_select");
  if (quickCountrySelect) {
    const selectedOtherCountry = state.routing_mode === "fixed_region" && countryKey !== "美国" ? countryKey : "";
    if (Array.from(quickCountrySelect.options).some(option => option.value === selectedOtherCountry)) {
      quickCountrySelect.value = selectedOtherCountry;
    } else {
      quickCountrySelect.value = "";
    }
    quickCountrySelect.classList.toggle("active", Boolean(selectedOtherCountry));
    quickCountrySelect.disabled = quickRoutingBusy;
  }
  document.querySelectorAll("[data-quick-ip-type]").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-quick-ip-type") === ipType);
    btn.disabled = quickRoutingBusy;
  });
}

async function saveQuickRouting(routingMode, forceCountry, routingIpType) {
  if (quickRoutingBusy) return;
  quickRoutingBusy = true;
  const message = $("quick_routing_message");
  if (message) {
    message.style.color = "var(--warning)";
    message.textContent = "正在保存策略并启动节点更新...";
  }
  renderQuickRouting();

  try {
    const response = await fetch("./api/update_routing", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        routing_mode: routingMode,
        force_country: forceCountry,
        routing_ip_type: routingIpType,
        connection_enabled: true
      })
    });
    const result = await response.json();
    if (!response.ok || !result.ok) {
      throw new Error(result.error || "保存策略失败");
    }

    state.routing_mode = routingMode;
    state.force_country = forceCountry;
    state.routing_ip_type = routingIpType;
    state.connection_enabled = true;
    if (message) {
      message.style.color = "var(--success)";
      message.textContent = "策略已保存，后台正在更新节点资料；需要重测连通性时请点击“检测节点可用性”。";
    }
    await fetch("./api/refresh_nodes", {method: "POST"});
    await load();
    startRefreshPolling();
  } catch (error) {
    if (message) {
      message.style.color = "var(--danger)";
      message.textContent = error.message || "保存策略失败，请稍后重试。";
    }
    await load();
  } finally {
    quickRoutingBusy = false;
    renderQuickRouting();
  }
}

function applyQuickCountry(country) {
  const routingMode = country === "auto" ? "auto" : "fixed_region";
  const forceCountry = country === "auto" ? "" : country;
  saveQuickRouting(routingMode, forceCountry, state.routing_ip_type || "all");
}

function applyQuickCountrySelect(country) {
  if (!country) return;
  applyQuickCountry(country);
}

function applyQuickIpType(ipType) {
  let routingMode = state.routing_mode || "auto";
  let forceCountry = state.force_country || "";
  if (!["auto", "fixed_region", "favorites", "fixed_ip"].includes(routingMode)) {
    routingMode = "auto";
    forceCountry = "";
  }
  saveQuickRouting(routingMode, forceCountry, ipType);
}

function getFilteredNodes() {
  const selectedCountry = $("country_filter").value;
  const selectedIpType = $("ip_type_filter").value;
  const selectedStatus = $("status_filter").value;
  return nodes.filter(n => {
    if (!n) return false;
    if (selectedCountry && translateCountry(n.country) !== selectedCountry) {
      return false;
    }
    if (selectedIpType) {
      if (selectedIpType === "residential" && !["residential", "mobile"].includes(n.ip_type)) {
        return false;
      }
      if (selectedIpType === "hosting" && n.ip_type !== "hosting") {
        return false;
      }
    }
    if (selectedStatus === "available" && n.probe_status !== "available" && !n.active) {
      return false;
    }
    if (selectedStatus === "not_checked" && !["not_checked", ""].includes(n.probe_status || "")) {
      return false;
    }
    if (selectedStatus === "testing" && n.probe_status !== "testing") {
      return false;
    }
    if (selectedStatus === "unavailable" && (n.probe_status !== "unavailable" || n.active)) {
      return false;
    }
    const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
    if (showFavoritesOnly && !favoriteIds.includes(n.id)) {
      return false;
    }
    return true;
  });
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if (!a || !b) return 0;
    const aScore = a.score || 0;
    const bScore = b.score || 0;
    if (bScore !== aScore) {
      return bScore - aScore;
    }
    const aId = a.id || "";
    const bId = b.id || "";
    return aId.localeCompare(bId);
  });
}

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n && (n.active || n.id === activeNodeId));

  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  if (state.is_connecting && !activeNode) {
    const busyTitle = state.maintenance_task === "metadata" ? "正在更新节点资料" : (state.maintenance_task === "availability" ? "正在检测可用性" : (state.maintenance_running ? "正在更新节点" : "正在连接"));
    const busyLatency = state.maintenance_task === "metadata" ? "服务商与 IP 类型识别中" : (state.maintenance_running ? "节点检测中" : (state.active_node_latency || "正在连接..."));
    const busyMessage = state.last_check_message || (state.maintenance_running ? "正在后台拉取并检测节点，已完成的结果会实时显示在下方列表。" : "正在与 VPN 节点建立加密隧道，请稍候...");
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>${esc(busyTitle)}</span>
              <strong>${esc(busyLatency)}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(busyMessage)}
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (activeNode) {
    const latencyClass = getLatencyClass(activeNode.latency_ms);
    const latencyText = activeNode.latency_ms ? `<span class="latency-val ${latencyClass}">${activeNode.latency_ms} ms</span>` : "-";
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    const exitIp = activeNode.exit_ip || state.proxy_ip || "-";
    const exitCountry = activeNode.exit_country || activeNode.exit_country_short || state.exit_country || "检测中";
    const exitLocation = activeNode.exit_location || state.exit_location || exitCountry;
    const exitIpType = activeNode.exit_ip_type || state.exit_ip_type || "";
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${esc(exitCountry)} 实际出口</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(exitIp)}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>入口节点: <strong>${esc(translateCountry(activeNode.country))} ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}</strong></span>
              <span style="margin-left: 12px;">入口位置: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>实际出口位置: <strong>${esc(exitLocation)}</strong></span>
              <span style="margin-left: 12px;">出口运营主体: <strong>${esc(activeNode.exit_owner || activeNode.exit_as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">出口 IP 类型: <strong>${esc(translateIpType(exitIpType))}</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  } else {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              在下方列表中选择一个可用备用节点并点击 “切换” 按钮开始连接。
            </div>
          </div>
        </div>
      </div>
    `;
  }

  const shown = getFilteredNodes();
  const filterCount = $("filter_result_count");
  if (filterCount) filterCount.textContent = "当前筛选：" + shown.length + " 个节点";

  if ($("total")) $("total").textContent = nodes.length;
  if ($("target")) $("target").textContent = state.target_valid_nodes || 3;
  if ($("active")) $("active").textContent = activeNode ? 1 : 0;

  const statusMessage = state.last_check_message || "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
  const localProxy = state.local_proxy || `http://127.0.0.1:${state.proxy_port || 7928}`;
  if ($("status")) { $("status").innerHTML=`<span class="status-dot"></span>HTTP 代理本地接口：${localProxy} | 活动节点：${activeNodeInfo} | 状态：${statusMessage}`; }

  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");

  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px; max-width: 450px; display: inline-block; white-space: normal; line-height: 1.4; text-align: left;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  updateFavPanelUI();
  renderQuickRouting();

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;

  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      if (!n) return '';
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';

      const badgeClass = isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms} ms</span>` : "-";
      const displayLocation = n.location || translateCountry(n.country) || "-";

      const isTesting = testingNodeIds.has(n.id) || n.probe_status === "testing";
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;

      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      // Connect button is disabled if probe status is "unavailable" and not already active, or if we are already connecting
      const isUnavailable = n.probe_status === "unavailable";
      const connectBtn = isCurrentlyActive
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" ${(isUnavailable || isTesting || state.is_connecting) ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')">切换</button>`;

      const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
      const isFav = favoriteIds.includes(n.id);
      const favBtn = isFav
        ? `<button class="test-btn" style="color: var(--warning); border-color: rgba(245, 158, 11, 0.4); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">★ 已收藏</button>`
        : `<button class="test-btn" style="color: var(--text-secondary); border-color: var(--border-color); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">☆ 收藏</button>`;

      return `<tr ${rowClass}>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td class="mono" style="white-space: nowrap; max-width: 220px; overflow: hidden; text-overflow: ellipsis;" title="${esc(n.ip||n.remote_host)}:${n.remote_port||""}">${esc(n.ip||n.remote_host)}:${n.remote_port||""}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(displayLocation)}">${esc(displayLocation)}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${esc(n.owner||n.as_name||"-")}">${esc(n.owner||n.as_name||"-")}</td>
        <td style="white-space: nowrap; max-width: 110px; overflow: hidden; text-overflow: ellipsis;" title="${esc(translateIpType(n.ip_type))}">${esc(translateIpType(n.ip_type))}</td>
        <td>
          <div class="table-actions">
            ${favBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;

  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event){
  if (event) event.stopPropagation();
  testingNodeIds.add(id);
  render();

  try {
    const response = await fetch("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n && n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
    }
  } catch (e) {
  } finally {
    testingNodeIds.delete(id);
    render();
  }
}

async function toggleFavorite(id, event) {
  if (event) event.stopPropagation();
  try {
    const response = await fetch("./api/toggle_favorite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok) {
      state.favorite_node_ids = Array.isArray(result.favorite_node_ids) ? result.favorite_node_ids : [];
      render();
    }
  } catch (e) {
    console.error("切换收藏失败", e);
  }
}

let pollInterval = null;
let refreshPollInterval = null;

function refreshButtonBusy(message = "正在后台更新...") {
  const btn = $("refresh");
  if (!btn) return;
  btn.disabled = true;
  btn.innerHTML = `<svg style="animation: spin 1s linear infinite; width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>${esc(message)}`;
}

function refreshButtonIdle() {
  const btn = $("refresh");
  if (!btn) return;
  btn.disabled = false;
  btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>更新节点资料`;
}

function availabilityButtonBusy(message = "正在检测可用性...") {
  const btn = $("test_availability");
  if (!btn) return;
  btn.disabled = true;
  btn.innerHTML = `<svg style="animation: spin 1s linear infinite; width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>${esc(message)}`;
}

function availabilityButtonIdle() {
  const btn = $("test_availability");
  if (!btn) return;
  btn.disabled = false;
  btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>检测节点可用性`;
}

function currentRefreshProgressLabel() {
  const message = String(state.last_check_message || "");
  if (message.includes("拉取")) return "正在拉取节点...";
  if (message.includes("识别") || message.includes("服务商") || message.includes("IP 类型")) return "正在识别 IP 资料...";
  if (message.includes("可用性")) return "正在检测可用性...";
  if (message.includes("快速") || message.includes("连接")) return "正在筛选并连接...";
  if (message.includes("检测")) return "正在检测节点...";
  return "更新任务进行中...";
}

function startRefreshPolling() {
  if (refreshPollInterval) clearInterval(refreshPollInterval);
  if (state.maintenance_task === "availability") {
    availabilityButtonBusy("正在检测可用性...");
    refreshButtonBusy("资料更新需等待...");
  } else {
    refreshButtonBusy(currentRefreshProgressLabel());
    availabilityButtonBusy("节点任务进行中...");
  }
  refreshPollInterval = setInterval(async () => {
    try {
      const resp = await fetch("./api/nodes");
      const data = await resp.json();
      nodes = Array.isArray(data.nodes) ? data.nodes : [];
      state = data.state || {};
      stableSortNodes();
      updateCountryFilter();
      render();
      loadMultiExit();

      if (state.maintenance_running) {
        if (state.maintenance_task === "availability") {
          availabilityButtonBusy("正在检测可用性...");
          refreshButtonBusy("资料更新需等待...");
        } else {
          refreshButtonBusy(currentRefreshProgressLabel());
          availabilityButtonBusy("节点任务进行中...");
        }
      } else {
        clearInterval(refreshPollInterval);
        refreshPollInterval = null;
        refreshButtonIdle();
        availabilityButtonIdle();
      }
    } catch (pe) {
      clearInterval(refreshPollInterval);
      refreshPollInterval = null;
      refreshButtonIdle();
      availabilityButtonIdle();
    }
  }, 1000);
}

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      const resp = await fetch("./api/nodes");
      const data = await resp.json();
      nodes = Array.isArray(data.nodes) ? data.nodes : [];
      state = data.state || {};
      stableSortNodes();
      updateCountryFilter();
      render();

      if (!state.is_connecting && !state.maintenance_running) {
        clearInterval(pollInterval);
        pollInterval = null;
        try {
          await fetch("./api/test_proxy", { method: "POST" });
        } catch(pe){}
        load();
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      load();
    }
  }, 1000);
}

async function connectNode(id){
  state.is_connecting = true;
  state.active_openvpn_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();

  startConnectionPolling();

  try {
    const r = await fetch("./api/connect",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({id})
    });
    const result = await r.json();
    if (!result.ok) {
      alert("连接失败: " + (result.error || "未知错误"));
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      render();
      return;
    }
  } catch(e) {
    alert("连接请求错误");
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    render();
  }
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const response = await fetch("./api/disconnect", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      try {
        await fetch("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败");
  }
}





async function load(){
  const r=await fetch("./api/nodes");
  const d=await r.json();
  nodes=Array.isArray(d.nodes) ? d.nodes : [];
  state=d.state||{};

  stableSortNodes();
  updateCountryFilter();
  render();

  if (state.maintenance_running) {
    startRefreshPolling();
  } else if (state.is_connecting) {
    startConnectionPolling();
  }
}
$("country_filter").onchange=()=>{ currentPage = 1; render(); };
$("ip_type_filter").onchange=()=>{ currentPage = 1; updateCountryFilter(); render(); };
$("status_filter").onchange=()=>{ currentPage = 1; updateCountryFilter(); render(); };

$("refresh").onclick=async()=>{
  refreshButtonBusy("正在启动更新...");
  try{
    const response = await fetch("./api/refresh_nodes",{method:"POST"});
    const result = await response.json();
    if (!response.ok || !result.ok) {
      throw new Error(result.error || "启动更新失败");
    }
    refreshButtonBusy(result.running ? "更新任务已在运行..." : "正在拉取节点...");
    await load();
    startRefreshPolling();
  }
  catch(e){
    const message = $("quick_routing_message");
    if (message) {
      message.style.color = "var(--danger)";
      message.textContent = e.message || "更新节点失败，请稍后重试。";
    }
    refreshButtonIdle();
  }
};
$("stop_refresh").onclick=async()=>{
  const btn=$("stop_refresh");
  const message=$("multi_exit_message");
  btn.disabled=true;
  btn.textContent="正在停止...";
  try{
    const response=await fetch("./api/stop_refresh",{method:"POST"});
    const result=await response.json();
    if(!response.ok||!result.ok)throw new Error(result.error||"停止失败");
    if(message){message.style.color="var(--warning)";message.textContent=result.message;}
    await load();
  }catch(e){
    if(message){message.style.color="var(--danger)";message.textContent=e.message||"停止节点拉取失败";}
  }finally{
    btn.disabled=false;
    btn.textContent="停止拉取节点";
  }
};
$("test_availability").onclick=async()=>{
  const filteredNodes = getFilteredNodes();
  const nodeIds = filteredNodes.map(n => n && n.id).filter(Boolean);
  if (!nodeIds.length) {
    const message = $("quick_routing_message");
    if (message) {
      message.style.color = "var(--warning)";
      message.textContent = "当前筛选条件下没有节点，无需检测。";
    }
    return;
  }
  availabilityButtonBusy("正在启动检测...");
  try {
    const response = await fetch("./api/test_availability", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ids: nodeIds}),
    });
    const result = await response.json();
    if (!response.ok || !result.ok) {
      throw new Error(result.error || "启动可用性检测失败");
    }
    availabilityButtonBusy(result.running ? "节点任务已在运行..." : `正在检测 ${nodeIds.length} 个节点...`);
    await load();
    startRefreshPolling();
  } catch (e) {
    const message = $("quick_routing_message");
    if (message) {
      message.style.color = "var(--danger)";
      message.textContent = e.message || "检测节点可用性失败，请稍后重试。";
    }
    availabilityButtonIdle();
  }
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");

  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";

  try {
    const response = await fetch("./api/test_proxy", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";

      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

// Admin dropdown toggle & GitHub dropdown toggle
const adminBtn = $("admin_btn");
const adminDropdown = $("admin_dropdown");

document.addEventListener("click", () => {
  if (adminDropdown) adminDropdown.style.display = "none";
});

let showFavoritesOnly = false;

function toggleFavoritesView() {
  showFavoritesOnly = !showFavoritesOnly;
  currentPage = 1;
  render();
}

function updateFavPanelUI() {
  const panel = $("favorites_panel");
  if (!panel) return;
  panel.style.display = showFavoritesOnly ? "block" : "none";

  const btn = $("btn_favorites");
  if (btn) {
    if (showFavoritesOnly) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  }

  if (showFavoritesOnly && state) {
    const favRoutingBtn = $("btn_toggle_fav_routing");
    if (favRoutingBtn) {
      if (state.routing_mode === "favorites") {
        favRoutingBtn.textContent = "禁用仅用收藏出站";
        favRoutingBtn.style.background = "var(--danger-gradient)";
        favRoutingBtn.style.borderColor = "transparent";
        favRoutingBtn.style.color = "#ffffff";
        favRoutingBtn.style.boxShadow = "0 0 12px rgba(244, 63, 94, 0.3)";
      } else {
        favRoutingBtn.textContent = "启用仅用收藏出站";
        favRoutingBtn.style.background = "rgba(255,255,255,0.03)";
        favRoutingBtn.style.borderColor = "var(--border-color)";
        favRoutingBtn.style.color = "var(--text-primary)";
        favRoutingBtn.style.boxShadow = "none";
      }
    }
  }
}

async function toggleFavRouting() {
  if (!state) return;
  const newMode = state.routing_mode === "favorites" ? "auto" : "favorites";

  state.routing_mode = newMode;
  updateFavPanelUI();

  try {
    const res = await fetch("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: newMode,
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all"
      })
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      load();
    } else {
      alert("更新出站路由设置失败: " + (data.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败，请稍后重试");
    load();
  }
}

function selectOptionCard(groupName, value) {
  if (groupName === 'routing_mode') {
    const input = $("net_routing_mode");
    if (input) input.value = value;

    const cards = document.querySelectorAll("#routing_mode_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });

    handleRoutingModeChange(value);
  } else if (groupName === 'routing_ip_type') {
    const input = $("net_routing_ip_type");
    if (input) input.value = value;

    const cards = document.querySelectorAll("#routing_ip_type_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
  }
}

function setRoutingMode(value) {
  selectOptionCard('routing_mode', value);
}

function setRoutingIpType(value) {
  selectOptionCard('routing_ip_type', value);
}

function handleRoutingModeChange(mode) {
  const countryGroup = $("net_force_country_group");
  const warningDiv = $("net_routing_warning");

  if (mode === "fixed_region") {
    countryGroup.style.display = "block";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定地区</strong>：限制仅连接选定国家的节点，且后台仅并发测速该国家的节点。如果该国的所有可用节点都失效，会造成代理中断且<strong>绝不自动切换到其他国家</strong>的节点。`;
  } else if (mode === "favorites") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>仅用收藏</strong>：只连接和切换您收藏的节点。如果所有收藏的节点均失效，系统不会自动切换到未收藏的节点。请确保收藏列表中有足够多且可用的节点。`;
  } else if (mode === "fixed_ip") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定IP</strong>：锁定当前连接的节点。不管该节点是否失效，系统都绝不自动切换至其他IP；如果节点由于网络故障失效，会造成代理中断（但如果OpenVPN连接意外退出，脚本将尝试为您在后台重新拉起连接同一IP）。<br><strong>提示</strong>：您可以在主页 of 节点列表中直接点击“连接”按钮来选择并锁定不同的IP节点。`;
  } else {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--text-secondary)";
    warningDiv.style.background = "rgba(255, 255, 255, 0.02)";
    warningDiv.style.border = "1px solid rgba(255, 255, 255, 0.05)";
    warningDiv.innerHTML = `ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。`;
  }
}

function populateRoutingCountries() {
  const select = $("net_force_country");
  if (!select) return;
  const countMap = {};
  nodes.forEach(n => {
    const c = translateCountry(n.country);
    if (c) {
      countMap[c] = (countMap[c] || 0) + 1;
    }
  });

  const countries = Object.keys(countMap).sort();
  let html = '<option value="">请选择要锁定的国家...</option>';
  countries.forEach(c => {
    html += `<option value="${esc(c)}">${esc(c)} (${countMap[c]}个节点)</option>`;
  });
  select.innerHTML = html;

  if (state) {
    select.value = state.force_country ? translateCountry(state.force_country) : "";
  }
}

function openCredentialsModal() {
  $("credentials_error").style.display = "none";
  $("credentials_success").style.display = "none";
  $("credentials_form").reset();
  if (state) {
    $("cred_username").value = state.username || "";
    $("cred_password").value = "";
    $("cred_port").value = state.port || 8787;
    $("cred_suffix").value = state.secret_path || "";
  }
  $("credentials_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeCredentialsModal() {
  $("credentials_modal").style.display = "none";
}

async function saveCredentials(e) {
  e.preventDefault();
  const errorDivEl = $("credentials_error");
  const successDiv = $("credentials_success");
  const submitBtn = $("credentials_submit_btn");

  errorDivEl.style.display = "none";
  successDiv.style.display = "none";

  const username = $("cred_username").value.trim();
  const password = $("cred_password").value.trim();
  const port = parseInt($("cred_port").value);
  const suffix = $("cred_suffix").value.trim();

  if (!username || (!password && !(state && state.password_set))) {
    errorDivEl.textContent = "用户名不能为空；首次设置时密码不能为空";
    errorDivEl.style.display = "block";
    return;
  }

  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "网页管理端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }

  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }

  if (state && port === state.proxy_port) {
    errorDivEl.textContent = "网页管理端口不能与代理出站端口相同";
    errorDivEl.style.display = "block";
    return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";

  try {
    const res = await fetch("./api/update_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: username,
        password: password,
        port: port,
        secret_path: suffix
      })
    });

    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！网页管理端口或路径已变更，页面将在 4 秒内自动跳转...";
        successDiv.style.display = "block";

        const inputs = $("credentials_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);

        setTimeout(() => {
          const protocol = window.location.protocol;
          const host = window.location.hostname;
          window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
        }, 4000);
      } else {
        successDiv.textContent = data.reauth_required ? "账号密码保存成功，请重新登录..." : "账号密码保存成功，已即时生效！";
        successDiv.style.display = "block";
        setTimeout(() => {
          if (data.reauth_required) {
            window.location.reload();
          } else {
            closeCredentialsModal();
            load();
          }
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

function openNetworkModal() {
  $("network_error").style.display = "none";
  $("network_success").style.display = "none";
  $("network_form").reset();

  if (state) {
    $("net_proxy_port").value = state.proxy_port || 7928;
    const mode = state.routing_mode || "auto";
    const ipType = state.routing_ip_type || "all";

    selectOptionCard('routing_mode', mode);
    selectOptionCard('routing_ip_type', ipType);
  }

  populateRoutingCountries();
  $("network_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeNetworkModal() {
  $("network_modal").style.display = "none";
}

async function saveNetwork(e) {
  e.preventDefault();
  const errorDivEl = $("network_error");
  const successDiv = $("network_success");
  const submitBtn = $("network_submit_btn");

  errorDivEl.style.display = "none";
  successDiv.style.display = "none";

  const proxyPort = parseInt($("net_proxy_port").value);
  const routingMode = $("net_routing_mode").value;
  const forceCountry = $("net_force_country").value;
  const routingIpType = $("net_routing_ip_type").value;

  if (isNaN(proxyPort) || proxyPort < 1024 || proxyPort > 65535) {
    errorDivEl.textContent = "代理出站端口范围必须在 1024 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }

  if (state && proxyPort === state.port) {
    errorDivEl.textContent = "代理出站端口不能与网页管理端口相同";
    errorDivEl.style.display = "block";
    return;
  }

  if (routingMode === "fixed_region" && !forceCountry) {
    errorDivEl.textContent = "请选择一个要锁定的目标国家";
    errorDivEl.style.display = "block";
    return;
  }
  if (routingMode === "fixed_ip" && !(state && (state.active_openvpn_node_id || state.fixed_node_id))) {
    errorDivEl.textContent = "启用固定 IP 前，请先连接一个要锁定的节点";
    errorDivEl.style.display = "block";
    return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";

  try {
    const res = await fetch("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        proxy_port: proxyPort,
        routing_mode: routingMode,
        force_country: forceCountry,
        routing_ip_type: routingIpType
      })
    });

    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！代理出站端口已变更，页面将在 4 秒内自动刷新...";
        successDiv.style.display = "block";

        const inputs = $("network_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);

        setTimeout(() => {
          window.location.reload();
        }, 4000);
      } else {
        successDiv.textContent = "配置保存成功，已即时生效！";
        successDiv.style.display = "block";
        setTimeout(() => {
          closeNetworkModal();
          load();
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}




async function logoutAdmin() {
  try {
    const res = await fetch("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

// 页面加载时自动初始化数据
load();

// 每 10 秒在前台空闲时自动更新节点与状态，无需手动刷新页面
setInterval(async () => {
  if (typeof state !== "undefined" && !state.is_connecting && (!testingNodeIds || !testingNodeIds.size) && document.visibilityState === "visible") {
    try {
      const r = await fetch("./api/nodes");
      const d = await r.json();
      nodes = d.nodes || [];
      state = d.state || {};
      stableSortNodes();
      updateCountryFilter();
      render();
    } catch(e) {}
  }
}, 10000);
let gatewayPollInterval = null;

function openGatewayModal() {
  $("admin_dropdown").style.display = "none";
  $("gateway_modal").style.display = "flex";
  loadGatewayStatus();
  if (gatewayPollInterval) clearInterval(gatewayPollInterval);
  gatewayPollInterval = setInterval(loadGatewayStatus, 3000);
}

function closeGatewayModal() {
  $("gateway_modal").style.display = "none";
  if (gatewayPollInterval) {
    clearInterval(gatewayPollInterval);
    gatewayPollInterval = null;
  }
}

async function loadGatewayStatus() {
  try {
    const res = await fetch("./api/gateway_status");
    const data = await res.json();
    if (data.ok && data.services) {
      renderGatewayServices(data.services);
    }
  } catch (e) {
    console.error("加载网关状态失败", e);
  }
}

function renderGatewayServices(services) {
  const container = $("gateway_services_list");
  if (!container) return;

  let html = "";
  services.forEach(s => {
    const statusText = s.status === "running" ? "正在运行" : "已停止";
    const badgeClass = s.status === "running" ? "available" : "unavailable";
    const statusPulse = s.status === "running" ? '<span class="badge-pulse"></span>' : '';

    html += `
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 10px; padding: 12px 16px; display: flex; flex-direction: column; gap: 6px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 14px; color: var(--text-primary);">${esc(s.name)}</strong>
          <span class="badge ${badgeClass}">${statusPulse}${statusText}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary);">${esc(s.details || "-")}</div>
        ${s.error ? `
          <div style="font-size: 12px; color: var(--danger); background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.15); border-radius: 6px; padding: 6px 10px; margin-top: 4px; line-height: 1.4;">
            ⚠️ 诊断原因: ${esc(s.error)}
          </div>
        ` : ''}
      </div>
    `;
  });
  container.innerHTML = html;
}

let logsPollInterval = null;
let rawLogsCache = [];

function openLogsModal() {
  $("admin_dropdown").style.display = "none";
  $("logs_modal").style.display = "flex";
  loadLogs();
  if (logsPollInterval) clearInterval(logsPollInterval);
  logsPollInterval = setInterval(loadLogs, 2500);
}

function closeLogsModal() {
  $("logs_modal").style.display = "none";
  if (logsPollInterval) {
    clearInterval(logsPollInterval);
    logsPollInterval = null;
  }
}

async function loadLogs() {
  try {
    const res = await fetch("./api/logs");
    const data = await res.json();
    if (data.logs) {
      rawLogsCache = data.logs;
      filterAndRenderLogs();
    }
  } catch (e) {
    console.error("加载日志失败", e);
  }
}

function filterAndRenderLogs() {
  const filterVal = $("log_filter_select").value;
  const term = $("log_terminal_container");
  if (!term) return;

  let filtered = rawLogsCache;
  if (filterVal === "proxy") {
    filtered = rawLogsCache.filter(l => l.module === "Proxy");
  } else if (filterVal === "vpn") {
    filtered = rawLogsCache.filter(l => l.module === "VPN");
  } else if (filterVal === "system") {
    filtered = rawLogsCache.filter(l => !["Proxy", "VPN"].includes(l.module));
  }

  if (filtered.length === 0) {
    term.innerHTML = `<div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">暂无该类型日志。</div>`;
    return;
  }

  const linesHtml = filtered.map(l => {
    let color = "#a5b4fc";
    if (l.module === "Proxy") color = "#38bdf8";
    if (l.module === "VPN") color = "#34d399";
    if (l.level === "WARNING") color = "#fbbf24";
    if (l.level === "ERROR") color = "#f43f5e";

    return `<div style="color: ${color}; margin-bottom: 4px;">[${esc(l.timestamp)}] [${esc(l.level)}] [${esc(l.module)}] ${esc(l.message)}</div>`;
  }).join("");

  const isAtBottom = term.scrollHeight - term.clientHeight <= term.scrollTop + 50;

  term.innerHTML = linesHtml;

  if (isAtBottom) {
    term.scrollTop = term.scrollHeight;
  }
}

function copyLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;

  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供复制的日志。");
    return;
  }

  navigator.clipboard.writeText(text).then(() => {
    alert("日志内容已成功复制到剪贴板！");
  }).catch(err => {
    console.error("复制失败", err);
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("日志内容已复制到剪贴板！");
  });
}

function exportLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;

  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供导出的日志。");
    return;
  }

  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const dateStr = new Date().toISOString().slice(0, 10);
  const filterVal = $("log_filter_select").value;
  a.download = `vpngate_log_${filterVal}_${dateStr}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
</script>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(1.5)
        connect_host = LOCAL_PROXY_HOST
        if connect_host in ("::", "0.0.0.0", ""):
            connect_host = "::1" if is_ipv6 else "127.0.0.1"
        try:
            s.connect((connect_host, LOCAL_PROXY_PORT))
        except Exception as e:
            if connect_host == "::1":
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
            else:
                raise e
    except Exception as e:
        diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
        diag_msg = diag[1] if diag else f"端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e}"
        return {
            "ok": False,
            "error": f"代理服务未运行 ({diag_msg})"
        }
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # 2. 检测虚拟网卡 tun0 是否存在 (Linux 下)
    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        proxy_hosts = []
        if LOCAL_PROXY_HOST == "::":
            proxy_hosts = ["[::1]", "127.0.0.1"]
        elif LOCAL_PROXY_HOST == "0.0.0.0":
            proxy_hosts = ["127.0.0.1"]
        elif ":" in LOCAL_PROXY_HOST:
            proxy_hosts = [f"[{LOCAL_PROXY_HOST}]", "127.0.0.1"]
        else:
            proxy_hosts = [LOCAL_PROXY_HOST]

        for p_host in proxy_hosts:
            proxy_url = f"socks5h://{p_host}:{LOCAL_PROXY_PORT}"
            proxy_user, proxy_pass = proxy_server.get_proxy_credentials()
            cmd = [
                "curl", "-s",
                "-w", "\n%{time_total} %{http_code}",
                "-x", proxy_url,
                url,
                "--max-time", "5"
            ]
            if proxy_user is not None and proxy_pass is not None:
                cmd.extend(["--proxy-user", f"{proxy_user}:{proxy_pass}"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    lines = res.stdout.strip().splitlines()
                    if len(lines) >= 2:
                        ip = lines[0].strip()
                        time_info = lines[1].strip().split()
                        if len(time_info) == 2:
                            total_time_str, http_code = time_info
                            if http_code == "200" and ip:
                                latency_ms = int(float(total_time_str) * 1000)
                                return {"ok": True, "ip": ip, "latency_ms": latency_ms}
            except Exception:
                pass
        return None

    try:
        result = _curl_check_ip("http://ip.sb")
        if result:
            return result
        result = _curl_check_ip("http://api.ipify.org")
        if result:
            return result

        # 此时外网测试失败，检测本地代理端口是否依然能连通。若仍能连通，直接抛出出口测试失败，不调用占用诊断
        port_still_listening = False
        test_sock = None
        try:
            test_sock = socket.socket(af, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                test_sock.connect((connect_host, LOCAL_PROXY_PORT))
                port_still_listening = True
            except Exception:
                if connect_host == "::1":
                    test_sock.close()
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(1.0)
                    test_sock.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                    port_still_listening = True
        except Exception:
            pass
        finally:
            if test_sock is not None:
                try:
                    test_sock.close()
                except Exception:
                    pass

        if not port_still_listening:
            diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
            if diag:
                return {"ok": False, "error": f"出口连接测试失败 | 本机诊断结果: {diag[1]}"}

        return {"ok": False, "error": "出口连接测试失败 (ip.sb 和 api.ipify.org 均无法连通，可能是节点已失效或 VPS 防火墙限制了 UDP/TCP 出站端口)"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting
    time.sleep(30)
    while True:
        last_checker_heartbeat = time.time()
        try:
            if is_connecting:
                time.sleep(5)
                continue

            res = check_proxy_health()
            if res["ok"]:
                exit_metadata = inspect_exit_ip(res["ip"])
                exit_rejection = ""
                if active_openvpn_node_id:
                    with lock:
                        nodes = read_nodes()
                        active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                        if active_node:
                            apply_exit_metadata_to_node(active_node, exit_metadata)
                            ui_cfg = load_ui_config()
                            try:
                                validate_exit_allowed_by_routing(active_node, ui_cfg)
                            except Exception as exit_exc:
                                exit_rejection = str(exit_exc)
                                active_node["probe_status"] = "unavailable"
                                active_node["probe_message"] = exit_rejection
                                mark_blacklisted(active_node, exit_rejection)
                            write_json(NODES_FILE, nodes)

                if exit_rejection:
                    log_to_json("WARNING", "ExitValidation", f"活动节点被拒绝: {exit_rejection}")
                    set_state(
                        proxy_ok=False,
                        proxy_ip=res["ip"],
                        proxy_latency_ms=res["latency_ms"],
                        proxy_error=exit_rejection,
                        last_check_message=exit_rejection,
                    )
                    auto_switch_node()
                    time.sleep(5)
                    continue

                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error="",
                    exit_country=exit_metadata.get("exit_country", ""),
                    exit_country_short=exit_metadata.get("exit_country_short", ""),
                    exit_location=exit_metadata.get("exit_location", ""),
                    exit_ip_type=exit_metadata.get("exit_ip_type", ""),
                )
                log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
            else:
                error_msg = res.get("error", "未知错误")
                if active_openvpn_node_id:
                    print(f"[警告] {LOCAL_PROXY_PORT} 端口本地代理当前不可用！原因: {error_msg}", flush=True)
                    log_to_json("WARNING", "Proxy", f"代理不可用: {error_msg}")
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg
                )

                # If we intended to have an active VPN node but proxy failed, trigger auto-switch
                if active_openvpn_node_id:
                    ui_cfg = load_ui_config()
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    if routing_mode != "fixed_ip":
                        with lock:
                            nodes = read_nodes()
                            active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                            if active_node:
                                mark_blacklisted(active_node, f"代理连通性检测失败: {error_msg}")
                                active_node["probe_status"] = "unavailable"
                                write_json(NODES_FILE, nodes)
                        auto_switch_node()
                    else:
                        print(f"[代理守护线程] 固定 IP 模式下代理不可用，正在尝试重启连接同一节点: {active_openvpn_node_id}", flush=True)
                        is_connecting = False
                        try:
                            connect_node(active_openvpn_node_id)
                        except Exception as e:
                            print(f"[代理守护线程] 重启固定节点失败: {e}", flush=True)
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    global last_pinger_heartbeat
    while True:
        last_pinger_heartbeat = time.time()
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                nodes = read_nodes()
                node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            set_state(active_node_latency=f"{latency} ms")
                        else:
                            set_state(active_node_latency="检测超时")
                    else:
                        set_state(active_node_latency="检测超时")
                else:
                    set_state(active_node_latency="检测超时")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


class BundleHandler(BaseHTTPRequestHandler):
    """Token-protected public endpoint for the combined client subscriptions."""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[总订阅 {self.log_date_time_string()}] {format % args}", flush=True)

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        token = ensure_bundle_token()
        universal_path = f"/all/{token}"
        clash_path = f"/all-clash/{token}"
        if not (secrets.compare_digest(path, universal_path) or secrets.compare_digest(path, clash_path)):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            if path == clash_path:
                body = aggregate_clash_subscription()
                content_type = "text/yaml; charset=utf-8"
            else:
                body = aggregate_universal_subscription()
                content_type = "text/plain; charset=utf-8"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Profile-Update-Interval", "12")
            self.send_header("Content-Disposition", 'inline; filename="aimilivpn-all.yaml"' if path == clash_path else 'inline; filename="aimilivpn-all.txt"')
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            print(f"[总订阅] 生成失败: {exc}", flush=True)
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)


def start_bundle_server() -> None:
    settings = xui_subscription_settings()
    cert_file = settings.get("subCertFile", "")
    key_file = settings.get("subKeyFile", "")
    if not cert_file or not key_file or not Path(cert_file).exists() or not Path(key_file).exists():
        print("[总订阅] 未找到 3x-ui 订阅证书，统一订阅服务未启动。", flush=True)
        return
    server = DualStackHTTPServer(("::", BUNDLE_PORT), BundleHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"[总订阅] HTTPS 服务已监听端口 {BUNDLE_PORT}。", flush=True)
    server.serve_forever()


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        ui_cfg = load_ui_config()
        return ui_cfg.get("secret_path", "EJsW2EeBo9lY")

    def is_authorized(self) -> bool:
        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            print("[Auth] 管理后台密码为空，已拒绝访问。请检查 ui_auth.json。", flush=True)
            return False

        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()

        session_token = cookies.get("session")
        if not session_token:
            return False

        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        request_path = urllib.parse.urlsplit(self.path).path
        if not secret_path:
            return request_path
        if request_path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if request_path.startswith(prefix):
            return "/" + request_path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def read_request_body(self, max_bytes: int = 65536) -> bytes:
        length = parse_int(self.headers.get("Content-Length"))
        if length < 0:
            raise ValueError("Content-Length 无效")
        if length > max_bytes:
            raise ValueError(f"请求体过大，最大允许 {max_bytes} 字节")
        return self.rfile.read(length) if length > 0 else b""

    def read_json_body(self, max_bytes: int = 65536) -> dict[str, Any]:
        body = self.read_request_body(max_bytes)
        if not body:
            return {}
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求 JSON 必须是对象")
        return data

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return

        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return

        if effective_path in ("/", "/index.html"):
            bootstrap_json = json.dumps(fast_multi_exit_bootstrap_payload(), ensure_ascii=False).replace("</", "<\\/")
            page = INDEX_HTML.replace("__MULTI_EXIT_BOOTSTRAP_JSON__", bootstrap_json)
            self.send_bytes(page.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/api/nodes":
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            nodes = read_nodes()
            active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = (active_openvpn_node_id and n.get("id") == active_openvpn_node_id)
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping,
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_nodes()
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            config_text = node_config_text(node) if node else ""
            if config_text:
                self.send_bytes(config_text.encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        elif effective_path == "/api/multi_exit":
            self.send_json(multi_exit_payload())
        elif effective_path == "/api/gateway_status":
            web_ui_status = {
                "name": "Web 管理服务",
                "status": "running",
                "details": f"监听地址: {load_ui_config().get('host', UI_HOST)}:{load_ui_config().get('port', UI_PORT)}",
                "error": ""
            }
            proxy_ok = False
            proxy_err = ""
            is_ipv6 = ":" in LOCAL_PROXY_HOST
            af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(0.5)
                connect_host = LOCAL_PROXY_HOST
                if connect_host in ("::", "0.0.0.0", ""):
                    connect_host = "::1" if is_ipv6 else "127.0.0.1"
                try:
                    s.connect((connect_host, LOCAL_PROXY_PORT))
                    proxy_ok = True
                except Exception:
                    if connect_host == "::1":
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        proxy_ok = True
                    else:
                        raise
            except Exception as e:
                diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
                proxy_err = diag[1] if diag else f"本地代理网关无法连通: {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            proxy_gateway_status = {
                "name": "本地代理网关",
                "status": "running" if proxy_ok else "stopped",
                "details": f"监听地址: {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
                "error": proxy_err
            }
            ovpn_ok = active_openvpn_running()
            ovpn_err = ""
            ovpn_details = "未连接"
            if ovpn_ok:
                ovpn_details = f"已连接节点: {active_openvpn_node_id}"
                if sys.platform.startswith("linux"):
                    if not Path("/sys/class/net/tun0").exists():
                        ovpn_err = "[警告] 虚拟网卡 (tun0) 未启用，可能存在策略路由配置问题。"
            else:
                if active_openvpn_node_id:
                    ovpn_err = "连接已中断或 OpenVPN 核心程序异常退出。"
                    ovpn_details = f"尝试连接节点 {active_openvpn_node_id} 失败"
            openvpn_status = {
                "name": "OpenVPN 核心连接",
                "status": "running" if ovpn_ok else "stopped",
                "details": ovpn_details,
                "error": ovpn_err
            }
            now = time.time()
            server_uptime = now - server_start_time
            collector_ok = (last_collector_heartbeat > 0.0 and now - last_collector_heartbeat < (CHECK_INTERVAL_SECONDS * 1.5)) or (server_uptime < 15.0)
            collector_status = {
                "name": "节点同步守护线程",
                "status": "running" if collector_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_collector_heartbeat)) if last_collector_heartbeat > 0 else '等待启动'}",
                "error": "" if collector_ok else "线程可能已异常终止，导致无法在后台拉取和测速新节点。"
            }
            checker_ok = (last_checker_heartbeat > 0.0 and now - last_checker_heartbeat < 90.0) or (server_uptime < 35.0)
            checker_status = {
                "name": "出口检测守护线程",
                "status": "running" if checker_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_checker_heartbeat)) if last_checker_heartbeat > 0 else '等待启动'}",
                "error": "" if checker_ok else "线程可能已挂起或终止，导致无法实时获取代理出口状态。"
            }
            pinger_ok = (last_pinger_heartbeat > 0.0 and now - last_pinger_heartbeat < 30.0) or (server_uptime < 15.0)
            pinger_status = {
                "name": "延迟测速守护线程",
                "status": "running" if pinger_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pinger_heartbeat)) if last_pinger_heartbeat > 0 else '等待启动'}",
                "error": "" if pinger_ok else "线程可能已中止，无法实时刷新活动节点的 Ping 延迟。"
            }
            self.send_json({
                "ok": True,
                "services": [
                    web_ui_status,
                    proxy_gateway_status,
                    openvpn_status,
                    collector_status,
                    checker_status,
                    pinger_status
                ]
            })
        elif effective_path == "/api/logs":
            logs_dir = DATA_DIR / "logs"
            date_str = time.strftime("%Y-%m-%d", time.localtime())
            log_file = logs_dir / f"{date_str}.json"
            entries = []
            if log_file.exists():
                try:
                    with lock:
                        with open(log_file, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        entries.append(json.loads(line))
                                    except Exception:
                                        pass
                except Exception as e:
                    print(f"[API Logs] Error reading log file: {e}", flush=True)
            self.send_json({"logs": entries})
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        global is_connecting
        effective_path = self.validate_path()
        if effective_path == "": return

        if effective_path == "/api/login":
            try:
                payload = self.read_json_body()
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")

                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")

                if expected_pwd and input_pwd == expected_pwd and input_uname == expected_uname:
                    token = uuid.uuid4().hex
                    with lock:
                        active_sessions[token] = time.time() + 30 * 24 * 3600
                    body = json.dumps({"ok": True}).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/update_direct_protocol":
            try:
                payload = self.read_json_body()
                protocol = str(payload.get("protocol") or "").lower()
                if protocol not in ("vless", "trojan", "hysteria"):
                    raise ValueError("协议必须是 VLESS、Trojan 或 HY2")
                config = read_multi_exit_config()
                old_config = json.loads(json.dumps(config, ensure_ascii=False))
                config["direct_protocol"] = protocol
                write_json(MULTI_EXIT_DIR / "channels.json", config)
                provision = Path("/usr/local/sbin/xui-multi-provision")
                subprocess.run(["systemctl", "stop", "x-ui"], check=True, timeout=20)
                try:
                    subprocess.run([str(provision), "--channels", str(MULTI_EXIT_DIR / "channels.json"), "--direct-only"], check=True, timeout=60)
                except Exception:
                    write_json(MULTI_EXIT_DIR / "channels.json", old_config)
                    raise
                finally:
                    subprocess.run(["systemctl", "start", "x-ui"], check=False, timeout=20)
                self.send_json({"ok": True, "message": "VPS 直连协议已单独保存；国家线路配置未重建。请在客户端更新订阅。"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/update_multi_exit_channel":
            try:
                payload = self.read_json_body()
                channel_id = re.sub(r"[^a-z0-9-]", "", str(payload.get("id") or "").lower())[:12]
                if not channel_id:
                    raise ValueError("线路 ID 无效")
                country = str(payload.get("country") or "").strip()
                port = int(payload.get("inbound_port") or 0)
                protocol = str(payload.get("protocol") or "hysteria").lower()
                ip_type = str(payload.get("ip_type") or "all")
                if not country or not 1024 <= port <= 65535:
                    raise ValueError("国家或端口无效")
                if protocol not in ("vless", "trojan", "hysteria"):
                    raise ValueError("协议必须是 VLESS、Trojan 或 HY2")
                if ip_type not in ("all", "residential_preferred", "residential_only", "hosting_only"):
                    raise ValueError("IP 类型策略无效")
                country_nodes = channel_candidate_nodes({"country": country})
                preferred_was_supplied = "preferred_node_id" in payload
                requested_preferred = str(payload.get("preferred_node_id") or "").strip()
                if not country_nodes:
                    raise ValueError("当前节点资料中没有该国家，请先更新节点资料")
                config = read_multi_exit_config()
                old_config = json.loads(json.dumps(config, ensure_ascii=False))
                is_new_channel = False
                country_changed = False
                try:
                    index, old_channel = find_multi_channel(config, channel_id)
                    updated = dict(old_channel)
                    if normalized_country_name(old_channel.get("country")) != normalized_country_name(country):
                        updated["preferred_node_id"] = ""
                        country_changed = True
                except ValueError:
                    is_new_channel = True
                    if len(config.get("channels", [])) >= 12:
                        raise ValueError("最多允许 12 条国家线路")
                    if any(normalized_country_name(item.get("country")) == normalized_country_name(country) for item in config.get("channels", [])):
                        raise ValueError("该国家已经存在独立出口")
                    index = len(config.setdefault("channels", []))
                    updated = {"id": channel_id, "enabled": True, "preferred_node_id": ""}
                    config["channels"].append(updated)
                if any(str(item.get("id")) != channel_id and int(item.get("inbound_port") or 0) == port for item in config.get("channels", [])):
                    raise ValueError("该端口已被其他国家线路使用")
                if is_new_channel or country_changed:
                    channel_name = generated_channel_name(country, country_nodes)
                else:
                    channel_name = str(updated.get("name") or payload.get("name") or country + "线路")[:30]
                updated.update({
                    "id": channel_id, "name": channel_name,
                    "country": country, "inbound_port": port, "protocol": protocol,
                    "ip_type": ip_type, "enabled": True, "restart_token": time.time(),
                })
                if preferred_was_supplied:
                    if requested_preferred and not any(
                        str(node.get("id") or "") == requested_preferred for node in country_nodes
                    ):
                        raise ValueError("The selected IP is not a candidate for this country")
                    updated["preferred_node_id"] = requested_preferred
                if is_new_channel or country_changed:
                    updated["created_at"] = time.time()
                    updated["awaiting_initial_test"] = True
                    updated["tested_only"] = True
                    updated.pop("initial_test_completed_at", None)
                config["channels"][index] = updated
                config["version"] = max(3, int(config.get("version") or 1))
                write_json(MULTI_EXIT_DIR / "channels.json", config)
                provision = Path("/usr/local/sbin/xui-multi-provision")
                subprocess.run(["systemctl", "stop", "x-ui"], check=True, timeout=20)
                try:
                    subprocess.run([str(provision), "--channels", str(MULTI_EXIT_DIR / "channels.json"), "--channel-id", channel_id], check=True, timeout=60)
                except Exception:
                    write_json(MULTI_EXIT_DIR / "channels.json", old_config)
                    raise
                finally:
                    subprocess.run(["systemctl", "start", "x-ui"], check=False, timeout=20)
                if shutil.which("ufw"):
                    status = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10)
                    if "Status: active" in status.stdout:
                        transport = "udp" if protocol == "hysteria" else "tcp"
                        subprocess.run(["ufw", "allow", f"{port}/{transport}"], check=False, timeout=15)
                if is_new_channel or country_changed:
                    ensure_channel_bootstrap(channel_id)
                    message = f"{country}线路已创建，正在优先检测本国节点；完成后会按所选 IP 类型自动连接"
                else:
                    message = f"{country}线路已单独保存并应用，其他国家配置未重建"
                self.send_json({"ok": True, "message": message, "initial_test_started": bool(is_new_channel or country_changed)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/delete_multi_exit_channel":
            try:
                payload = self.read_json_body()
                channel_id = re.sub(r"[^a-z0-9-]", "", str(payload.get("channel_id") or "").lower())[:12]
                if not channel_id:
                    raise ValueError("线路 ID 无效")
                with multi_config_lock:
                    config = read_multi_exit_config()
                    index, channel = find_multi_channel(config, channel_id)
                    old_config = json.loads(json.dumps(config, ensure_ascii=False))
                    config["channels"].pop(index)
                    config["version"] = max(5, int(config.get("version") or 1))
                    write_json(MULTI_EXIT_DIR / "channels.json", config)
                    provision = Path("/usr/local/sbin/xui-multi-provision")
                    subprocess.run(["systemctl", "stop", "x-ui"], check=True, timeout=20)
                    try:
                        subprocess.run([
                            str(provision), "--channels", str(MULTI_EXIT_DIR / "channels.json"),
                            "--delete-channel-id", channel_id,
                        ], check=True, timeout=60)
                    except Exception:
                        write_json(MULTI_EXIT_DIR / "channels.json", old_config)
                        try:
                            subprocess.run([
                                str(provision), "--channels", str(MULTI_EXIT_DIR / "channels.json"),
                                "--channel-id", channel_id,
                            ], check=True, timeout=60)
                        except Exception as restore_exc:
                            log_to_json("ERROR", "DeleteChannel", f"恢复 {channel_id} 失败：{restore_exc}")
                        raise
                    finally:
                        subprocess.run(["systemctl", "start", "x-ui"], check=False, timeout=20)
                subprocess.run(["systemctl", "restart", "aimilivpn-multiexit"], check=False, timeout=30)
                if shutil.which("ufw"):
                    status = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10)
                    if "Status: active" in status.stdout:
                        transport = "udp" if str(channel.get("protocol") or "") == "hysteria" else "tcp"
                        subprocess.run([
                            "ufw", "--force", "delete", "allow",
                            f"{int(channel.get('inbound_port') or 0)}/{transport}",
                        ], check=False, timeout=15)
                main_state = read_json(STATE_FILE, {})
                channel_results = main_state.get("channel_test_results") or {}
                channel_results.pop(channel_id, None)
                set_state(channel_test_results=channel_results)
                self.send_json({
                    "ok": True,
                    "message": (
                        f"已删除{channel.get('country')}通道：3x-ui 端口 {channel.get('inbound_port')} 的入站、"
                        "客户端、路由、出站和订阅记录均已同步删除"
                    ),
                })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/switch_multi_exit_node":
            try:
                payload = self.read_json_body()
                channel_id = str(payload.get("channel_id") or "").strip()
                node_id = str(payload.get("node_id") or "").strip()
                config = read_multi_exit_config()
                index, channel = find_multi_channel(config, channel_id)
                candidate = next((node for node in channel_candidate_nodes(channel) if node.get("id") == node_id), None)
                if not candidate:
                    raise ValueError("所选 IP 不属于当前国家")
                mode = str(channel.get("ip_type") or "all")
                if mode == "residential_only" and candidate.get("ip_type") not in ("residential", "mobile"):
                    raise ValueError("当前线路仅允许住宅 IP")
                if mode == "hosting_only" and candidate.get("ip_type") != "hosting":
                    raise ValueError("当前线路仅允许机房 IP")
                channel["preferred_node_id"] = node_id
                channel["restart_token"] = time.time()
                config["channels"][index] = channel
                write_json(MULTI_EXIT_DIR / "channels.json", config)
                self.send_json({"ok": True, "message": f"已要求{channel.get('country')}线路切换到 {candidate.get('ip') or node_id}；若该 IP 失败，将按本线路策略选择同国备用节点"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/test_multi_exit_channel":
            try:
                payload = self.read_json_body()
                channel_id = str(payload.get("channel_id") or "").strip()
                config = read_multi_exit_config()
                _, channel = find_multi_channel(config, channel_id)
                count = len(channel_candidate_nodes(channel))
                if count < 1:
                    raise ValueError("该国家暂无候选节点，请先点击顶部更新节点资料")
                if maintenance_lock.locked():
                    current = read_json(STATE_FILE, {})
                    self.send_json({
                        "ok": False,
                        "error": str(current.get("last_check_message") or "已有节点任务正在运行，请稍后再试"),
                    }, HTTPStatus.CONFLICT)
                else:
                    set_state(
                        maintenance_task="channel_availability_queued",
                        maintenance_channel_id=channel_id,
                        last_check_message=f"正在启动{channel.get('country')}节点检测，共 {count} 个候选节点...",
                    )
                    threading.Thread(target=run_channel_availability, args=(channel_id,), daemon=True).start()
                    self.send_json({"ok": True, "running": True, "count": count, "message": f"已开始仅检测{channel.get('country')}的 {count} 个候选节点"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/update_multi_exit":
            try:
                payload = self.read_json_body()
                channels = payload.get("channels")
                direct_protocol = str(payload.get("direct_protocol") or "hysteria").lower()
                if direct_protocol not in ("vless", "trojan", "hysteria"):
                    raise ValueError("Invalid direct protocol")
                if not isinstance(channels, list) or len(channels) > 12:
                    self.send_json({"ok": False, "error": "通道必须是列表，最多 12 条"}, HTTPStatus.BAD_REQUEST)
                    return
                normalized = []
                ids, ports = set(), set()
                for index, item in enumerate(channels, 1):
                    if not isinstance(item, dict):
                        raise ValueError("通道格式无效")
                    cid = re.sub(r"[^a-z0-9-]", "", str(item.get("id") or f"line{index}").lower())[:12]
                    country = str(item.get("country") or "").strip()
                    port = int(item.get("inbound_port") or 0)
                    ip_type = str(item.get("ip_type") or "all")
                    protocol = str(item.get("protocol") or "hysteria").lower()
                    if not cid or cid in ids or not country or port in ports or not 1024 <= port <= 65535:
                        raise ValueError("通道 ID、国家或端口无效/重复")
                    if ip_type not in ("all", "residential_preferred", "residential_only", "hosting_only"):
                        raise ValueError("IP 类型策略无效")
                    if protocol not in ("vless", "trojan", "hysteria"):
                        raise ValueError("Invalid channel protocol")
                    ids.add(cid); ports.add(port)
                    normalized.append({"id": cid, "name": str(item.get("name") or country + "线路")[:30], "inbound_port": port, "country": country, "protocol": protocol, "ip_type": ip_type, "enabled": bool(item.get("enabled", True))})
                multi_dir = Path("/var/lib/aimilivpn-multiexit")
                multi_dir.mkdir(parents=True, exist_ok=True)
                write_json(multi_dir / "channels.json", {"version": 2, "direct_protocol": direct_protocol, "channels": normalized})
                provision = Path("/usr/local/sbin/xui-multi-provision")
                if provision.exists() and Path("/etc/x-ui/x-ui.db").exists():
                    subprocess.run(["systemctl", "stop", "x-ui"], check=True, timeout=20)
                    try:
                        subprocess.run([str(provision), "--channels", str(multi_dir / "channels.json")], check=True, timeout=60)
                    finally:
                        subprocess.run(["systemctl", "start", "x-ui"], check=False, timeout=20)
                if shutil.which("ufw"):
                    ufw_status = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10)
                    if "Status: active" in ufw_status.stdout:
                        direct = get_direct_node_status()
                        direct_transport = "udp" if direct_protocol == "hysteria" else "tcp"
                        if direct.get("port"):
                            subprocess.run(["ufw", "allow", f"{int(direct['port'])}/{direct_transport}"], check=False, timeout=15)
                        for item in normalized:
                            transport = "udp" if item["protocol"] == "hysteria" else "tcp"
                            subprocess.run(["ufw", "allow", f"{item['inbound_port']}/{transport}"], check=False, timeout=15)
                subprocess.run(["systemctl", "restart", "aimilivpn-multiexit"], check=False, timeout=20)
                self.send_json({"ok": True, "message": "多国家通道已保存并重新加载"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/update_credentials":
            try:
                payload = self.read_json_body()
                new_username = str(payload.get("username") or "").strip()
                new_password = str(payload.get("password") or "").strip()
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()

                ui_cfg = load_ui_config()
                if not new_username or (not new_password and not ui_cfg.get("password")):
                    self.send_json({"ok": False, "error": "用户名不能为空；首次设置时密码不能为空"}, HTTPStatus.BAD_REQUEST)
                    return

                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "网页管理端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return

                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return

                expected_username = ui_cfg.get("username", "")
                expected_password = ui_cfg.get("password", "")
                expected_port = ui_cfg.get("port", 8787)
                expected_suffix = ui_cfg.get("secret_path", "EJsW2EeBo9lY")

                ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix

                auth_file = DATA_DIR / "ui_auth.json"
                reauth_required = new_username != expected_username or (new_password and new_password != expected_password)
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                    if reauth_required:
                        active_sessions.clear()

                restart_needed = (new_port_int != expected_port or new_suffix != expected_suffix)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "reauth_required": reauth_required, "message": "配置更新成功，网页管理端口或路径已变更，将在 2 秒内重启..."})

                    def restart_server():
                        time.sleep(2)
                        print("[系统] 管理后台安全配置更新，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)

                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    self.send_json({"ok": True, "restart_needed": False, "reauth_required": reauth_required, "message": "账号密码配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_settings":
            try:
                payload = self.read_json_body()

                new_proxy_port = payload.get("proxy_port")
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()

                try:
                    new_proxy_port_int = int(new_proxy_port)
                    if not (1024 <= new_proxy_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "代理出站端口范围必须是 1024 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return

                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_region" and not force_country:
                    self.send_json({"ok": False, "error": "启用固定地区前，请先选择一个要锁定的国家"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg = load_ui_config()
                expected_proxy_port = ui_cfg.get("proxy_port", 7928)
                fixed_node_id = current_fixed_node_id(ui_cfg) if routing_mode == "fixed_ip" else ""

                if new_proxy_port_int == ui_cfg.get("port", 8787):
                    self.send_json({"ok": False, "error": "代理出站端口不能与网页管理端口相同"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_ip" and not fixed_node_id:
                    self.send_json({"ok": False, "error": "启用固定 IP 前，请先连接一个要锁定的节点"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg["proxy_port"] = new_proxy_port_int
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                if routing_mode == "favorites":
                    ui_cfg["fav_fail_fallback"] = False
                if routing_mode == "fixed_ip":
                    ui_cfg["fixed_node_id"] = fixed_node_id

                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "路由设置已更新")

                restart_needed = (new_proxy_port_int != expected_proxy_port)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "message": "配置更新成功，代理出站端口变更，将在 2 秒内重启..."})

                    def restart_server():
                        time.sleep(2)
                        print("[系统] 代理出站端口变更，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)

                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    message = policy_message or "配置更新成功，已即时生效！"
                    self.send_json({"ok": True, "restart_needed": False, "message": message})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_routing":
            try:
                payload = self.read_json_body()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                fav_fail_fallback = False

                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_region" and not force_country:
                    self.send_json({"ok": False, "error": "启用固定地区前，请先选择一个要锁定的国家"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg = load_ui_config()
                fixed_node_id = current_fixed_node_id(ui_cfg) if routing_mode == "fixed_ip" else ""
                if routing_mode == "fixed_ip" and not fixed_node_id:
                    self.send_json({"ok": False, "error": "启用固定 IP 前，请先连接一个要锁定的节点"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                ui_cfg["fav_fail_fallback"] = fav_fail_fallback
                if "connection_enabled" in payload:
                    ui_cfg["connection_enabled"] = bool(payload.get("connection_enabled"))
                if routing_mode == "fixed_ip":
                    ui_cfg["fixed_node_id"] = fixed_node_id
                ui_cfg.pop("enable_force_country", None)

                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "出站路由配置已更新")

                self.send_json({"ok": True, "message": policy_message or "出站路由配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/toggle_favorite":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "").strip()
                if not node_id:
                    self.send_json({"ok": False, "error": "节点 ID 不能为空"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg = load_ui_config()
                fav_ids = ui_cfg.get("favorite_node_ids", [])
                if not isinstance(fav_ids, list):
                    fav_ids = []

                if node_id in fav_ids:
                    fav_ids.remove(node_id)
                else:
                    fav_ids.append(node_id)

                ui_cfg["favorite_node_ids"] = fav_ids
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                policy_message = None
                if ui_cfg.get("routing_mode") == "favorites":
                    policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "收藏列表已更新")

                self.send_json({"ok": True, "favorite_node_ids": fav_ids, "message": policy_message or ""})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                self.send_json({"ok": True, "message": maintain_valid_nodes(force=True)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                if maintenance_lock.locked():
                    self.send_json({"ok": True, "message": "节点任务正在运行，请稍后再试", "running": True})
                else:
                    resume_metadata_refresh()
                    threading.Thread(target=refresh_node_catalog_only, kwargs={"force": True}, daemon=True).start()
                    self.send_json({"ok": True, "message": "已开始更新全部节点资料，不执行可用性检测", "running": False})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/stop_refresh":
            try:
                pause_metadata_refresh()
                self.send_json({
                    "ok": True,
                    "message": "已请求停止节点资料拉取；自动拉取已暂停，现有国家出口继续运行。",
                })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_availability":
            try:
                payload = self.read_json_body(max_bytes=262144)
                node_ids = payload.get("ids", [])
                if not isinstance(node_ids, list):
                    self.send_json({"ok": False, "error": "筛选节点 ID 列表无效"}, HTTPStatus.BAD_REQUEST)
                    return
                node_ids = list(dict.fromkeys(str(node_id or "").strip() for node_id in node_ids))
                node_ids = [node_id for node_id in node_ids if node_id]
                if not node_ids:
                    self.send_json({"ok": False, "error": "当前筛选条件下没有节点"}, HTTPStatus.BAD_REQUEST)
                    return
                if len(node_ids) > 1000:
                    self.send_json({"ok": False, "error": "筛选节点数量异常"}, HTTPStatus.BAD_REQUEST)
                    return
                if maintenance_lock.locked():
                    self.send_json({"ok": True, "message": "节点任务正在运行，请稍后再试", "running": True})
                else:
                    threading.Thread(target=test_node_availability_only, args=(node_ids,), daemon=True).start()
                    self.send_json({"ok": True, "message": f"已开始检测当前筛选出的 {len(node_ids)} 个节点", "running": False, "count": len(node_ids)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                payload = self.read_json_body(max_bytes=262144)
                node_ids = payload.get("ids", [])
                if not isinstance(node_ids, list):
                    self.send_json({"ok": False, "error": "节点 ID 列表无效"}, HTTPStatus.BAD_REQUEST)
                    return
                node_ids = [str(node_id or "").strip() for node_id in node_ids]
                node_ids = [node_id for node_id in node_ids if node_id]
                if len(node_ids) > MANUAL_TEST_NODE_LIMIT:
                    self.send_json({"ok": False, "error": f"单次最多测试 {MANUAL_TEST_NODE_LIMIT} 个节点"}, HTTPStatus.BAD_REQUEST)
                    return
                if not maintenance_lock.acquire(blocking=False):
                    self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                    return
                with lock:
                    if is_connecting:
                        maintenance_lock.release()
                        self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                        return
                    is_connecting = True
                try:
                    set_state(is_connecting=True, last_check_message="正在手动测试节点可用性...")
                    tested_nodes = test_multiple_nodes(node_ids)
                    self.send_json({"ok": True, "nodes": tested_nodes})
                finally:
                    with lock:
                        is_connecting = False
                    set_state(is_connecting=False)
                    maintenance_lock.release()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                ui_cfg = load_ui_config()
                ui_cfg["connection_enabled"] = False
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                stop_active_openvpn()
                with lock:
                    nodes = read_nodes()
                    for item in nodes:
                        item["active"] = False
                    write_json(NODES_FILE, nodes)
                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0
                set_state(active_openvpn_node_id="", last_check_message="手动断开连接", active_node_latency="无活动连接")
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            try:
                payload = self.read_json_body()
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id") or ""))})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "")
                if not node_id.strip():
                    self.send_json({"ok": False, "error": "节点 ID 不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                if not maintenance_lock.acquire(blocking=False):
                    self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                    return
                with lock:
                    if is_connecting:
                        maintenance_lock.release()
                        self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                        return
                    is_connecting = True
                try:
                    set_state(is_connecting=True, last_check_message="正在手动测试节点可用性...")
                    updated_node = test_node_by_id(node_id)
                    self.send_json({"ok": True, "node": updated_node})
                finally:
                    with lock:
                        is_connecting = False
                    set_state(is_connecting=False)
                    maintenance_lock.release()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                self.read_request_body()
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.stdout, attr)

def main() -> None:
    ensure_dirs()
    if metadata_refresh_paused():
        metadata_cancel_event.set()
    compacted_configs = compact_node_catalog_configs()
    if compacted_configs:
        print(f"[startup] compacted {compacted_configs} inline OVPN configs from node catalog", flush=True)
    normalized_count = normalize_node_country_catalog()
    if normalized_count:
        print(f"[启动迁移] 已统一 {normalized_count} 个节点的国家名称。", flush=True)
    kill_existing_openvpn_processes()
    reset_count = reset_stale_testing_nodes("服务已重启，等待重新检测")
    if reset_count:
        print(f"[启动恢复] 已复位 {reset_count} 个遗留的检测中状态", flush=True)

    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{'[' + LOCAL_PROXY_HOST + ']' if ':' in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": True,
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
            "metadata_refresh_paused": metadata_refresh_paused(),
            "refresh_cancel_requested": metadata_refresh_paused(),
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()

    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    for _ in range(30):
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(0.5)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                s.connect((connect_host, LOCAL_PROXY_PORT))
                gateway_ready = True
                break
            except Exception:
                if connect_host == "::1":
                    try:
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        gateway_ready = True
                        break
                    except Exception:
                        pass
                raise
        except Exception:
            time.sleep(0.5)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)

    if len(read_nodes()) < CACHED_CONFIG_RECOVERY_TARGET and CONFIG_DIR.exists():
        try:
            restored, _ = enrich_and_store_candidates([])
            print(f"[启动恢复] 已从近期目录/本地配置缓存恢复节点目录，共 {len(restored)} 个。", flush=True)
        except Exception as exc:
            print(f"[启动恢复] 本地节点缓存恢复失败: {exc}", flush=True)

    migrate_xui_direct_display_name()
    migrate_multi_exit_channels()
    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=bootstrap_supervisor_loop, daemon=True).start()
    threading.Thread(target=standby_maintenance_loop, daemon=True).start()
    threading.Thread(target=multi_exit_auto_recovery_loop, daemon=True).start()
    threading.Thread(target=start_bundle_server, daemon=True).start()
    # 国家出口由 aimilivpn-multiexit 独立守护；主后台只维护节点目录。

    ui_cfg = load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = bounded_int(ui_cfg.get("port"), UI_PORT, 1, 65535)

    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    DualStackHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()
