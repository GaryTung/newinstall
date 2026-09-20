"""Bounded real-egress benchmarks; never test by replacing a production tunnel."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from channel_policy import candidate_rejection, ip_type_rank

BATCH_SIZE = 6
INTERVAL = 15 * 60
RESULT_TTL = 3 * 3600
SWITCH_COOLDOWN = 30 * 60
MIN_GAIN = 1.25
SAMPLE_BYTES = 1024 * 1024
SAMPLE_SECONDS = 10
SAMPLE_URL = f"https://speed.cloudflare.com/__down?bytes={SAMPLE_BYTES}"
NS = "avpn-speed-benchmark"  # Longer than any production avpn-<10 character id>.
HOST_IF = "vgsp-host"
PEER_IF = "vgsp-peer"
SUBNET = "10.252.254.0/30"
HOST_IP = "10.252.254.1"
PROXY_IP = "10.252.254.2"


def policy_key(channel):
    # Policy revision also invalidates measurements after exclusion-rule changes.
    values = [channel.get("country"), channel.get("ip_type", "all"), "43"]
    return hashlib.sha256(json.dumps(values, ensure_ascii=False).encode()).hexdigest()[:16]


def node_key(node):
    values = [node.get(key) for key in ("id", "ip", "remote_host", "remote_port", "config_text", "config_file")]
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()[:16]


def read_results(data_dir):
    try:
        result = json.loads((Path(data_dir) / "speed_results.json").read_text())
        return result if isinstance(result, dict) else {}
    except (OSError, ValueError):
        return {}


def valid_sample(sample, node, channel, now=None):
    now = time.time() if now is None else now
    if not isinstance(sample, dict) or not sample.get("ok"):
        return False
    if not 0 <= now - float(sample.get("tested_at") or 0) < RESULT_TTL:
        return False
    if sample.get("node_key") != node_key(node) or sample.get("policy_key") != policy_key(channel):
        return False
    if float(sample.get("bps") or 0) <= 0:
        return False
    actual = {**node, "exit_ip": sample.get("exit_ip"), "exit_ip_type": sample.get("ip_type"),
              "exit_provider": sample.get("provider"), "exit_asn": sample.get("asn")}
    return not candidate_rejection(channel, actual)


def ranked_samples(channel, nodes, result, now=None):
    samples = result.get("samples", {})
    ranked = []
    for node in nodes:
        sample = samples.get(str(node.get("id")), {})
        if valid_sample(sample, node, channel, now):
            actual = {**node, "exit_ip": sample.get("exit_ip"), "exit_ip_type": sample.get("ip_type")}
            ranked.append((ip_type_rank(actual, channel.get("ip_type", "all")), -float(sample["bps"]), str(node["id"])))
    return sorted(ranked)


def speed_order(channel, node, result, now=None):
    if not channel.get("speed_auto", True) or channel.get("preferred_node_id"):
        return (1, 0)
    sample = result.get("samples", {}).get(str(node.get("id")), {})
    return (0, -float(sample["bps"])) if valid_sample(sample, node, channel, now) else (1, 0)


def choose_switch(channel, runtime, nodes, result, now=None):
    """Healthy manual pins win; automatic changes need a measured improvement."""
    now = time.time() if now is None else now
    if not channel.get("speed_auto", True) or channel.get("preferred_node_id"):
        return ""
    if runtime.get("status") != "connected" or result.get("status") != "complete":
        return ""
    if result.get("policy_key") != policy_key(channel):
        return ""
    ranking = ranked_samples(channel, nodes, result, now)
    if not ranking:
        return ""
    winner_rank, negative_speed, winner = ranking[0]
    current_id = str(runtime.get("node_id") or "")
    if winner == current_id:
        return ""
    current = next((n for n in nodes if str(n.get("id")) == current_id), None)
    baseline = result.get("samples", {}).get(current_id, {})
    # A failed benchmark is not a failed tunnel. Leave recovery to health checks.
    if not current or not valid_sample(baseline, current, channel, now):
        return ""
    if baseline.get("exit_ip") != runtime.get("exit_ip"):
        return ""
    request = float(channel.get("speed_request_token") or 0)
    if request > float(result.get("request_token") or 0):
        return ""
    forced = request > float(runtime.get("speed_request_applied") or 0) and float(result.get("request_token") or 0) == request
    if not forced and now - float(runtime.get("speed_switch_at") or 0) < SWITCH_COOLDOWN:
        return ""
    current_rank = ip_type_rank({**current, "exit_ip": baseline.get("exit_ip"), "exit_ip_type": baseline.get("ip_type")}, channel.get("ip_type", "all"))
    gain = 1.0 if forced else MIN_GAIN
    if winner_rank < current_rank or (winner_rank == current_rank and -negative_speed > float(baseline["bps"]) * gain):
        return winner
    return ""


def batch_candidates(nodes, runtime, result):
    samples = result.get("samples", {})
    current = str(runtime.get("node_id") or "")
    # Re-measure the current baseline; rotate oldest/untested alternatives fairly.
    ordered = sorted(nodes, key=lambda n: (0 if str(n["id"]) == current else 1,
                     float(samples.get(str(n["id"]), {}).get("tested_at") or 0)))
    return ordered[:BATCH_SIZE]


def resources_available():
    try:
        values = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        if int(values["MemAvailable"].strip().split()[0]) < 128 * 1024:
            return False
        return os.getloadavg()[0] < max(2.0, float(os.cpu_count() or 1) * 1.5)
    except (OSError, KeyError, ValueError):
        return False


def setup_namespace(manager):
    run = manager.run
    existing = run(["ip", "netns", "list"], check=False, capture=True).stdout.split()
    interface_exists = run(["ip", "link", "show", HOST_IF], check=False, capture=True).returncode == 0
    if (NS in existing or interface_exists) and not owns_namespace(manager):
        raise RuntimeError("测速网络名称已被未确认归属的接口占用，未修改现有网络")
    if NS not in existing:
        # Refuse unrelated routes in our dedicated subnet, never overwrite them.
        routes = json.loads(run(["ip", "-j", "route", "show", "table", "all"], capture=True).stdout or "[]")
        import ipaddress
        target = ipaddress.ip_network(SUBNET)
        for route in routes:
            dst = route.get("dst", "default")
            if dst == "default" or route.get("dev") == HOST_IF:
                continue
            try:
                other = ipaddress.ip_network(dst, strict=False)
                if other.version == 4 and other.overlaps(target):
                    raise RuntimeError("测速专用网段与现有网络重叠，未启动测速")
            except ValueError:
                continue
        marker = manager.DATA_DIR / "speed-test" / "network-owned.json"
        manager.write_json(marker, {"namespace": NS, "host_if": HOST_IF})
        run(["ip", "netns", "add", NS])
    if run(["ip", "link", "show", HOST_IF], check=False, capture=True).returncode != 0:
        run(["ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", PEER_IF])
        run(["ip", "link", "set", PEER_IF, "netns", NS])
    run(["ip", "addr", "replace", f"{HOST_IP}/30", "dev", HOST_IF])
    run(["ip", "link", "set", HOST_IF, "up"])
    prefix = ["ip", "netns", "exec", NS]
    run([*prefix, "ip", "addr", "replace", f"{PROXY_IP}/30", "dev", PEER_IF])
    run([*prefix, "ip", "link", "set", PEER_IF, "up"])
    run([*prefix, "ip", "link", "set", "lo", "up"])
    run([*prefix, "ip", "route", "replace", "default", "via", HOST_IP])
    for args in (["-t", "nat", "POSTROUTING", "-s", SUBNET, "-j", "MASQUERADE"],
                 ["FORWARD", "-i", HOST_IF, "-j", "ACCEPT"], ["FORWARD", "-o", HOST_IF, "-j", "ACCEPT"]):
        pre, rule = (args[:2], args[2:]) if args[0] == "-t" else ([], args)
        if run(["iptables", *pre, "-C", *rule], check=False, capture=True).returncode:
            run(["iptables", *pre, "-A", *rule])
    routes = json.loads(run(["ip", "-j", "route", "get", PROXY_IP], capture=True).stdout or "[]")
    if not routes or routes[0].get("dev") != HOST_IF:
        raise RuntimeError("测速内部路由异常，未进行出口测试")


def owns_namespace(manager):
    marker = manager.read_json(manager.DATA_DIR / "speed-test" / "network-owned.json", {})
    return marker == {"namespace": NS, "host_if": HOST_IF}


def cleanup_namespace(manager):
    if not owns_namespace(manager):
        return
    manager.stop_namespace_processes(NS)
    manager.run(["ip", "netns", "del", NS], check=False, capture=True)
    manager.run(["ip", "link", "del", HOST_IF], check=False, capture=True)
    manager.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", SUBNET, "-j", "MASQUERADE"], check=False, capture=True)
    for direction in ("-i", "-o"):
        manager.run(["iptables", "-D", "FORWARD", direction, HOST_IF, "-j", "ACCEPT"], check=False, capture=True)
    # Keep ownership marker for safe retry after a partially failed cleanup.


def download_sample(manager):
    result = manager.run([
        "curl", "-4fsS", "--noproxy", "", "--proto", "=https", "--max-time", str(SAMPLE_SECONDS),
        "--connect-timeout", "4", "--max-filesize", str(SAMPLE_BYTES),
        "--socks5-hostname", f"{PROXY_IP}:1080", "-o", "/dev/null",
        "-w", "%{http_code} %{size_download} %{time_total}", SAMPLE_URL,
    ], check=False, capture=True, timeout=SAMPLE_SECONDS + 3)
    parts = result.stdout.strip().split()
    if len(parts) != 3 or parts[0] != "200":
        raise RuntimeError("测速下载未完整完成（不等同于节点不可用）")
    size, elapsed = float(parts[1]), float(parts[2])
    full = result.returncode == 0 and size == SAMPLE_BYTES
    timed_sample = result.returncode == 28 and 65536 <= size <= SAMPLE_BYTES and elapsed >= SAMPLE_SECONDS - 1
    if not (full or timed_sample) or elapsed <= 0:
        raise RuntimeError("测速响应大小异常")
    return size / elapsed


def benchmark(manager, channel, node):
    work = manager.DATA_DIR / "speed-test"
    work.mkdir(parents=True, exist_ok=True)
    manager.stop_namespace_processes(NS)
    try:
        manager.start_openvpn(NS, work, node)
        manager.start_proxy(NS, work)
        time.sleep(0.5)
        ok, exit_ip, _ = manager.proxy_health(PROXY_IP)
        if not ok:
            raise RuntimeError("测速专用连接未通过完整出口验证")
        country = manager.enforce_country_lock(channel, node, exit_ip)
        info = manager.ippure_exit_info(PROXY_IP)
        reason = manager.channel_provider_rejection(channel, node=node, provider=info.get("provider", ""), asn=info.get("asn", ""))
        if reason:
            raise RuntimeError(reason)
        manager.enforce_exit_ip_type(channel, exit_ip, info)
        measurements = [download_sample(manager), download_sample(manager)]
        return {"ok": True, "bps": min(measurements), "measurements": measurements,
                "exit_ip": exit_ip, "country_code": country, **info}
    finally:
        manager.stop_namespace_processes(NS)


def speed_loop(manager):
    """One extra OpenVPN process, globally serial, with a persistent bounded cache."""
    results = read_results(manager.DATA_DIR)
    results.setdefault("channels", {})
    path = manager.DATA_DIR / "speed_results.json"
    time.sleep(20)  # Let production exits recover before consuming spare resources.
    cleanup_namespace(manager)
    for previous in results["channels"].values():
        if previous.get("status") == "testing":
            previous.update(status="waiting", completed_at=0, message="服务重启，等待重新测速")
    manager.write_json(path, results)
    while True:
        try:
            config = manager.read_json(manager.CONFIG_FILE, {})
            channels = [c for c in config.get("channels", []) if c.get("enabled", True)]
            valid_ids = {c["id"] for c in channels}
            results["channels"] = {k: v for k, v in results["channels"].items() if k in valid_ids}
            for channel in channels:
                cid = channel["id"]
                if not channel.get("speed_auto", True) or channel.get("preferred_node_id") or channel.get("awaiting_initial_test"):
                    continue
                current = results["channels"].get(cid, {})
                request = float(channel.get("speed_request_token") or 0)
                if current.get("status") in {"complete", "error"} and current.get("policy_key") == policy_key(channel) and request <= float(current.get("request_token") or 0) and time.time() - float(current.get("completed_at") or 0) < INTERVAL:
                    continue
                runtime = manager.read_json(manager.STATE_FILE, {}).get("channels", {}).get(cid, {})
                if runtime.get("status") != "connected" or not resources_available():
                    continue
                candidates = manager.select_candidates({**channel, "tested_only": True})
                if not candidates:
                    continue
                if current.get("policy_key") != policy_key(channel):
                    current = {"samples": {}}
                allowed_ids = {str(n["id"]) for n in candidates}
                current["samples"] = {k: v for k, v in current.get("samples", {}).items() if k in allowed_ids}
                batch = batch_candidates(candidates, runtime, current)
                current.update(status="testing", tested=0, total=len(batch), eligible_total=len(candidates),
                               policy_key=policy_key(channel), request_token=request,
                               message="独立临时出口串行测速，正在使用的出口保持连接")
                results["channels"][cid] = current
                manager.write_json(path, results)
                try:
                    setup_namespace(manager)
                    for index, node in enumerate(batch, 1):
                        latest = next((c for c in manager.read_json(manager.CONFIG_FILE, {}).get("channels", []) if c.get("id") == cid), {})
                        live = manager.read_json(manager.STATE_FILE, {}).get("channels", {}).get(cid, {})
                        if not latest.get("enabled", True) or not latest or not latest.get("speed_auto", True) or latest.get("preferred_node_id") or policy_key(latest) != policy_key(channel) or live.get("status") != "connected" or not resources_available():
                            raise RuntimeError("线路配置/连接或资源状态发生变化，暂停本轮测速")
                        current["message"] = f"正在测速 {index}/{len(batch)}：{node.get('ip') or node.get('remote_host') or node['id']}"
                        manager.write_json(path, results)
                        try:
                            sample = benchmark(manager, channel, node)
                        except Exception as exc:
                            sample = {"ok": False, "bps": 0, "error": str(exc)[-240:]}
                        sample.update(tested_at=time.time(), node_key=node_key(node), policy_key=policy_key(channel))
                        current["samples"][str(node["id"])] = sample
                        current["tested"] = index
                        manager.write_json(path, results)
                        time.sleep(2)
                    ranking = ranked_samples(channel, candidates, current)
                    current.update(status="complete", winner_id=ranking[0][2] if ranking else "",
                                   winner_bps=-ranking[0][1] if ranking else 0,
                                   message=f"本轮已测 {len(batch)} 个；自动选择有效实测结果中最快的合格出口")
                except Exception as exc:
                    current.update(status="error", message=str(exc)[-240:])
                finally:
                    cleanup_namespace(manager)
                    current["completed_at"] = time.time()
                    results["updated_at"] = time.time()
                    manager.write_json(path, results)
                    manager.WAKE_EVENT.set()
        except Exception as exc:
            print(f"exit speed worker: {exc}", flush=True)
        time.sleep(30)
