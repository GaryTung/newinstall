"""Shared country-exit selection rules for the daemon and dashboard."""

from __future__ import annotations

import ipaddress
import re


# Keep the previously confirmed Ping0 classifications effective even when an
# older IPPure entry is still cached as residential.
FORCED_HOSTING_IPS = {
    "121.128.66.171", "47.153.119.84", "61.76.60.93", "118.47.249.153",
}
FORCED_HOSTING_NETWORKS = (ipaddress.ip_network("219.100.37.0/24"),)


def provider_rejection(channel, node=None, provider="", asn=""):
    """Return the user's country-specific provider exclusion, if any."""
    country = str(channel.get("country") or "").strip().casefold()
    node = node if isinstance(node, dict) else {}
    providers = [str(value or "").strip().casefold() for value in (
        provider, node.get("owner"), node.get("as_name"), node.get("org"),
        node.get("exit_owner"), node.get("exit_as_name"), node.get("exit_provider"),
    )]
    provider_text = " ".join(providers)
    asns = set(re.findall(r"(?i)\bAS\s*(\d+)\b", " ".join(
        str(value or "") for value in (asn, node.get("asn"), node.get("exit_asn"))
    )))
    asns.update(str(value) for value in (asn, node.get("asn"), node.get("exit_asn"))
                if str(value or "").isdigit())
    if country in {"日本", "japan", "jp"}:
        if "kddi" in provider_text:
            return "日本线路已排除 KDDI 服务商"
        if "2516" in asns:
            return "日本线路已排除 KDDI AS2516"
    if country in {"韩国", "south korea", "korea republic of", "republic of korea", "kr"}:
        if "kt" in providers or any(marker in provider_text for marker in (
            "korea telecom", "kornet", "kixs", "kt corporation",
        )):
            return "韩国线路已排除 KT/Korea Telecom 服务商"
        if "4766" in asns:
            return "韩国线路已排除 KT AS4766"
    return ""


def effective_ip_type(node):
    address = str(node.get("exit_ip") or node.get("ip") or node.get("remote_host") or "").strip()
    if address in FORCED_HOSTING_IPS:
        return "hosting"
    try:
        if any(ipaddress.ip_address(address) in network for network in FORCED_HOSTING_NETWORKS):
            return "hosting"
    except ValueError:
        pass
    value = str(node.get("exit_ip_type") or node.get("ip_type") or "unknown").lower()
    return {"住宅": "residential", "移动": "mobile", "datacenter": "hosting", "机房": "hosting"}.get(value, value)


def ip_type_rank(node, mode):
    value = effective_ip_type(node)
    residential = value in {"residential", "mobile"}
    hosting = value == "hosting"
    if mode == "residential_only":
        return 0 if residential else 99
    if mode == "hosting_only":
        return 0 if hosting else 99
    if mode == "residential_preferred":
        return 0 if residential else (2 if hosting else 1)
    return 0


def candidate_rejection(channel, node):
    reason = provider_rejection(channel, node=node)
    if reason:
        return reason
    mode = str(channel.get("ip_type") or "all")
    if ip_type_rank(node, mode) >= 99:
        return "当前线路仅允许住宅 IP" if mode == "residential_only" else "当前线路仅允许机房 IP"
    return ""


def failure_record(records, node_id, channel_id=""):
    """Read a channel-local failure, falling back to pre-migration records."""
    if not isinstance(records, dict):
        return {}
    node_id, channel_id = str(node_id or ""), str(channel_id or "")
    key = f"{channel_id}:{node_id}"
    if channel_id and key in records:
        value = records[key]
    else:
        value = records.get(node_id)
    return value if isinstance(value, dict) else {}
