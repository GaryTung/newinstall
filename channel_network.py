"""Stable, persisted network allocations shared by the dashboard and Xray."""
from __future__ import annotations

MAX_NETWORK_SLOT = 3360


def valid_slot(value):
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_NETWORK_SLOT


def ensure_network_slots(config):
    """Allocate once; reserve disabled channels and never renumber survivors."""
    changed = False
    used = set()
    missing = []
    for channel in config.get("channels", []):
        slot = channel.get("network_slot")
        if valid_slot(slot) and slot not in used:
            used.add(slot)
        else:
            missing.append(channel)
    next_slot = max(int(config.get("network_next_slot") or 1), max(used, default=0) + 1)
    for channel in missing:
        if next_slot > MAX_NETWORK_SLOT:
            raise ValueError("通道内部网段已耗尽")
        channel["network_slot"] = next_slot
        used.add(next_slot)
        next_slot += 1
        changed = True
    if config.get("network_next_slot") != next_slot:
        config["network_next_slot"] = next_slot
        changed = True
    return changed


def channel_slot(channel, index=None):
    slot = channel.get("network_slot", index)
    if not valid_slot(slot):
        raise ValueError("通道缺少有效的固定内部网段")
    return slot


def channel_network(slot):
    if not valid_slot(slot):
        raise ValueError("Invalid network slot")
    offset = slot - 1
    third = 200 + offset // 60
    fourth = (offset % 60) * 4
    return f"10.253.{third}.{fourth}/30", f"10.253.{third}.{fourth + 1}", f"10.253.{third}.{fourth + 2}"


def slot_from_proxy_address(value):
    try:
        a, b, third, fourth = [int(part) for part in str(value).split(".")]
        if (a, b) != (10, 253) or not 200 <= third <= 255 or not 2 <= fourth <= 238 or fourth % 4 != 2:
            return None
        return (third - 200) * 60 + (fourth - 2) // 4 + 1
    except (ValueError, TypeError):
        return None


def managed_address(value):
    try:
        a, b, third, fourth = [int(part) for part in str(value).split("/")[0].split(".")]
        return (a, b) == (10, 253) and 200 <= third <= 255 and 0 <= fourth <= 255
    except (ValueError, TypeError):
        return False
