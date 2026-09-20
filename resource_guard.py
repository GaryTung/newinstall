"""Cheap, conservative admission checks for optional gateway maintenance.

No process, timer or cleanup is started here.  These checks are not intended
for existing tunnel forwarding or its essential health checks.
"""
from __future__ import annotations

import math
from pathlib import Path


MEMINFO_PATH = Path("/proc/meminfo")
LOW_MEMORY_TOTAL_KIB = 1536 * 1024
DEFAULT_MIN_AVAILABLE_MIB = 192


def _memory_kib(meminfo_text: str | None = None) -> tuple[int, int]:
    """Return total/available KiB, rejecting incomplete or inconsistent input."""
    text = MEMINFO_PATH.read_text(encoding="ascii") if meminfo_text is None else meminfo_text
    values: dict[str, int] = {}
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        if not separator or name not in {"MemTotal", "MemAvailable"}:
            continue
        fields = value.split()
        if name in values or len(fields) != 2 or fields[1] != "kB":
            raise ValueError(f"{name} 格式无效")
        try:
            values[name] = int(fields[0])
        except ValueError as exc:
            raise ValueError(f"{name} 不是有效整数") from exc
    if "MemTotal" not in values or "MemAvailable" not in values:
        raise ValueError("缺少 MemTotal 或 MemAvailable")
    total, available = values["MemTotal"], values["MemAvailable"]
    if total <= 0 or available < 0 or available > total:
        raise ValueError("MemTotal 与 MemAvailable 数值无效")
    return total, available


def background_work_allowed(
    min_available_mib: int = DEFAULT_MIN_AVAILABLE_MIB,
    *,
    meminfo_text: str | None = None,
) -> tuple[bool, str]:
    """Gate optional catalog pulls/probes using Linux's available-memory value.

    Inject ``meminfo_text`` for deterministic tests without a Linux filesystem.
    An unreadable/malformed snapshot denies optional work rather than assuming
    unlimited memory.  This is an admission check, not a hard memory limit.
    """
    try:
        minimum = float(min_available_mib)
        if not math.isfinite(minimum) or minimum <= 0:
            raise ValueError("可用内存门槛必须为正数")
    except (TypeError, ValueError, OverflowError) as exc:
        return False, f"后台任务已暂停：内存门槛无效（{exc}）"
    try:
        _, available_kib = _memory_kib(meminfo_text)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        return False, f"后台任务已暂停：无法可靠读取可用内存（{exc}）；现有出口健康检查不受影响"
    available_mib = available_kib / 1024
    if available_mib < minimum:
        return False, (
            f"后台任务已暂停：可用内存 {available_mib:.1f} MiB，"
            f"低于安全门槛 {minimum:g} MiB；请稍后重试，现有出口健康检查不受影响"
        )
    return True, f"内存检查通过：可用 {available_mib:.1f} MiB（门槛 {minimum:g} MiB）"


def recommended_probe_workers(
    requested: int = 2,
    *,
    meminfo_text: str | None = None,
) -> int:
    """Cap probe concurrency at one on <=1.5 GiB or unknown-memory hosts."""
    try:
        workers = min(5, max(1, int(requested)))
    except (TypeError, ValueError, OverflowError):
        workers = 2
    try:
        total_kib, _ = _memory_kib(meminfo_text)
    except (OSError, UnicodeError, ValueError, TypeError):
        return 1
    return 1 if total_kib <= LOW_MEMORY_TOTAL_KIB else workers
