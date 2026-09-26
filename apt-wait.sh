#!/usr/bin/env bash

apt_get_wait() {
  local timeout="${APT_LOCK_TIMEOUT_SECONDS:-900}"
  local interval=5
  local elapsed=0
  local started=$SECONDS
  local output=""
  local status=0
  local owner_pid=""

  while true; do
    set +e
    output="$(apt-get -o DPkg::Lock::Timeout=30 "$@" 2>&1)"
    status=$?
    set -e
    [[ -z "$output" ]] || printf '%s\n' "$output"
    (( status == 0 )) && return 0

    elapsed=$((SECONDS - started))

    if ! grep -Eqi 'could not get lock|unable to lock directory|unable to acquire the dpkg frontend lock|is held by process|another process using it' <<<"$output"; then
      return "$status"
    fi
    if (( elapsed >= timeout )); then
      printf '等待 APT/DPKG 锁超过 %s 秒，请稍后重新执行安装命令。\n' "$timeout" >&2
      return "$status"
    fi

    owner_pid="$(sed -nE 's/.*held by process ([0-9]+).*/\1/p' <<<"$output" | head -n 1)"
    if [[ -n "$owner_pid" ]] && [[ -r "/proc/${owner_pid}/comm" ]]; then
      printf '系统自动更新正在运行（PID %s，%s），等待锁释放：%s/%s 秒...\n' \
        "$owner_pid" "$(<"/proc/${owner_pid}/comm")" "$elapsed" "$timeout"
    else
      printf 'APT/DPKG 正被其他系统任务占用，等待锁释放：%s/%s 秒...\n' "$elapsed" "$timeout"
    fi
    sleep "$interval"
  done
}
