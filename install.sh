#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="${AIMILIVPN_REPOSITORY:-GaryTung/newinstall}"
BRANCH="${AIMILIVPN_BRANCH:-main}"

fail() {
  printf '安装失败：%s\n' "$*" >&2
  exit 1
}

apt_get_wait() {
  # Scope temporary-file cleanup and pipefail to this call, not the installer.
  (
    set -o pipefail
    local timeout="${APT_LOCK_TIMEOUT_SECONDS:-900}" interval=5 elapsed=0
    local started=$SECONDS status=0 owner_pid="" log_file=""
    local -a pipeline_status
    log_file="$(mktemp "${TMPDIR:-/tmp}/node-gateway-apt.XXXXXX")" || return 1
    trap 'rm -f -- "$log_file"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    printf '[APT] 正在执行：apt-get'
    printf ' %s' "$@"
    printf '\n[APT] 以下实时显示软件源、下载及安装输出；请勿重复启动安装。\n'
    while true; do
      # tee streams output immediately; retain apt's status, not just tee's.
      if apt-get -o DPkg::Lock::Timeout=30 -o Dpkg::Use-Pty=0 "$@" 2>&1 | tee "$log_file"; then
        pipeline_status=("${PIPESTATUS[@]}")
      else
        pipeline_status=("${PIPESTATUS[@]}")
      fi
      status="${pipeline_status[0]}"
      if (( ${pipeline_status[1]} != 0 )); then
        printf '[APT] 无法显示或保存安装输出，已停止。\n' >&2
        return "${pipeline_status[1]}"
      fi
      elapsed=$((SECONDS - started))
      if (( status == 0 )); then
        printf '[APT] 本步骤完成，耗时 %s 秒。\n' "$elapsed"
        return 0
      fi
      if ! grep -Eqi 'could not get lock|unable to lock directory|unable to acquire the dpkg frontend lock|is held by process|another process using it' "$log_file"; then
        printf '[APT] 本步骤失败（退出码 %s），请查看上方错误。\n' "$status" >&2
        return "$status"
      fi
      if (( elapsed >= timeout )); then
        printf '等待 APT/DPKG 锁超过 %s 秒，请稍后重新执行安装命令。\n' "$timeout" >&2
        return "$status"
      fi
      owner_pid="$(sed -nE 's/.*held by process ([0-9]+).*/\1/p' "$log_file" | sed -n '1p')"
      if [[ -n "$owner_pid" ]] && [[ -r "/proc/${owner_pid}/comm" ]]; then
        printf '系统自动更新正在运行（PID %s，%s），等待锁释放：%s/%s 秒...\n' "$owner_pid" "$(<"/proc/${owner_pid}/comm")" "$elapsed" "$timeout"
      else
        printf 'APT/DPKG 正被其他系统任务占用，等待锁释放：%s/%s 秒...\n' "$elapsed" "$timeout"
      fi
      sleep "$interval"
    done
  )
}

[[ ${EUID} -eq 0 ]] || fail "请使用 sudo bash 运行安装命令"

export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
  apt_get_wait update
  apt_get_wait install -y --no-install-recommends ca-certificates curl tar
else
  fail "当前一键安装版本仅支持 Ubuntu/Debian"
fi

work_dir="$(mktemp -d /tmp/aimilivpn-installer.XXXXXX)"
trap 'rm -rf -- "${work_dir}"' EXIT
archive="${work_dir}/source.tar.gz"

printf '%s\n' "正在下载 ${REPOSITORY} (${BRANCH}) 完整安装包..."
curl -fL --retry 3 --connect-timeout 15 \
  "https://github.com/${REPOSITORY}/archive/refs/heads/${BRANCH}.tar.gz" \
  -o "${archive}"
tar -xzf "${archive}" -C "${work_dir}"

source_dir="$(find "${work_dir}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[[ -n "${source_dir}" && -f "${source_dir}/unified-install.sh" ]] \
  || fail "下载的安装包不完整"

bash "${source_dir}/unified-install.sh" "$@"
