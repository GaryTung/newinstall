#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="${AIMILIVPN_REPOSITORY:-GaryTung/newinstall}"
BRANCH="${AIMILIVPN_BRANCH:-main}"

fail() {
  printf '安装失败：%s\n' "$*" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "请使用 sudo bash 运行安装命令"

export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl tar
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
