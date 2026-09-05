#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="aimilivpn"
APP_DIR="/opt/${APP_NAME}"
DATA_DIR="/var/lib/${APP_NAME}"
ENV_FILE="/etc/default/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

UI_PORT="${UI_PORT:-8787}"
PROXY_PORT="${PROXY_PORT:-7928}"
UI_HOST="${UI_HOST:-::}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"

fail() {
  printf '安装失败：%s\n' "$*" >&2
  exit 1
}

if [[ "${EUID}" -ne 0 ]]; then
  fail "请使用 sudo bash install.sh 运行。"
fi

for file in vpngate_manager.py vpn_utils.py proxy_server.py; do
  [[ -f "${SCRIPT_DIR}/${file}" ]] || fail "安装包缺少 ${file}"
done

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
else
  fail "无法识别操作系统。此安装包支持 Ubuntu/Debian。"
fi

case "${ID:-}" in
  ubuntu|debian) ;;
  *) fail "当前系统 ${ID:-unknown} 暂不支持；请使用 Ubuntu 22.04/24.04 或 Debian 12。" ;;
esac

case "${UI_PORT}" in
  ''|*[!0-9]*) fail "UI_PORT 必须是数字" ;;
esac
case "${PROXY_PORT}" in
  ''|*[!0-9]*) fail "PROXY_PORT 必须是数字" ;;
esac
(( UI_PORT >= 1 && UI_PORT <= 65535 )) || fail "UI_PORT 超出范围"
(( PROXY_PORT >= 1024 && PROXY_PORT <= 65535 )) || fail "PROXY_PORT 超出范围"
[[ "${UI_PORT}" != "${PROXY_PORT}" ]] || fail "管理端口和代理端口不能相同"

printf '%s\n' '[1/7] 安装系统依赖...'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl iproute2 iptables openvpn procps python3

printf '%s\n' '[2/7] 检查 TUN 设备...'
modprobe tun 2>/dev/null || true
[[ -c /dev/net/tun ]] || fail "未检测到 /dev/net/tun。请先在 VPS 控制台启用 TUN/TAP 后再安装。"

printf '%s\n' '[3/7] 校验并安装程序文件...'
cache_dir="$(mktemp -d /tmp/aimilivpn-pycache.XXXXXX)"
trap 'rm -rf -- "${cache_dir}"' EXIT
PYTHONPYCACHEPREFIX="${cache_dir}" python3 -m py_compile \
  "${SCRIPT_DIR}/vpngate_manager.py" \
  "${SCRIPT_DIR}/vpn_utils.py" \
  "${SCRIPT_DIR}/proxy_server.py"

backup_dir=""
if [[ -f "${APP_DIR}/vpngate_manager.py" ]]; then
  backup_dir="/var/backups/aimilivpn/$(date +%Y%m%d-%H%M%S)"
  install -d -o root -g root -m 0700 "${backup_dir}"
  for file in vpngate_manager.py vpn_utils.py proxy_server.py; do
    [[ -f "${APP_DIR}/${file}" ]] && cp -p -- "${APP_DIR}/${file}" "${backup_dir}/${file}"
  done
fi

install -d -o root -g root -m 0755 "${APP_DIR}"
install -d -o root -g root -m 0700 "${DATA_DIR}"
install -o root -g root -m 0755 "${SCRIPT_DIR}/vpngate_manager.py" "${APP_DIR}/vpngate_manager.py"
install -o root -g root -m 0755 "${SCRIPT_DIR}/vpn_utils.py" "${APP_DIR}/vpn_utils.py"
install -o root -g root -m 0755 "${SCRIPT_DIR}/proxy_server.py" "${APP_DIR}/proxy_server.py"
if [[ -f "${SCRIPT_DIR}/LICENSE" ]]; then
  install -o root -g root -m 0644 "${SCRIPT_DIR}/LICENSE" "${APP_DIR}/LICENSE"
fi
if [[ -f "${SCRIPT_DIR}/VERSION" ]]; then
  install -o root -g root -m 0644 "${SCRIPT_DIR}/VERSION" "${APP_DIR}/VERSION"
fi

printf '%s\n' '[4/7] 初始化独立账号和配置...'
auth_file="${DATA_DIR}/ui_auth.json"
if [[ ! -s "${auth_file}" ]]; then
  username="admin_$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
  password="$(python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(18)))')"
  secret_path="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  umask 077
  printf '{\n  "username": "%s",\n  "password": "%s",\n  "secret_path": "%s",\n  "host": "%s",\n  "port": %s,\n  "proxy_port": %s,\n  "routing_mode": "auto",\n  "force_country": "",\n  "routing_ip_type": "all",\n  "connection_enabled": true,\n  "fixed_node_id": "",\n  "favorite_node_ids": [],\n  "fav_fail_fallback": false\n}\n' \
    "${username}" "${password}" "${secret_path}" "${UI_HOST}" "${UI_PORT}" "${PROXY_PORT}" > "${auth_file}"
  chmod 0600 "${auth_file}"
else
  printf '%s\n' '检测到已有数据，保留原账号、页面路径、收藏和路由设置。'
fi

cat > "${ENV_FILE}" <<EOF
VPNGATE_DATA_DIR=${DATA_DIR}
UI_HOST=${UI_HOST}
UI_PORT=${UI_PORT}
LOCAL_PROXY_HOST=${PROXY_HOST}
LOCAL_PROXY_PORT=${PROXY_PORT}
PYTHONUNBUFFERED=1
EOF
chmod 0600 "${ENV_FILE}"

printf '%s\n' '[5/7] 创建系统服务和管理命令...'
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=AimiliVPN OpenVPN Manager with HTTP/SOCKS5 Proxy
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
EnvironmentFile=-${ENV_FILE}
ExecStart=/usr/bin/python3 -u ${APP_DIR}/vpngate_manager.py
Restart=always
RestartSec=5
UMask=0077
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

install -o root -g root -m 0755 "${SCRIPT_DIR}/aimilivpnctl" /usr/local/sbin/aimilivpnctl
ln -sfn /usr/local/sbin/aimilivpnctl /usr/local/bin/ml

printf '%s\n' '[6/7] 启动服务...'
systemctl daemon-reload
systemctl enable --now "${APP_NAME}.service"
systemctl restart "${APP_NAME}.service"
sleep 5
if ! systemctl is-active --quiet "${APP_NAME}.service"; then
  journalctl -u "${APP_NAME}.service" -n 80 --no-pager >&2 || true
  if [[ -n "${backup_dir}" ]]; then
    printf '%s\n' '正在恢复升级前版本...' >&2
    for file in vpngate_manager.py vpn_utils.py proxy_server.py; do
      [[ -f "${backup_dir}/${file}" ]] && install -o root -g root -m 0755 "${backup_dir}/${file}" "${APP_DIR}/${file}"
    done
    systemctl restart "${APP_NAME}.service" || true
  fi
  fail "服务启动失败，日志已显示在上方。"
fi

printf '%s\n' '[7/7] 健康检查...'
sleep 2
systemctl is-active --quiet "${APP_NAME}.service" || fail "健康检查失败"

readarray -t login_info < <(python3 - "${auth_file}" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    cfg = json.load(f)
print(cfg.get("username", ""))
print(cfg.get("password", ""))
print(cfg.get("secret_path", ""))
print(cfg.get("port", 8787))
PY
)

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow "${login_info[3]}/tcp" comment 'AimiliVPN Web UI'
  ufw allow 2097/tcp comment 'AimiliVPN combined subscriptions'
fi

public_ip="$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
[[ -n "${public_ip}" ]] || public_ip='<服务器公网IP>'

printf '\n%s\n' 'AimiliVPN 安装/升级完成。'
printf '管理地址：http://%s:%s/%s/\n' "${public_ip}" "${login_info[3]}" "${login_info[2]}"
printf '管理账号：%s\n' "${login_info[0]}"
printf '管理密码：%s\n' "${login_info[1]}"
printf '本机代理：http/socks5://127.0.0.1:%s\n' "${PROXY_PORT}"
printf '%s\n' '完整登录信息：sudo ml info'
printf '%s\n' '管理命令：sudo ml status | credentials | logs | restart'
printf '请在云服务商安全组中放行 TCP %s（后台）及 TCP 2097（总订阅）；不要向公网开放代理端口 %s。\n' "${login_info[3]}" "${PROXY_PORT}"
