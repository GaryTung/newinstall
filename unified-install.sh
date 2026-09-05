#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
XUI_INSTALL_URL="https://raw.githubusercontent.com/MHSanaei/3x-ui/main/install.sh"

fail() { printf '安装失败：%s\n' "$*" >&2; exit 1; }
random_text() { openssl rand -hex "$1"; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

[[ ${EUID} -eq 0 ]] || fail "请使用 sudo bash unified-install.sh 运行"
[[ -f "${SCRIPT_DIR}/install-core.sh" ]] || fail "安装包不完整：缺少 install-core.sh"
[[ -f "${SCRIPT_DIR}/xui_provision.py" ]] || fail "安装包不完整：缺少 xui_provision.py"

printf '%s\n' '统一节点系统安装向导'
printf '%s\n' '1) VLESS + TLS（TCP）'
printf '%s\n' '2) Trojan + TLS（TCP）'
printf '%s\n' '3) Hysteria2 + TLS（UDP）'
read -rp '请选择协议 [默认 3]: ' protocol_choice
case "${protocol_choice:-3}" in
  1|vless|VLESS) protocol="vless" ;;
  2|trojan|TROJAN) protocol="trojan" ;;
  3|hysteria|hy2|HY2) protocol="hysteria" ;;
  *) fail "不支持的协议选项" ;;
esac

read -rp '请输入节点端口 [默认 24129]: ' node_port
node_port="${node_port:-24129}"
valid_port "${node_port}" || fail "节点端口无效"

read -rp '请输入 3x-ui 面板端口 [默认 3322]: ' panel_port
panel_port="${panel_port:-3322}"
valid_port "${panel_port}" || fail "面板端口无效"

read -rp '请输入订阅端口 [默认 2096]: ' sub_port
sub_port="${sub_port:-2096}"
valid_port "${sub_port}" || fail "订阅端口无效"

[[ "${node_port}" != "${panel_port}" && "${node_port}" != "${sub_port}" && "${panel_port}" != "${sub_port}" ]] \
  || fail "节点、面板和订阅端口不能相同"

read -rp '证书方式：输入域名，直接回车则申请公网 IP 证书: ' tls_domain
read -rp 'Let’s Encrypt 邮箱（可留空）: ' acme_email

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl openssl python3 cron socat

public_ip="$(curl -4fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
[[ -n "${public_ip}" ]] || fail "无法识别公网 IPv4，请稍后重试"
if [[ -n "${tls_domain}" ]]; then
  tls_host="${tls_domain}"
  ssl_mode="domain"
  cert_dir="/root/cert/${tls_domain}"
else
  tls_host="${public_ip}"
  ssl_mode="ip"
  cert_dir="/root/cert/ip"
fi

printf '%s\n' '[1/5] 安装节点出口管理系统...'
bash "${SCRIPT_DIR}/install-core.sh"

printf '%s\n' '[2/5] 安装或升级 3x-ui，并申请证书...'
if [[ ! -x /usr/local/x-ui/x-ui ]]; then
  export XUI_NONINTERACTIVE=1
  export XUI_USERNAME="admin_$(random_text 4)"
  export XUI_PASSWORD="$(random_text 12)"
  export XUI_WEB_BASE_PATH="$(random_text 10)"
  export XUI_PANEL_PORT="${panel_port}"
  export XUI_SSL_MODE="${ssl_mode}"
  export XUI_DOMAIN="${tls_domain}"
  export XUI_SERVER_IP="${public_ip}"
  export XUI_ACME_EMAIL="${acme_email}"
  xui_installer="$(mktemp /tmp/3x-ui-install.XXXXXX)"
  curl -fsSL "${XUI_INSTALL_URL}" -o "${xui_installer}"
  bash "${xui_installer}"
  rm -f -- "${xui_installer}"
else
  printf '%s\n' '检测到已有 3x-ui，保留面板账号并复用现有证书。'
fi

cert_file="${cert_dir}/fullchain.pem"
key_file="${cert_dir}/privkey.pem"
[[ -s "${cert_file}" && -s "${key_file}" ]] || fail "证书不存在。请确认公网 TCP 80 已放行，且域名已解析到 ${public_ip}"
chmod 600 "${key_file}"
chmod 644 "${cert_file}"

printf '%s\n' '[3/5] 加固证书自动续签...'
cat > /etc/systemd/system/node-gateway-cert-renew.service <<'EOF'
[Unit]
Description=Renew 3x-ui TLS certificate
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/root/.acme.sh/acme.sh --cron --home /root/.acme.sh
ExecStartPost=/bin/systemctl try-restart x-ui.service
EOF
cat > /etc/systemd/system/node-gateway-cert-renew.timer <<'EOF'
[Unit]
Description=Daily TLS certificate renewal check

[Timer]
OnCalendar=*-*-* 03:25:00
RandomizedDelaySec=45m
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now node-gateway-cert-renew.timer

printf '%s\n' '[4/5] 自动创建入站、订阅和出口路由...'
systemctl stop x-ui
install -o root -g root -m 0700 "${SCRIPT_DIR}/xui_provision.py" /usr/local/sbin/node-gateway-provision
result_json="$(/usr/local/sbin/node-gateway-provision \
  --protocol "${protocol}" \
  --port "${node_port}" \
  --host "${tls_host}" \
  --cert "${cert_file}" \
  --key "${key_file}" \
  --proxy-port "${PROXY_PORT:-7928}" \
  --sub-port "${sub_port}")"

systemctl restart x-ui
sleep 5
if ! systemctl is-active --quiet x-ui; then
  backup="$(python3 -c 'import json; print(json.load(open("/etc/x-ui/gateway-result.json"))["backup"])')"
  [[ -f "${backup}" ]] && cp -p -- "${backup}" /etc/x-ui/x-ui.db
  systemctl restart x-ui || true
  fail "新入站启动失败，3x-ui 数据库已自动恢复"
fi

printf '%s\n' '[5/6] 安装多国家独立出口（默认 7825 美国、7866 日本、7888 韩国）...'
bash "${SCRIPT_DIR}/install-multi-exit.sh"

printf '%s\n' '[6/6] 设置防火墙并输出结果...'
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow "${panel_port}/tcp" comment '3x-ui panel'
  ufw allow "${sub_port}/tcp" comment '3x-ui subscription'
  if [[ "${protocol}" == "hysteria" ]]; then
    ufw allow "${node_port}/udp" comment 'Hysteria2 inbound'
  else
    ufw allow "${node_port}/tcp" comment 'Proxy inbound'
  fi
  ufw allow 80/tcp comment 'ACME renewal'
fi

python3 - <<'PY'
import json
from pathlib import Path

result = json.loads(Path('/etc/x-ui/gateway-result.json').read_text(encoding='utf-8'))
print('\n统一节点系统安装完成')
print('协议：', result['protocol'])
print('节点端口：', result['port'])
print('通用订阅：', result['subscription'])
print('Clash 订阅：', result['clash'])
print('续签定时器：node-gateway-cert-renew.timer（每天自动检查）')
print('3x-ui 面板凭据：/etc/x-ui/install-result.env（仅 root 可读）')
PY

printf '\n请在云服务商安全组放行：TCP 80、TCP %s、TCP %s，以及节点端口 %s/%s。\n' \
  "${panel_port}" "${sub_port}" "${node_port}" "$([[ "${protocol}" == "hysteria" ]] && echo UDP || echo TCP)"
