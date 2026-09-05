#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/aimilivpn"
DATA_DIR="/var/lib/aimilivpn-multiexit"
CHANNEL_FILE="${DATA_DIR}/channels.json"

fail() { printf '多国家出口安装失败：%s\n' "$*" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || fail "请使用 sudo bash install-multi-exit.sh"
[[ -x /usr/local/x-ui/x-ui && -f /etc/x-ui/x-ui.db ]] || fail "未检测到 3x-ui，请先执行统一安装器"
[[ -f "${APP_DIR}/proxy_server.py" ]] || fail "未检测到节点管理系统"

for file in multi_exit_manager.py xui_multi_provision.py; do
  [[ -f "${SCRIPT_DIR}/${file}" ]] || fail "安装包缺少 ${file}"
done

apt-get update
apt-get install -y --no-install-recommends iproute2 iptables curl openvpn python3
modprobe tun 2>/dev/null || true
[[ -c /dev/net/tun ]] || fail "未检测到 /dev/net/tun"

install -d -o root -g root -m 0700 "${DATA_DIR}"
install -o root -g root -m 0755 "${SCRIPT_DIR}/multi_exit_manager.py" /usr/local/sbin/aimilivpn-multiexit
install -o root -g root -m 0755 "${SCRIPT_DIR}/xui_multi_provision.py" /usr/local/sbin/xui-multi-provision

if [[ ! -s "${CHANNEL_FILE}" ]]; then
  cat > "${CHANNEL_FILE}" <<'EOF'
{
  "version": 4,
  "direct_protocol": "hysteria",
  "channels": [
    {
      "id": "us",
      "name": "美国线路",
      "inbound_port": 7825,
      "country": "美国",
      "protocol": "hysteria",
      "ip_type": "residential_preferred",
      "enabled": true,
      "tested_only": true,
      "awaiting_initial_test": true,
      "standby_hot_target": 3,
      "standby_normal_target": 2
    },
    {
      "id": "jp",
      "name": "日本线路",
      "inbound_port": 7866,
      "country": "日本",
      "protocol": "trojan",
      "ip_type": "all",
      "enabled": true,
      "tested_only": true,
      "awaiting_initial_test": true,
      "standby_hot_target": 3,
      "standby_normal_target": 2
    },
    {
      "id": "kr",
      "name": "韩国线路",
      "inbound_port": 7888,
      "country": "韩国",
      "protocol": "vless",
      "ip_type": "all",
      "enabled": true,
      "tested_only": true,
      "awaiting_initial_test": true,
      "standby_hot_target": 3,
      "standby_normal_target": 2
    }
  ]
}
EOF
  chmod 0600 "${CHANNEL_FILE}"
fi

cat > /etc/systemd/system/aimilivpn-multiexit.service <<EOF
[Unit]
Description=Multi-country isolated VPNGate exits
Wants=network-online.target aimilivpn.service
After=network-online.target aimilivpn.service

[Service]
Type=simple
Environment=VPNGATE_APP_DIR=${APP_DIR}
Environment=MULTI_EXIT_DATA_DIR=${DATA_DIR}
ExecStart=/usr/bin/python3 -u /usr/local/sbin/aimilivpn-multiexit daemon
Restart=always
RestartSec=10
UMask=0077
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl stop x-ui
/usr/local/sbin/xui-multi-provision --channels "${CHANNEL_FILE}"
systemctl daemon-reload
systemctl enable --now aimilivpn-multiexit.service
systemctl restart x-ui
sleep 5
systemctl is-active --quiet x-ui || fail "3x-ui 启动失败，数据库备份位置记录在 /etc/x-ui/multi-exit-result.json"
systemctl is-active --quiet aimilivpn-multiexit || fail "多国家出口服务启动失败"

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  python3 - "${CHANNEL_FILE}" <<'PY' | while read -r proto port; do
import json, sys
cfg=json.load(open(sys.argv[1], encoding='utf-8'))
for item in cfg.get('channels', []):
    if item.get('enabled', True): print('udp' if item.get('protocol', 'hysteria') == 'hysteria' else 'tcp', int(item['inbound_port']))
PY
    ufw allow "${port}/${proto}" comment "Country exit ${port}"
  done
fi

printf '\n%s\n' '多国家出口已部署：'
python3 - <<'PY'
import json
r=json.load(open('/etc/x-ui/multi-exit-result.json', encoding='utf-8'))
for c in r['channels']:
    print(f"- {c['port']} -> {c['country']} ({c['protocol']})，本地出口 {c['proxy_address']}:1080")
print('状态命令：sudo ml channels')
print('配置文件：/var/lib/aimilivpn-multiexit/channels.json')
PY
