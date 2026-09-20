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

for file in multi_exit_manager.py xui_multi_provision.py channel_network.py channel_policy.py migrate_network_slots.py exit_speed.py; do
  [[ -f "${SCRIPT_DIR}/${file}" ]] || fail "安装包缺少 ${file}"
done

apt-get update
apt-get install -y --no-install-recommends iproute2 iptables curl openvpn python3
modprobe tun 2>/dev/null || true
[[ -c /dev/net/tun ]] || fail "未检测到 /dev/net/tun"

install -d -o root -g root -m 0700 "${DATA_DIR}"
existing_channels=0
[[ ! -s "${CHANNEL_FILE}" ]] || existing_channels=1
backup="/var/backups/aimilivpn/multi-install-43-$(date +%Y%m%d-%H%M%S)-$$"
targets=(
  "${APP_DIR}/channel_network.py" "${APP_DIR}/channel_policy.py" "${APP_DIR}/migrate_network_slots.py"
  "${APP_DIR}/exit_speed.py"
  /usr/local/sbin/aimilivpn-multiexit /usr/local/sbin/xui-multi-provision
  /etc/systemd/system/aimilivpn-multiexit.service
  "${CHANNEL_FILE}" "${DATA_DIR}/state.json" "${DATA_DIR}/deep_failures.json" "${DATA_DIR}/verified_exits.json"
  /etc/x-ui/multi-exit-result.json /etc/x-ui/x-ui.db /etc/x-ui/x-ui.db-wal /etc/x-ui/x-ui.db-shm
)
active_services=()
for service in aimilivpn aimilivpn-multiexit x-ui; do
  if systemctl is-active --quiet "$service"; then active_services+=("$service"); fi
done
was_enabled=0
if systemctl is-enabled --quiet aimilivpn-multiexit; then was_enabled=1; fi
restore_ready=0
rollback_multi_install() {
  local status="${1:-1}" index service active
  trap - ERR INT TERM
  set +e
  systemctl stop aimilivpn aimilivpn-multiexit x-ui
  if [[ "$was_enabled" == 0 ]]; then systemctl disable aimilivpn-multiexit; fi
  if [[ "$restore_ready" == 1 ]]; then
    for index in "${!targets[@]}"; do
      if [[ -f "$backup/files/$index" ]]; then
        cp -p -- "$backup/files/$index" "${targets[$index]}"
      elif [[ -f "$backup/files/$index.absent" ]]; then
        rm -f -- "${targets[$index]}"
      fi
    done
  fi
  systemctl daemon-reload
  for service in x-ui aimilivpn-multiexit aimilivpn; do
    for active in "${active_services[@]}"; do
      [[ "$service" != "$active" ]] || systemctl start "$service"
    done
  done
  printf '多国家安装未完成，已恢复本步骤备份并尝试重启原服务：%s\n' "$backup" >&2
  printf '内部网络将在服务重连时重新配置；请检查 sudo journalctl -u aimilivpn-multiexit -n 60\n' >&2
  exit "$status"
}
trap 'rollback_multi_install $?' ERR
trap 'rollback_multi_install 130' INT TERM
# The daemon may not be installed on a fresh host; only stop units that exist.
for service in aimilivpn aimilivpn-multiexit x-ui; do
  if [[ "$(systemctl show -p LoadState --value "$service")" != not-found ]]; then
    systemctl stop "$service"
  fi
done
install -d -m 0700 "$backup/files"
printf '%s\n' "${targets[@]}" > "$backup/manifest.txt"
for index in "${!targets[@]}"; do
  if [[ -f "${targets[$index]}" ]]; then
    cp -p -- "${targets[$index]}" "$backup/files/$index"
  else
    : > "$backup/files/$index.absent"
  fi
done
restore_ready=1
install -o root -g root -m 0644 "${SCRIPT_DIR}/channel_network.py" "${APP_DIR}/channel_network.py"
install -o root -g root -m 0644 "${SCRIPT_DIR}/channel_policy.py" "${APP_DIR}/channel_policy.py"
install -o root -g root -m 0644 "${SCRIPT_DIR}/exit_speed.py" "${APP_DIR}/exit_speed.py"
install -o root -g root -m 0755 "${SCRIPT_DIR}/migrate_network_slots.py" "${APP_DIR}/migrate_network_slots.py"
install -o root -g root -m 0755 "${SCRIPT_DIR}/multi_exit_manager.py" /usr/local/sbin/aimilivpn-multiexit
install -o root -g root -m 0755 "${SCRIPT_DIR}/xui_multi_provision.py" /usr/local/sbin/xui-multi-provision

if [[ ! -s "${CHANNEL_FILE}" ]]; then
  install_date="$(date +%Y%m%d)"
  install_epoch="$(date +%s)"
  cat > "${CHANNEL_FILE}" <<EOF
{
  "version": 4,
  "direct_protocol": "hysteria",
  "channels": [
    {
      "id": "us",
      "name": "美国-${install_date}",
      "created_at": ${install_epoch},
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
      "name": "日本-${install_date}",
      "created_at": ${install_epoch},
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
      "name": "韩国-${install_date}",
      "created_at": ${install_epoch},
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

if [[ "$existing_channels" == 1 ]]; then
  python3 "${SCRIPT_DIR}/migrate_network_slots.py" --apply
fi
/usr/local/sbin/xui-multi-provision --channels "${CHANNEL_FILE}"
systemctl daemon-reload
systemctl enable aimilivpn-multiexit.service
systemctl restart x-ui
systemctl restart aimilivpn-multiexit
systemctl start aimilivpn
sleep 5
systemctl is-active --quiet x-ui
systemctl is-active --quiet aimilivpn-multiexit
systemctl is-active --quiet aimilivpn
trap - ERR INT TERM

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
