#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo '请使用 sudo 运行'; exit 1; }
app=/opt/aimilivpn
[[ -f "$app/vpngate_manager.py" ]] || { echo '未检测到已安装后台'; exit 1; }
work=$(mktemp -d /tmp/gateway-dashboard.XXXXXX)
backup="/var/backups/aimilivpn/dashboard-43-$(date +%Y%m%d-%H%M%S)-$$"
cleanup() {
  [[ "$work" == /tmp/gateway-dashboard.* && -d "$work" ]] && rm -rf -- "$work"
}
trap cleanup EXIT

# Resolve main once: helpers and services must come from the exact same revision.
ref="${GATEWAY_GIT_REF:-}"
if [[ -z "$ref" ]]; then
  curl -fsSL --retry 2 --connect-timeout 15 \
    https://api.github.com/repos/GaryTung/newinstall/commits/main -o "$work/revision.json"
  ref=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha"])' "$work/revision.json")
fi
[[ "$ref" =~ ^[0-9a-f]{40}$ ]] || { echo '无法确定升级版本，请稍后重试'; exit 1; }
base="https://raw.githubusercontent.com/GaryTung/newinstall/$ref"
sources=(vpngate_manager.py xui_multi_provision.py multi_exit_manager.py channel_network.py channel_policy.py migrate_network_slots.py exit_speed.py proxy_server.py)
for file in "${sources[@]}" VERSION; do
  curl -fsSL --retry 2 --connect-timeout 15 "$base/$file" -o "$work/$file"
done
for file in "${sources[@]}"; do
  python3 -m py_compile "$work/$file"
done

targets=(
  "$app/vpngate_manager.py" "$app/channel_network.py" "$app/channel_policy.py"
  "$app/migrate_network_slots.py" "$app/VERSION"
  "$app/exit_speed.py" "$app/proxy_server.py" /var/lib/aimilivpn-multiexit/speed_results.json
  /usr/local/sbin/xui-multi-provision /usr/local/sbin/aimilivpn-multiexit
  /var/lib/aimilivpn-multiexit/channels.json /var/lib/aimilivpn-multiexit/state.json
  /var/lib/aimilivpn-multiexit/deep_failures.json /var/lib/aimilivpn-multiexit/verified_exits.json
  /etc/x-ui/multi-exit-result.json /etc/x-ui/x-ui.db
  /etc/x-ui/x-ui.db-wal /etc/x-ui/x-ui.db-shm
)
active_services=()
for service in aimilivpn aimilivpn-multiexit x-ui; do
  if systemctl is-active --quiet "$service"; then active_services+=("$service"); fi
done
restore_ready=0
rollback() {
  local status="${1:-1}" index target
  trap - ERR INT TERM
  set +e
  systemctl stop aimilivpn aimilivpn-multiexit x-ui
  if [[ "$restore_ready" == 1 ]]; then
    for index in "${!targets[@]}"; do
      target="${targets[$index]}"
      if [[ -f "$backup/files/$index" ]]; then
        cp -p -- "$backup/files/$index" "$target"
      elif [[ -f "$backup/files/$index.absent" ]]; then
        rm -f -- "$target"
      fi
    done
  fi
  for service in x-ui aimilivpn-multiexit aimilivpn; do
    for active in "${active_services[@]}"; do
      [[ "$service" != "$active" ]] || systemctl start "$service"
    done
  done
  printf '升级失败，已恢复备份的程序和配置，原有服务已尝试重新启动。备份：%s\n' "$backup" >&2
  printf '迁移过的内部网络会在服务重连时重新配置；请检查 sudo journalctl -u aimilivpn-multiexit -n 60\n' >&2
  exit "$status"
}
trap 'rollback $?' ERR
trap 'rollback 130' INT TERM

# Stop all writers before copying JSON/SQLite, including any WAL companions.
systemctl stop aimilivpn aimilivpn-multiexit x-ui
install -d -m 0700 "$backup/files"
printf '%s\n' "${targets[@]}" > "$backup/manifest.txt"
printf '%s\n' "$ref" > "$backup/target-revision.txt"
for index in "${!targets[@]}"; do
  if [[ -f "${targets[$index]}" ]]; then
    cp -p -- "${targets[$index]}" "$backup/files/$index"
  else
    : > "$backup/files/$index.absent"
  fi
done
restore_ready=1
install -m 0644 "$work/channel_network.py" "$app/channel_network.py"
install -m 0644 "$work/channel_policy.py" "$app/channel_policy.py"
install -m 0644 "$work/exit_speed.py" "$app/exit_speed.py"
install -m 0755 "$work/proxy_server.py" "$app/proxy_server.py"
install -m 0755 "$work/migrate_network_slots.py" "$app/migrate_network_slots.py"
install -m 0755 "$work/vpngate_manager.py" "$app/vpngate_manager.py"
install -m 0755 "$work/xui_multi_provision.py" /usr/local/sbin/xui-multi-provision
install -m 0755 "$work/multi_exit_manager.py" /usr/local/sbin/aimilivpn-multiexit
install -m 0644 "$work/VERSION" "$app/VERSION"
python3 "$work/migrate_network_slots.py" --apply
systemctl start x-ui
systemctl start aimilivpn-multiexit
systemctl start aimilivpn
sleep 8
systemctl is-active --quiet x-ui
systemctl is-active --quiet aimilivpn-multiexit
systemctl is-active --quiet aimilivpn
trap - ERR INT TERM
printf '后台升级完成，出口测速择优与 DNS 缓存已启用；线路将自动恢复，测速在恢复后后台执行。备份：%s\n' "$backup"
