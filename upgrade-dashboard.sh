#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo '请使用 sudo 运行'; exit 1; }
app=/opt/aimilivpn
[[ -f "$app/vpngate_manager.py" ]] || { echo '未检测到已安装后台'; exit 1; }
work=$(mktemp -d /tmp/gateway-dashboard.XXXXXX)
backup="/var/backups/aimilivpn/dashboard-35-$(date +%Y%m%d-%H%M%S)-$$"
trap 'rm -rf -- "$work"' EXIT
base=https://raw.githubusercontent.com/GaryTung/newinstall/main
curl -fSL --retry 2 --connect-timeout 15 "$base/vpngate_manager.py" -o "$work/vpngate_manager.py"
curl -fSL --retry 2 --connect-timeout 15 "$base/VERSION" -o "$work/VERSION"
python3 -m py_compile "$work/vpngate_manager.py"
install -d -m 0700 "$backup"
cp -p "$app/vpngate_manager.py" "$backup/vpngate_manager.py"
[[ ! -f "$app/VERSION" ]] || cp -p "$app/VERSION" "$backup/VERSION"
install -m 0755 "$work/vpngate_manager.py" "$app/vpngate_manager.py"
install -m 0644 "$work/VERSION" "$app/VERSION"
if systemctl restart aimilivpn; then
  sleep 8
  if systemctl is-active --quiet aimilivpn; then
    printf '后台升级完成，待检测国家将在后台自动进入检测。备份：%s\n' "$backup"
    exit 0
  fi
fi
cp -p "$backup/vpngate_manager.py" "$app/vpngate_manager.py"
[[ ! -f "$backup/VERSION" ]] || cp -p "$backup/VERSION" "$app/VERSION"
systemctl restart aimilivpn || true
echo '后台启动失败，已恢复旧版。请查看 sudo journalctl -u aimilivpn -n 60'
exit 1
