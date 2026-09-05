#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf '%s\n' '请使用 sudo bash uninstall.sh [--purge] 运行。' >&2
  exit 1
fi

systemctl disable --now aimilivpn.service 2>/dev/null || true
rm -f -- /etc/systemd/system/aimilivpn.service
systemctl daemon-reload
rm -f -- /etc/default/aimilivpn /usr/local/sbin/aimilivpnctl /usr/local/bin/ml
rm -rf -- /opt/aimilivpn

if [[ "${1:-}" == "--purge" ]]; then
  rm -rf -- /var/lib/aimilivpn
  printf '%s\n' '程序和节点数据均已删除。'
else
  printf '%s\n' '程序已卸载，设置与数据保留在 /var/lib/aimilivpn。'
  printf '%s\n' '如需彻底删除：sudo bash uninstall.sh --purge'
fi
