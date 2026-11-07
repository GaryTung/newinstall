#!/usr/bin/env bash
# Only receive socket buffers; no DNS cache, speed tests or VPNGate jobs.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo '请使用 sudo 运行'; exit 1; }
restart=0
case "${1:-}" in
  '') ;;
  --restart-xray) restart=1 ;;
  *) echo '用法：configure-udp-buffer.sh [--restart-xray]' >&2; exit 2 ;;
esac

configure_udp_receive_buffer() {
  local target="${1:-/etc/sysctl.d/90-hy2-udp-recv.conf}"
  local previous_default previous_max backup temporary
  previous_default=$(sysctl -n net.core.rmem_default)
  previous_max=$(sysctl -n net.core.rmem_max)
  backup=$(mktemp -d /var/backups/aimilivpn/udp-buffer.XXXXXX)
  printf '%s\n' "$previous_default" > "$backup/rmem_default"
  printf '%s\n' "$previous_max" > "$backup/rmem_max"
  if [[ -f "$target" ]]; then cp -p -- "$target" "$backup/config"; fi
  temporary=$(mktemp "${target}.XXXXXX")
  printf '%s\n' \
    '# HY2 receive socket buffer defaults: 4 MiB (not DNS cache).' \
    '# Existing sockets pick up the default after the proxy service restarts.' \
    'net.core.rmem_max = 4194304' \
    'net.core.rmem_default = 4194304' > "$temporary"
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$target"
  if ! sysctl -p "$target" \
      || [[ $(sysctl -n net.core.rmem_default) != 4194304 ]] \
      || [[ $(sysctl -n net.core.rmem_max) != 4194304 ]]; then
    if [[ -f "$backup/config" ]]; then cp -p -- "$backup/config" "$target";
    else rm -f -- "$target"; fi
    sysctl -w "net.core.rmem_max=$previous_max" "net.core.rmem_default=$previous_default" || true
    echo "UDP 接收缓冲区设置失败，已尝试恢复；备份：$backup" >&2
    return 1
  fi
  printf 'UDP 接收缓冲区默认值及上限已设为 4 MiB；备份：%s\n' "$backup"
}

install -d -m 0700 /var/backups/aimilivpn
configure_udp_receive_buffer
if [[ $restart == 1 ]] && systemctl is-active --quiet x-ui; then
  systemctl restart x-ui
  systemctl is-active --quiet x-ui
else
  echo '已运行的代理连接需在服务下次重启后使用新的默认缓冲区。'
fi
