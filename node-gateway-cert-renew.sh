#!/usr/bin/env bash
set -Eeuo pipefail

ACME_HOME="${ACME_HOME:-/root/.acme.sh}"
ACME_BIN="${ACME_BIN:-${ACME_HOME}/acme.sh}"
CERT_ROOT="${CERT_ROOT:-/root/cert}"

certificate_digest() {
  local file
  local found=0
  while IFS= read -r -d '' file; do
    found=1
    printf '%s  %s\n' "$(sha256sum "$file" | awk '{print $1}')" "$file"
  done < <(find "$CERT_ROOT" -mindepth 2 -maxdepth 2 -type f -name fullchain.pem -print0 2>/dev/null | sort -z)
  (( found == 1 )) || printf '%s\n' 'no-installed-certificate'
}

service_pid() {
  systemctl show "$1" -p MainPID --value 2>/dev/null || printf '0\n'
}

reload_if_stale() {
  local service="$1" old_pid="$2" new_pid
  systemctl is-active --quiet "$service" || return 0
  new_pid="$(service_pid "$service")"
  if [[ -n "$old_pid" && "$old_pid" != "0" && "$new_pid" == "$old_pid" ]]; then
    printf '证书已更新，正在让 %s 重新加载新证书。\n' "$service"
    systemctl try-restart "$service"
  fi
}

main() {
  [[ -x "$ACME_BIN" ]] || { printf '未找到 acme.sh：%s\n' "$ACME_BIN" >&2; exit 1; }
  local before after xui_pid manager_pid
  before="$(certificate_digest)"
  xui_pid="$(service_pid x-ui.service)"
  manager_pid="$(service_pid aimilivpn.service)"

  "$ACME_BIN" --cron --home "$ACME_HOME"
  after="$(certificate_digest)"
  if [[ "$before" == "$after" ]]; then
    printf '%s\n' '证书没有变化，现有服务保持运行。'
    return 0
  fi

  reload_if_stale x-ui.service "$xui_pid"
  reload_if_stale aimilivpn.service "$manager_pid"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
