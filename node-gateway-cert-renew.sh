#!/usr/bin/env bash
set -Eeuo pipefail

ACME_HOME="${ACME_HOME:-/root/.acme.sh}"
ACME_BIN="${ACME_BIN:-${ACME_HOME}/acme.sh}"
CERT_ROOT="${CERT_ROOT:-/root/cert}"
CERT_STATE_DIR="${CERT_STATE_DIR:-/var/lib/aimilivpn}"
CERT_LOCK_FILE="${CERT_LOCK_FILE:-/run/node-gateway-cert-renew.lock}"
CERT_DIGEST_FILE="${CERT_STATE_DIR}/cert-loaded.digest"
ACME_CHECK_FILE="${CERT_STATE_DIR}/cert-acme-last-check"
ACME_CHECK_INTERVAL="${ACME_CHECK_INTERVAL:-86400}"

certificate_digest() {
  local file found=0
  while IFS= read -r -d '' file; do
    found=1
    printf '%s  %s\n' "$(sha256sum "$file" | awk '{print $1}')" "$file"
  done < <(find "$CERT_ROOT" -mindepth 2 -maxdepth 2 -type f -name fullchain.pem -print0 2>/dev/null | sort -z)
  (( found == 1 )) || printf '%s\n' 'no-installed-certificate'
}

write_state() {
  local target="$1" value="$2" temporary
  install -d -m 0700 "$CERT_STATE_DIR"
  temporary="$(mktemp "${CERT_STATE_DIR}/.cert-state.XXXXXX")"
  printf '%s\n' "$value" > "$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$target"
}

renew_if_due() {
  local now previous=0
  [[ -x "$ACME_BIN" ]] || { printf '未找到 acme.sh：%s\n' "$ACME_BIN" >&2; return 1; }
  [[ "$ACME_CHECK_INTERVAL" =~ ^[0-9]+$ ]] || { printf 'ACME_CHECK_INTERVAL 必须为秒数。\n' >&2; return 1; }
  now="$(date +%s)"
  if [[ -f "$ACME_CHECK_FILE" ]]; then
    read -r previous < "$ACME_CHECK_FILE" || true
    [[ "$previous" =~ ^[0-9]+$ ]] || previous=0
  fi
  if (( now - previous < ACME_CHECK_INTERVAL )); then
    return 0
  fi
  local result=0
  "$ACME_BIN" --cron --home "$ACME_HOME" || result=$?
  (( result == 0 )) || return "$result"
  write_state "$ACME_CHECK_FILE" "$now"
}

reconcile_loaded_certificate() {
  local current previous='' service
  current="$(certificate_digest)"
  if [[ "$current" == 'no-installed-certificate' ]]; then
    printf '%s\n' '未发现已安装的证书，跳过服务重载。'
    return 0
  fi
  if [[ -f "$CERT_DIGEST_FILE" ]]; then
    previous="$(< "$CERT_DIGEST_FILE")"
  fi
  if [[ "$current" == "$previous" ]]; then
    printf '%s\n' '证书没有变化，现有服务保持运行。'
    return 0
  fi
  for service in x-ui.service aimilivpn.service; do
    if systemctl is-active --quiet "$service"; then
      printf '检测到新证书，正在重新载入 %s。\n' "$service"
      local result=0
      systemctl restart "$service" || result=$?
      (( result == 0 )) || return "$result"
      systemctl is-active --quiet "$service" || return 1
    fi
  done
  write_state "$CERT_DIGEST_FILE" "$current"
}

main() {
  local mode="${1:-}" acme_status=0 lock_dir
  [[ $# -le 1 && ( -z "$mode" || "$mode" == '--check' || "$mode" == '--mark-loaded' ) ]] \
    || { printf '用法：%s [--check|--mark-loaded]\n' "$0" >&2; return 2; }
  lock_dir="$(dirname "$CERT_LOCK_FILE")"
  [[ -d "$lock_dir" ]] || install -d -m 0700 "$lock_dir"
  exec 9> "$CERT_LOCK_FILE"
  flock 9

  if [[ "$mode" == '--mark-loaded' ]]; then
    local current
    current="$(certificate_digest)"
    [[ "$current" == 'no-installed-certificate' ]] || write_state "$CERT_DIGEST_FILE" "$current"
    return 0
  fi
  if [[ "$mode" != '--check' ]]; then
    renew_if_due || acme_status=$?
  fi
  reconcile_loaded_certificate
  return "$acme_status"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
