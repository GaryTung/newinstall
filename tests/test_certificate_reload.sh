#!/usr/bin/env bash
set -Eeuo pipefail

repository="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
workspace="$(mktemp -d)"
trap 'rm -rf -- "$workspace"' EXIT

mkdir -p "$workspace/bin" "$workspace/certs/ip" "$workspace/acme"
printf 'certificate-v1\n' > "$workspace/certs/ip/fullchain.pem"
: > "$workspace/restarts.log"
: > "$workspace/acme.log"

cat > "$workspace/bin/systemctl" <<'MOCK_SYSTEMCTL'
#!/usr/bin/env bash
if [[ "$1" == 'is-active' ]]; then
  exit 0
fi
if [[ "$1" == 'restart' ]]; then
  printf '%s\n' "$2" >> "$TEST_RESTART_LOG"
  [[ "$2" == "${FAIL_SERVICE:-}" ]] && exit 1
  exit 0
fi
exit 2
MOCK_SYSTEMCTL

cat > "$workspace/acme.sh" <<'MOCK_ACME'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TEST_ACME_LOG"
if [[ -n "${MOCK_ACME_CERT_UPDATE:-}" ]]; then
  printf '%s\n' "$MOCK_ACME_CERT_UPDATE" > "$CERT_ROOT/ip/fullchain.pem"
fi
[[ "${MOCK_ACME_FAIL:-0}" == 1 ]] && exit 1
exit 0
MOCK_ACME
chmod 0755 "$workspace/bin/systemctl" "$workspace/acme.sh"

export PATH="$workspace/bin:$PATH"
export CERT_ROOT="$workspace/certs"
export CERT_STATE_DIR="$workspace/state"
export CERT_LOCK_FILE="$workspace/lock/renew.lock"
export ACME_HOME="$workspace/acme"
export ACME_BIN="$workspace/acme.sh"
export TEST_RESTART_LOG="$workspace/restarts.log"
export TEST_ACME_LOG="$workspace/acme.log"
renew="$repository/node-gateway-cert-renew.sh"

assert_count() {
  local file="$1" expected="$2" actual
  actual="$(wc -l < "$file")"
  [[ "$actual" -eq "$expected" ]] || {
    printf 'Expected %s lines in %s, got %s\n' "$expected" "$file" "$actual" >&2
    exit 1
  }
}

bash "$renew" --mark-loaded
bash "$renew" --check
assert_count "$TEST_RESTART_LOG" 0
assert_count "$TEST_ACME_LOG" 0

# A separate acme.sh cron updates the installed certificate before our timer runs.
printf 'certificate-v2\n' > "$CERT_ROOT/ip/fullchain.pem"
bash "$renew" --check
assert_count "$TEST_RESTART_LOG" 2
bash "$renew" --check
assert_count "$TEST_RESTART_LOG" 2

export MOCK_ACME_CERT_UPDATE=certificate-v3
export ACME_CHECK_INTERVAL=0
bash "$renew"
assert_count "$TEST_RESTART_LOG" 4
assert_count "$TEST_ACME_LOG" 1
unset MOCK_ACME_CERT_UPDATE
export ACME_CHECK_INTERVAL=86400
bash "$renew"
assert_count "$TEST_ACME_LOG" 1

# Do not record a new certificate if a service failed to reload.
printf 'certificate-v4\n' > "$CERT_ROOT/ip/fullchain.pem"
export FAIL_SERVICE=aimilivpn.service
if bash "$renew" --check; then
  printf 'Expected the failed service restart to return an error\n' >&2
  exit 1
fi
unset FAIL_SERVICE
bash "$renew" --check
assert_count "$TEST_RESTART_LOG" 8

# Even if acme.sh fails, an already installed new certificate is reloaded.
printf 'certificate-v5\n' > "$CERT_ROOT/ip/fullchain.pem"
export MOCK_ACME_FAIL=1
export ACME_CHECK_INTERVAL=0
if bash "$renew"; then
  printf 'Expected the acme.sh error to be reported\n' >&2
  exit 1
fi
assert_count "$TEST_RESTART_LOG" 10

printf 'certificate reload integration tests passed\n'
