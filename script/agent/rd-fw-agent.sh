#!/bin/bash
# redis-fw-agent 통합 헬스체크 & 운영 스크립트 (URI 미지원 redis-cli 호환판)
# - redis-cli -u 미사용, host/port/password 추출 후 -h/-p/-a로 호출
# - URL 인코딩된 REDIS_URL 비밀번호는 python(venv)로 unquote

set -euo pipefail

SERVICE="redis-fw-agent"
UNIT_FILE="/etc/systemd/system/${SERVICE}.service"
PYTHON="/opt/py38-venv/bin/python"   # url decode에 사용


err() { echo "[ERROR] $*" >&2; exit 1; }
ok()  { echo "[OK] $*"; }
info(){ echo "==> $*"; }

require_cmds() {
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || err "missing command: $c"; done
}

# unit 파일에서 REDIS_URL=... 추출
get_redis_url() {
  [ -r "$UNIT_FILE" ] || err "unit file not found: $UNIT_FILE"
  line=$(grep -E '^Environment="REDIS_URL=' "$UNIT_FILE" || true)
  [ -n "${line:-}" ] || err "REDIS_URL not found in unit file"
  echo "$line" | sed -E 's/^Environment="REDIS_URL=([^"]+)".*/\1/'
}

# REDIS_URL에서 host/port/encoded_pw 파싱 후 decoded_pw까지 전역 변수로 준비
# 지원하는 URL 예: redis://:ENCODED_PW@127.0.0.1:6379/0
parse_redis_url() {
  local url="$1"

  # host
  HOST=$(echo "$url" | sed -E 's|redis://:[^@]+@([^:/]+).*|\1|')
  [ -n "${HOST:-}" ] || HOST="127.0.0.1"

  # port
  PORT=$(echo "$url" | sed -E 's|.*:([0-9]+)/.*|\1|')
  [[ "$PORT" =~ ^[0-9]+$ ]] || PORT="6379"

  # encoded password
  PW_ENC=$(echo "$url" | sed -E 's|redis://:([^@]+)@.*|\1|')
  [ -n "${PW_ENC:-}" ] || PW_ENC=""

  # decode password via python urllib.parse.unquote
  if [ -n "$PW_ENC" ]; then
    PW_DEC=$("$PYTHON" - <<'PY' "$PW_ENC"
import sys, urllib.parse as u
print(u.unquote(sys.argv[1]))
PY
)
  else
    PW_DEC=""
  fi
}

redis_ping() {
  local host="$1" port="$2" pass="$3"
  if [ -n "$pass" ]; then
    redis-cli -h "$host" -p "$port" -a "$pass" ping | grep -q '^PONG$'
  else
    redis-cli -h "$host" -p "$port" ping | grep -q '^PONG$'
  fi
}

redis_publish() {
  local host="$1" port="$2" pass="$3" channel="$4" payload="$5"
  if [ -n "$pass" ]; then
    redis-cli -h "$host" -p "$port" -a "$pass" PUBLISH "$channel" "$payload" >/dev/null
  else
    redis-cli -h "$host" -p "$port" PUBLISH "$channel" "$payload" >/dev/null
  fi
}

redis_sadd() {
  local host="$1" port="$2" pass="$3" key="$4" value="$5"
  if [ -n "$pass" ]; then
    redis-cli -h "$host" -p "$port" -a "$pass" SADD "$key" "$value" >/dev/null
  else
    redis-cli -h "$host" -p "$port" SADD "$key" "$value" >/dev/null
  fi
}

redis_srem() {
  local host="$1" port="$2" pass="$3" key="$4" value="$5"
  if [ -n "$pass" ]; then
    redis-cli -h "$host" -p "$port" -a "$pass" SREM "$key" "$value" >/dev/null
  else
    redis-cli -h "$host" -p "$port" SREM "$key" "$value" >/dev/null
  fi
}

ensure_ipset_sets() {
  ipset list fw_black_ips  >/dev/null 2>&1 || ipset create fw_black_ips  hash:ip -exist
  ipset list fw_block_ports >/dev/null 2>&1 || ipset create fw_block_ports bitmap:port range 1-65535 -exist
  ok "ipset sets ready"
}

ensure_iptables_rules() {
  iptables -C INPUT -m set --match-set fw_black_ips src -j DROP 2>/dev/null || \
  iptables -I INPUT -m set --match-set fw_black_ips src -j DROP

  iptables -C INPUT -p tcp -m set --match-set fw_block_ports dst -j DROP 2>/dev/null || \
  iptables -I INPUT -p tcp -m set --match-set fw_block_ports dst -j DROP

  ok "iptables rules ready"
}

show_status() {
  systemctl status "$SERVICE" --no-pager || true
  echo
  ipset list fw_black_ips 2>/dev/null | sed -n '1,30p' || true
  echo
  ipset list fw_block_ports 2>/dev/null | sed -n '1,30p' || true
}

# channel 읽기
get_channel() {
  CH=$(grep -E '^Environment=FW_CHANNEL=' "$UNIT_FILE" | sed -E 's/^Environment=FW_CHANNEL=//') || true
  [ -n "${CH:-}" ] || CH="fw:events"
  echo "$CH"
}

cmd_ban() {
  [ $# -eq 2 ] || err "usage: $0 ban <IP>"
  URL=$(get_redis_url); parse_redis_url "$URL"; CH=$(get_channel)
  redis_sadd "$HOST" "$PORT" "$PW_DEC" "fw:blacklist:ips" "$2"
  redis_publish "$HOST" "$PORT" "$PW_DEC" "$CH" "ban_ip $2"
  ok "ban_ip $2"
}

cmd_unban() {
  [ $# -eq 2 ] || err "usage: $0 unban <IP>"
  URL=$(get_redis_url); parse_redis_url "$URL"; CH=$(get_channel)
  redis_srem "$HOST" "$PORT" "$PW_DEC" "fw:blacklist:ips" "$2"
  redis_publish "$HOST" "$PORT" "$PW_DEC" "$CH" "unban_ip $2"
  ok "unban_ip $2"
}

cmd_block() {
  [ $# -eq 2 ] || err "usage: $0 block <PORT>"
  URL=$(get_redis_url); parse_redis_url "$URL"; CH=$(get_channel)
  redis_sadd "$HOST" "$PORT" "$PW_DEC" "fw:block:ports" "$2"
  redis_publish "$HOST" "$PORT" "$PW_DEC" "$CH" "block_port $2"
  ok "block_port $2"
}

cmd_unblock() {
  [ $# -eq 2 ] || err "usage: $0 unblock <PORT>"
  URL=$(get_redis_url); parse_redis_url "$URL"; CH=$(get_channel)
  redis_srem "$HOST" "$PORT" "$PW_DEC" "fw:block:ports" "$2"
  redis_publish "$HOST" "$PORT" "$PW_DEC" "$CH" "unblock_port $2"
  ok "unblock_port $2"
}

main() {
  require_cmds systemctl redis-cli iptables ipset grep sed "$PYTHON"

  cmd="${1:-health}"
  case "$cmd" in
    health)
      info "service check"
      if systemctl is-active --quiet "$SERVICE"; then ok "$SERVICE running"; else echo "[FAIL] $SERVICE not running"; fi

      info "read REDIS_URL"
      URL=$(get_redis_url)
      echo "REDIS_URL: $URL"

      info "parse URL"
      parse_redis_url "$URL"
      echo "HOST=$HOST PORT=$PORT"

      info "Redis ping"
      if redis_ping "$HOST" "$PORT" "$PW_DEC"; then ok "Redis PONG"; else err "Redis PING failed"; fi

      info "ensure ipset sets"
      ensure_ipset_sets

      info "ensure iptables rules"
      ensure_iptables_rules

      info "publish noop"
      CH=$(get_channel)
      redis_publish "$HOST" "$PORT" "$PW_DEC" "$CH" "noop $(date +%s)" && ok "noop publish OK"

      info "summary"
      show_status
      ;;
    fix)
      info "quick fix: sets/rules + service restart"
      ensure_ipset_sets
      ensure_iptables_rules
      systemctl restart "$SERVICE"
      ok "restarted"
      ;;
    restart)
      systemctl restart "$SERVICE"; ok "service restarted";;
    status)
      show_status ;;
    logs)
      journalctl -u "$SERVICE" -f ;;
    ban)      shift; cmd_ban "$@" ;;
    unban)    shift; cmd_unban "$@" ;;
    block)    shift; cmd_block "$@" ;;
    unblock)  shift; cmd_unblock "$@" ;;
    *)
      cat <<USAGE
usage:
  $0 health
  $0 fix
  $0 restart
  $0 status
  $0 logs
  $0 ban <IP>
  $0 unban <IP>
  $0 block <PORT>
  $0 unblock <PORT>
USAGE
      exit 1 ;;
  esac
}

main "$@"