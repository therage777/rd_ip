#!/bin/bash
set -e

# ===== 안내 =====
# 이 스크립트는 중앙 Redis(42.125.244.4)를 구독하는 ipset/iptables 에이전트를 설치합니다.
# - 로컬 Redis는 설치/사용하지 않습니다.
# - SSH 포트/FTP(제어포트) 번호를 질문하여 입력받아 적용합니다.
# - SSH는 "210.239.60.44" 한 IP만 정적으로 허용(안전장치)합니다.
# - FTP(IP:PORT)는 Redis 세트(fw:allow:ipports) + 에이전트로 동적 관리합니다.
# - CentOS 7.9(systemd) / 6.10(init.d) 자동 분기.

CENTRAL_REDIS_HOST="42.125.244.4"
CENTRAL_REDIS_PORT="6379"

ask() {
  local prompt="$1" default="$2" var
  read -rp "$prompt [default: $default]: " var
  echo "${var:-$default}"
}

echo "=== 중앙 Redis 연결 정보 입력 ==="
REDIS_HOST=$(ask "Redis host" "$CENTRAL_REDIS_HOST")
REDIS_PORT=$(ask "Redis port" "$CENTRAL_REDIS_PORT")
read -rsp "Redis password (필수): " REDIS_PASS; echo
if [ -z "$REDIS_PASS" ]; then echo "[ERR] Redis password는 필수입니다."; exit 1; fi
REDIS_DB=$(ask "Redis DB index" "0")
REDIS_CH=$(ask "Redis Pub/Sub channel" "fw:events")

echo
echo "=== 서버 포트 입력 ==="
SSH_PORT=$(ask "SSH port" "2197")
FTP_PORT=$(ask "FTP control port (예: 2193)" "2193")

# SSH 정적 허용 고정 IP (요청사항)
SSH_STATIC_IP="210.239.60.44"

echo
echo "설정 요약:"
echo "  Redis: $REDIS_HOST:$REDIS_PORT DB=$REDIS_DB CH=$REDIS_CH"
echo "  SSH  : port=$SSH_PORT, static allow=$SSH_STATIC_IP"
echo "  FTP  : control port=$FTP_PORT"
read -rp "진행할까요? (y/N): " go
[[ "$go" =~ ^[Yy]$ ]] || { echo "중단."; exit 1; }

echo "=== OS/레포 준비 ==="
yum install -y epel-release || true
if [ -f /etc/yum.repos.d/epel.repo ]; then
  sed -i 's|^metalink=|#metalink=|g' /etc/yum.repos.d/epel.repo
  sed -i 's|^#baseurl=http://download.fedoraproject.org/pub/epel|baseurl=https://archives.fedoraproject.org/pub/epel|g' /etc/yum.repos.d/epel.repo
fi
yum clean all || true
yum makecache fast || true

echo "=== 필수 패키지 설치 ==="
yum install -y ipset iptables which conntrack-tools || true
if grep -q "release 7" /etc/centos-release 2>/dev/null; then
  yum install -y python3 python3-pip || true
  PYCMD="python3"
  PIPCMD="pip3"
else
  yum install -y python python-pip || true
  PYCMD="python"
  PIPCMD="pip"
fi
$PIPCMD install --upgrade pip >/dev/null 2>&1 || true
PYMAJOR=$($PYCMD -c 'import sys;print(sys.version_info[0])')
if [ "$PYMAJOR" = "2" ]; then
  $PIPCMD install "redis==2.10.6"
else
  $PIPCMD install "redis<6"
fi

echo "=== 에이전트 배포 (/usr/local/bin/redis-fw-agent.py) ==="
AGENT=/usr/local/bin/redis-fw-agent.py
cat > "$AGENT" <<'PY'
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os, sys, subprocess
try:
    import redis
except Exception as e:
    sys.stderr.write("[redis-fw-agent] redis module missing\n"); sys.exit(1)

REDIS_HOST = os.environ.get("REDIS_HOST", "42.125.244.4")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
REDIS_PASS = os.environ.get("REDIS_PASS", "")
REDIS_DB   = int(os.environ.get("REDIS_DB", "0"))
CHANNEL    = os.environ.get("FW_CHANNEL", "fw:events")

K_BLACK_IPS    = "fw:blacklist:ips"
K_BLOCK_PORTS  = "fw:block:ports"
K_ALLOW_IPPORT = "fw:allow:ipports"
K_BLOCK_IPPORT = "fw:block:ipports"

SET_BLACK_IPS    = "fw_black_ips"
SET_BLOCK_PORTS  = "fw_block_ports"
SET_ALLOW_IPPORT = "fw_allow_ipports"
SET_BLOCK_IPPORT = "fw_block_ipports"

def sh(cmd):
    rc = subprocess.call(cmd, shell=True)
    if rc != 0:
        sys.stderr.write("[redis-fw-agent] CMD FAIL({0}): {1}\n".format(rc, cmd))
    return rc

def ipset_create():
    sh("ipset create {0} hash:ip -exist".format(SET_BLACK_IPS))
    sh("ipset create {0} bitmap:port range 1-65535 -exist".format(SET_BLOCK_PORTS))
    sh("ipset create {0} hash:ip,port -exist".format(SET_ALLOW_IPPORT))
    sh("ipset create {0} hash:ip,port -exist".format(SET_BLOCK_IPPORT))

def ipset_restore_from_redis(r):
    sh("ipset flush {0}".format(SET_BLACK_IPS))
    sh("ipset flush {0}".format(SET_BLOCK_PORTS))
    sh("ipset flush {0}".format(SET_ALLOW_IPPORT))
    sh("ipset flush {0}".format(SET_BLOCK_IPPORT))

    for ip in r.smembers(K_BLACK_IPS):
        if isinstance(ip, bytes): ip = ip.decode()
        if ip: sh("ipset add {0} {1} -exist".format(SET_BLACK_IPS, ip))

    for p in r.smembers(K_BLOCK_PORTS):
        if isinstance(p, bytes): p = p.decode()
        if p: sh("ipset add {0} {1} -exist".format(SET_BLOCK_PORTS, p))

    for s in r.smembers(K_ALLOW_IPPORT):
        s = s.decode() if isinstance(s, bytes) else s
        if s and ':' in s:
            ip, port = s.split(':', 1)
            sh("ipset add {0} {1},tcp:{2} -exist".format(SET_ALLOW_IPPORT, ip, port))

    for s in r.smembers(K_BLOCK_IPPORT):
        s = s.decode() if isinstance(s, bytes) else s
        if s and ':' in s:
            ip, port = s.split(':', 1)
            sh("ipset add {0} {1},tcp:{2} -exist".format(SET_BLOCK_IPPORT, ip, port))

def ensure_iptables():
    # ipset 기반 차단/허용
    sh("iptables -C INPUT -m set --match-set {0} src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set {0} src -j DROP".format(SET_BLACK_IPS))
    sh("iptables -C INPUT -p tcp -m set --match-set {0} dst -j DROP 2>/dev/null || iptables -I INPUT -p tcp -m set --match-set {0} dst -j DROP".format(SET_BLOCK_PORTS))
    sh("iptables -C INPUT -p tcp -m set --match-set {0} src,dst -j DROP 2>/dev/null || iptables -I INPUT -p tcp -m set --match-set {0} src,dst -j DROP".format(SET_BLOCK_IPPORT))
    sh("iptables -C INPUT -p tcp -m set --match-set {0} src,dst -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp -m set --match-set {0} src,dst -j ACCEPT".format(SET_ALLOW_IPPORT))

def handle(msg):
    parts = (msg or "").strip().split()
    if not parts: return
    cmd = parts[0]
    a1 = parts[1] if len(parts) > 1 else None
    a2 = parts[2] if len(parts) > 2 else None

    if cmd == "ban_ip" and a1:
        sh("ipset add {0} {1} -exist".format(SET_BLACK_IPS, a1))
    elif cmd == "unban_ip" and a1:
        sh("ipset del {0} {1} 2>/dev/null".format(SET_BLACK_IPS, a1))

    elif cmd == "block_port" and a1:
        sh("ipset add {0} {1} -exist".format(SET_BLOCK_PORTS, a1))
    elif cmd == "unblock_port" and a1:
        sh("ipset del {0} {1} 2>/dev/null".format(SET_BLOCK_PORTS, a1))

    elif cmd == "allow_ipport" and a1 and a2:
        sh("ipset add {0} {1},tcp:{2} -exist".format(SET_ALLOW_IPPORT, a1, a2))
    elif cmd == "unallow_ipport" and a1 and a2:
        sh("ipset del {0} {1},tcp:{2} 2>/dev/null".format(SET_ALLOW_IPPORT, a1, a2))

    elif cmd == "block_ipport" and a1 and a2:
        sh("ipset add {0} {1},tcp:{2} -exist".format(SET_BLOCK_IPPORT, a1, a2))
    elif cmd == "unblock_ipport" and a1 and a2:
        sh("ipset del {0} {1},tcp:{2} 2>/dev/null".format(SET_BLOCK_IPPORT, a1, a2))

def main():
    r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, password=REDIS_PASS)
    ipset_create()
    ensure_iptables()
    ipset_restore_from_redis(r)
    ps = r.pubsub()
    ps.subscribe(os.environ.get("FW_CHANNEL","fw:events"))
    for item in ps.listen():
        if item.get("type") != "message": continue
        data = item.get("data")
        if isinstance(data, bytes): data = data.decode()
        try:
            handle(data)
        except Exception as e:
            sys.stderr.write("[redis-fw-agent] handle error: {0}\n".format(e))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        sys.stderr.write("[redis-fw-agent] fatal: {0}\n".format(e))
        sys.exit(1)
PY
chmod +x "$AGENT"

echo "=== 서비스 등록 ==="
if grep -q "release 7" /etc/centos-release 2>/dev/null; then
  UNIT=/etc/systemd/system/redis-fw-agent.service
  cat > "$UNIT" <<EOF
[Unit]
Description=Redis -> ipset/iptables firewall agent
After=network-online.target iptables.service
Wants=network-online.target

[Service]
Type=simple
Environment=REDIS_HOST=${REDIS_HOST}
Environment=REDIS_PORT=${REDIS_PORT}
Environment=REDIS_PASS=${REDIS_PASS}
Environment=REDIS_DB=${REDIS_DB}
Environment=FW_CHANNEL=${REDIS_CH}
ExecStart=$(command -v $PYCMD) -u $AGENT
Restart=always
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now redis-fw-agent
  systemctl status redis-fw-agent --no-pager || true
else
  INIT=/etc/init.d/redis-fw-agent
  cat > "$INIT" <<'SH'
#!/bin/sh
# chkconfig: 2345 97 03
# description: Redis->ipset firewall agent
### BEGIN INIT INFO
# Provides:          redis-fw-agent
# Required-Start:    $local_fs $network iptables
# Required-Stop:     $local_fs $network iptables
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
### END INFO
AGENT=/usr/local/bin/redis-fw-agent.py
PY=$(which python || echo /usr/bin/python)
start()  { nohup $PY -u $AGENT >/var/log/redis-fw-agent.log 2>&1 & echo $! >/var/run/redis-fw-agent.pid; echo "started"; }
stop()   { [ -f /var/run/redis-fw-agent.pid ] && kill $(cat /var/run/redis-fw-agent.pid) && rm -f /var/run/redis-fw-agent.pid || true; echo "stopped"; }
status() { pgrep -f "$AGENT" >/dev/null && echo running || echo stopped; }
case "$1" in start) start;; stop) stop;; restart) stop; start;; status) status;; *) echo "Usage: $0 {start|stop|restart|status}";; esac
SH
  chmod +x "$INIT"
  chkconfig --add redis-fw-agent
  service redis-fw-agent start || true
fi

echo "=== ipset/iptables 규칙 주입 (안전 모드) ==="
# 세트 보장
ipset list fw_black_ips  >/dev/null 2>&1 || ipset create fw_black_ips  hash:ip -exist
ipset list fw_block_ports >/dev/null 2>&1 || ipset create fw_block_ports bitmap:port range 1-65535 -exist
ipset list fw_allow_ipports >/dev/null 2>&1 || ipset create fw_allow_ipports hash:ip,port -exist
ipset list fw_block_ipports >/dev/null 2>&1 || ipset create fw_block_ipports hash:ip,port -exist

# SSH(정적 허용 + 나머지 DROP)
iptables -C INPUT -s ${SSH_STATIC_IP}/32 -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || \
iptables -I INPUT -s ${SSH_STATIC_IP}/32 -p tcp --dport "$SSH_PORT" -j ACCEPT
iptables -C INPUT -p tcp --dport "$SSH_PORT" -j DROP 2>/dev/null || \
iptables -A INPUT -p tcp --dport "$SSH_PORT" -j DROP

# FTP(동적 허용 세트 + 전역 DROP)
iptables -C INPUT -p tcp -m set --match-set fw_allow_ipports src,dst -j ACCEPT 2>/dev/null || \
iptables -I INPUT -p tcp -m set --match-set fw_allow_ipports src,dst -j ACCEPT
iptables -C INPUT -p tcp --dport "$FTP_PORT" -j DROP 2>/dev/null || \
iptables -A INPUT -p tcp --dport "$FTP_PORT" -j DROP

# FTP conntrack helper (제어포트 지정)
modprobe -r nf_conntrack_ftp 2>/dev/null || true
modprobe nf_conntrack_ftp ports="$FTP_PORT" || true
echo "options nf_conntrack_ftp ports=${FTP_PORT}" > /etc/modprobe.d/nf_conntrack_ftp.conf

# 저장
if command -v service >/dev/null 2>&1; then
  service iptables save || true
fi

echo "[DONE] 설치 완료"
echo " - 중앙 Redis: ${REDIS_HOST}:${REDIS_PORT} / CH=${REDIS_CH}"
echo " - SSH 포트: ${SSH_PORT} (정적 허용: ${SSH_STATIC_IP})"
echo " - FTP 포트: ${FTP_PORT} (ipset 동적 관리)"