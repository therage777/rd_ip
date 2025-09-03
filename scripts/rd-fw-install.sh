#!/usr/bin/env bash
# rd-fw-install.sh (2025-09-02 fixed)
# - Ubuntu: UFW 유지 + ufw-before-input 에 ipset 룰 삽입
# - CentOS 6/7: iptables 직접 구성
# - 중앙 Redis만 사용 (로컬 6379 허용 규칙 불필요)
# - SSH 비상용 210.239.60.44 상시 허용, 나머지 SSH/FTP는 ipset 관리

set -euo pipefail

### 0) 공용 함수
ask(){ local p="$1" d="${2:-}"; local a; read -rp "$p ${d:+[$d]}: " a || true; echo "${a:-$d}"; }
detect_os(){
  if [[ -f /etc/centos-release ]]; then
    grep -q " 6\." /etc/centos-release && OS_FAMILY=el6 || OS_FAMILY=el7
  elif [[ -f /etc/lsb-release ]] || [[ -f /etc/debian_version ]]; then
    OS_FAMILY=ubuntu
  else
    echo "[!] 지원하지 않는 OS" >&2; exit 1
  fi
}

# ---- CentOS7 EOL 레포 자동 복구 (Vault & EPEL archive)
fix_centos7_repos(){
  echo "[*] CentOS 7 레포 점검/복구 중..."
  # 1) 기존 CentOS mirrorlist 비활성 & Vault 7.9.2009 레포 파일 생성
  cat > /etc/yum.repos.d/CentOS-Vault-7.9.2009.repo <<'EOF'
[base]
name=CentOS-7.9.2009 - Base
baseurl=http://vault.centos.org/7.9.2009/os/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1

[updates]
name=CentOS-7.9.2009 - Updates
baseurl=http://vault.centos.org/7.9.2009/updates/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1

[extras]
name=CentOS-7.9.2009 - Extras
baseurl=http://vault.centos.org/7.9.2009/extras/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1
EOF

  # 2) 기존 CentOS-Base 등은 전부 비활성
  for f in /etc/yum.repos.d/CentOS-*.repo; do
    [[ -f "$f" && "$f" != "/etc/yum.repos.d/CentOS-Vault-7.9.2009.repo" ]] && sed -i 's/^enabled=1/enabled=0/g' "$f" || true
  done

  # 3) EPEL 7도 아카이브로 교체
  cat > /etc/yum.repos.d/epel.repo <<'EOF'
[epel]
name=Extra Packages for Enterprise Linux 7 - $basearch (Archive)
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/$basearch/
enabled=1
gpgcheck=0
EOF

  yum clean all -y
  yum --setopt=timeout=30 --setopt=retries=3 -y makecache || true
}

# ---- /etc/iptables 보증
ensure_iptables_dir(){ mkdir -p /etc/iptables; }

### 1) 입력값
detect_os; echo "[OS] $OS_FAMILY"
REDIS_HOST="$(ask 'Redis HOST' '42.125.244.4')"
REDIS_PORT="$(ask 'Redis PORT' '6379')"
REDIS_DB="$(ask 'Redis DB' '0')"
REDIS_PASS="$(ask 'Redis PASS (따옴표 없이)')"
FW_CHANNEL="$(ask 'Redis Channel' 'fw:events')"
SERVER_ID_VAL="$(ask 'SERVER_ID (비우면 hostname)')"
SERVER_GROUPS_VAL="$(ask 'SERVER_GROUPS (콤마, 옵션)')"
SSH_PORT="$(ask 'SSH 포트' '2197')"
EMERGENCY_SSH_CIDR="$(ask '긴급 SSH 허용 CIDR' '210.239.60.44/32')"
FTP_PORT="$(ask 'FTP 제어 포트' '2193')"

### 2) 패키지 설치
if [[ $OS_FAMILY == el7 ]]; then
  # 먼저 레포 복구
  fix_centos7_repos
  yum -y install epel-release >/dev/null 2>&1 || true
  yum --setopt=timeout=30 --setopt=retries=3 -y install ipset conntrack-tools iptables-services python3 python3-pip >/dev/null
  systemctl enable iptables >/dev/null || true
elif [[ $OS_FAMILY == el6 ]]; then
  yum -y install epel-release >/dev/null 2>&1 || true
  yum --setopt=timeout=30 --setopt=retries=3 -y install ipset conntrack-tools iptables python2 python-pip >/dev/null
else
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get -o Acquire::Retries=3 -y install ipset conntrack iptables iptables-persistent python3 python3-pip >/dev/null
fi

# Python redis 모듈
if command -v python3 >/dev/null 2>&1; then
  pip3 install -q --upgrade redis >/dev/null || true
else
  pip install -q "redis==2.10.6" >/dev/null || true
fi

### 3) 에이전트/헬퍼 다운로드 배포
AGENT=/usr/local/bin/redis-fw-agent.py
HELPER=/usr/local/bin/rd-fw-agent.sh
CONF=/etc/redis-fw-agent.conf
SRC_BASE="https://rdips.waba88.com/scripts/agent"

fetch() {
  local url="$1" dst="$2" tmp
  tmp="$(mktemp)"
  if command -v curl >/dev/null 2>&1; then curl -fsSL --retry 3 "$url" -o "$tmp"; else wget -q "$url" -O "$tmp"; fi
  [ -s "$tmp" ] || { echo "[!] 다운로드 실패: $url" >&2; exit 2; }
  install -m 0644 "$tmp" "$dst"; rm -f "$tmp"
}

echo "[*] 에이전트/헬퍼 스크립트 다운로드"
fetch "$SRC_BASE/redis-fw-agent.py" "$AGENT"; chmod +x "$AGENT"
fetch "$SRC_BASE/rd-fw-agent.sh" "$HELPER"; chmod +x "$HELPER"

echo "[*] 기본 설정 다운로드"
fetch "$SRC_BASE/redis-fw-agent.conf" "$CONF"; chmod 600 "$CONF"

# 프롬프트 입력값으로 설정 반영
sed -i -E "s|^REDIS_HOST=.*|REDIS_HOST=$REDIS_HOST|" "$CONF"
sed -i -E "s|^REDIS_PORT=.*|REDIS_PORT=$REDIS_PORT|" "$CONF"
sed -i -E "s|^REDIS_DB=.*|REDIS_DB=$REDIS_DB|" "$CONF"
sed -i -E "s|^REDIS_PASS=.*|REDIS_PASS=$REDIS_PASS|" "$CONF"
sed -i -E "s|^FW_CHANNEL=.*|FW_CHANNEL=$FW_CHANNEL|" "$CONF"
sed -i -E "s|^SSH_PORT=.*|SSH_PORT=$SSH_PORT|" "$CONF"
sed -i -E "s|^EMERGENCY_SSH_CIDR=.*|EMERGENCY_SSH_CIDR=$EMERGENCY_SSH_CIDR|" "$CONF"
if [[ -n "$SERVER_ID_VAL" ]]; then sed -i -E "s|^SERVER_ID=.*|SERVER_ID=$SERVER_ID_VAL|" "$CONF"; fi
if [[ -n "$SERVER_GROUPS_VAL" ]]; then sed -i -E "s|^SERVER_GROUPS=.*|SERVER_GROUPS=$SERVER_GROUPS_VAL|" "$CONF"; fi

# SSH를 보호 포트에 포함 보장
if grep -q '^PROTECTED_PORTS=' "$CONF"; then sed -i -E "s|^PROTECTED_PORTS=.*|PROTECTED_PORTS=$SSH_PORT|" "$CONF"; else echo "PROTECTED_PORTS=$SSH_PORT" >> "$CONF"; fi

# (백업용) 내장 에이전트 코드 — 현재는 비활성
if false; then
cat > "$AGENT" <<'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, subprocess, socket
LOG_LEVEL=os.getenv("LOG_LEVEL","INFO").upper()
_LEVELS={"DEBUG":10,"INFO":20,"WARN":30,"ERROR":40,"NONE":100}
def _log(l,m): 
    (sys.stderr if l in ("ERROR","WARN") else sys.stdout).write("[redis-fw-agent] %s\n"%m) if _LEVELS.get(l,20)>=_LEVELS.get(LOG_LEVEL,20) else None
SERVER_ID=os.getenv("SERVER_ID",socket.gethostname())
SERVER_GROUPS=[g.strip() for g in os.getenv("SERVER_GROUPS","").split(",") if g.strip()]
REDIS_HOST=os.getenv("REDIS_HOST","42.125.244.4")
REDIS_PORT=int(os.getenv("REDIS_PORT","6379"))
REDIS_DB=int(os.getenv("REDIS_DB","0"))
REDIS_PASS=os.getenv("REDIS_PASS",None)
CHANNEL=os.getenv("FW_CHANNEL","fw:events")
K_BLACK_IPS="fw:black_ips"; K_BLOCK_PORTS="fw:block:ports"; K_ALLOW_PORTS="fw:allow:ports"; K_ALLOW_IPPORTS="fw:allow:ipports"; K_BLOCK_IPPORTS="fw:block:ipports"
SET_BLACK_IPS="fw_black_ips"; SET_BLOCK_PORTS="fw_block_ports"; SET_ALLOW_PORTS="fw_allow_ports"; SET_ALLOW_IPPORTS="fw_allow_ipports"; SET_BLOCK_IPPORTS="fw_block_ipports"
def sh(c):
    p=subprocess.Popen(c,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE); o,e=p.communicate()
    if p.returncode!=0: raise RuntimeError("%s\n%s"%(c,e.decode()))
    return o.decode()
def try_sh(c):
    try: return sh(c)
    except Exception as e: _log("DEBUG","cmd failed: %s"%e); return ""
def ensure_sets():
    try_sh(f"ipset create {SET_BLACK_IPS} hash:ip -exist")
    try_sh(f"ipset create {SET_BLOCK_PORTS} bitmap:port range 0-65535 -exist")
    try_sh(f"ipset create {SET_ALLOW_PORTS} bitmap:port range 0-65535 -exist")
    try_sh(f"ipset create {SET_ALLOW_IPPORTS} hash:ip,port -exist")
    try_sh(f"ipset create {SET_BLOCK_IPPORTS} hash:ip,port -exist")
def add_ipport(s,ip,p): try_sh(f"ipset add {s} {ip},tcp:{p} -exist")
def del_ipport(s,ip,p): try_sh(f"ipset del {s} {ip},tcp:{p} -exist")

# ---- Helpers (flags/scope/protected) ----
def has_flag(parts, name):
    flag = "@%s" % name
    return any(t.strip() == flag for t in parts)

def is_protected_port(port):
    pro = set([x.strip() for x in (os.getenv("PROTECTED_PORTS","")) .split(',') if x.strip()])
    sshp = os.getenv("SSH_PORT")
    if sshp: pro.add(str(sshp))
    return str(port) in pro

def parse_scope(parts):
    servers, groups = set(), set()
    for t in parts:
        if not t.startswith("@") or "=" not in t: continue
        k,v = t[1:].split("=",1)
        vals = [x.strip() for x in v.split(",") if x.strip()]
        if k in ("server","servers"): servers.update(vals)
        elif k in ("group","groups"): groups.update(vals)
    return {"servers": servers, "groups": groups}

def scope_matches(scope):
    if not scope["servers"] and not scope["groups"]:
        return True
    if SERVER_ID in scope["servers"]:
        return True
    if SERVER_GROUPS:
        if set(SERVER_GROUPS).intersection(scope["groups"]):
            return True
    return False

def key_server(base, sid):
    return f"{base}:server:{sid}"

def key_group(base, gid):
    return f"{base}:group:{gid}"
def sync_all(r):
    ensure_sets()
    try_sh(f"ipset flush {SET_BLACK_IPS}")
    try_sh(f"ipset flush {SET_BLOCK_PORTS}")
    try_sh(f"ipset flush {SET_ALLOW_PORTS}")
    try_sh(f"ipset flush {SET_ALLOW_IPPORTS}")
    try_sh(f"ipset flush {SET_BLOCK_IPPORTS}")
    # ---- BLACK IPs (global + scoped) ----
    def load_blackips():
        for ip in r.smembers(K_BLACK_IPS):
            yield ip
        for ip in r.smembers(key_server(K_BLACK_IPS, SERVER_ID)):
            yield ip
        for g in SERVER_GROUPS:
            for ip in r.smembers(key_group(K_BLACK_IPS, g)):
                yield ip
    for ip in load_blackips():
        try_sh(f"ipset add {SET_BLACK_IPS} {ip} -exist")

    # ---- BLOCK PORTS (global + scoped) ----
    def load_blkports():
        for p in r.smembers(K_BLOCK_PORTS):
            yield p
        for p in r.smembers(key_server(K_BLOCK_PORTS, SERVER_ID)):
            yield p
        for g in SERVER_GROUPS:
            for p in r.smembers(key_group(K_BLOCK_PORTS, g)):
                yield p
    for p in load_blkports():
        try_sh(f"ipset add {SET_BLOCK_PORTS} {p} -exist")

    # ---- ALLOW PORTS (global + scoped, protected guard) ----
    def load_alwports():
        for p in r.smembers(K_ALLOW_PORTS):
            yield p
        for p in r.smembers(key_server(K_ALLOW_PORTS, SERVER_ID)):
            yield p
        for g in SERVER_GROUPS:
            for p in r.smembers(key_group(K_ALLOW_PORTS, g)):
                yield p
    for p in load_alwports():
        if is_protected_port(p) and os.getenv("ALLOW_PROTECTED_PORTS","") not in ("1","true","TRUE","yes","YES"):
            _log("WARN", f"skip protected allow_port tcp:{p} (sync)")
            continue
        try_sh(f"ipset add {SET_ALLOW_PORTS} {p} -exist")

    # ---- ALLOW/BLOCK IP:PORT (global + scoped) ----
    def load_ipports(base):
        for s in r.smembers(base):
            yield s
        for s in r.smembers(key_server(base, SERVER_ID)):
            yield s
        for g in SERVER_GROUPS:
            for s in r.smembers(key_group(base, g)):
                yield s
    for s in load_ipports(K_ALLOW_IPPORTS):
        if ":" in s:
            ip,p = s.split(":",1)
            # allow_ipport는 보호 포트라도 sync 시에는 안전상 무시
            if is_protected_port(p) and os.getenv("ALLOW_PROTECTED_PORTS","") not in ("1","true","TRUE","yes","YES"):
                _log("WARN", f"skip protected allow_ipport {ip},tcp:{p} (sync)")
                continue
            add_ipport(SET_ALLOW_IPPORTS, ip, p)
    for s in load_ipports(K_BLOCK_IPPORTS):
        if ":" in s:
            ip,p = s.split(":",1)
            add_ipport(SET_BLOCK_IPPORTS, ip, p)
def handle(tokens):
    op=tokens[0]
    # scope check
    scope = parse_scope(tokens)
    if not scope_matches(scope):
        return
    force = has_flag(tokens, "force")
    if op=="allow_ipport" and len(tokens)>=3: add_ipport(SET_ALLOW_IPPORTS,tokens[1],tokens[2])
    elif op=="unallow_ipport" and len(tokens)>=3: del_ipport(SET_ALLOW_IPPORTS,tokens[1],tokens[2])
    elif op=="block_ipport" and len(tokens)>=3: add_ipport(SET_BLOCK_IPPORTS,tokens[1],tokens[2])
    elif op=="unblock_ipport" and len(tokens)>=3: del_ipport(SET_BLOCK_IPPORTS,tokens[1],tokens[2])
    elif op=="ban_ip" and len(tokens)>=2: try_sh(f"ipset add {SET_BLACK_IPS} {tokens[1]} -exist")
    elif op=="unban_ip" and len(tokens)>=2: try_sh(f"ipset del {SET_BLACK_IPS} {tokens[1]} -exist")
    elif op=="block_port" and len(tokens)>=2: try_sh(f"ipset add {SET_BLOCK_PORTS} {tokens[1]} -exist")
    elif op=="unblock_port" and len(tokens)>=2: try_sh(f"ipset del {SET_BLOCK_PORTS} {tokens[1]} -exist")
    elif op=="allow_port" and len(tokens)>=2:
        p=tokens[1]
        if is_protected_port(p) and not force and os.getenv("ALLOW_PROTECTED_PORTS","") not in ("1","true","TRUE","yes","YES"):
            _log("WARN", f"skip protected allow_port {p}")
        else:
            try_sh(f"ipset add {SET_ALLOW_PORTS} {p} -exist")
    elif op=="unallow_port" and len(tokens)>=2:
        try_sh(f"ipset del {SET_ALLOW_PORTS} {tokens[1]} -exist")
def main():
    import redis
    r=redis.StrictRedis(host=REDIS_HOST,port=REDIS_PORT,db=REDIS_DB,password=REDIS_PASS,decode_responses=True)
    ensure_sets(); sync_all(r)
    ps=r.pubsub(); ps.subscribe(CHANNEL)
    _log("INFO",f"SERVER_ID={SERVER_ID} subscribed {CHANNEL}")
    for m in ps.listen():
        if m.get("type")!="message": continue
        t=m.get("data").split(); 
        if not t: continue
        try: handle(t)
        except Exception as e: _log("ERROR",f"cmd error: {e}")
if __name__=="__main__": main()
PYEOF
chmod +x "$AGENT"
fi

### 4) 환경 파일(다운로드/패치 완료) — 별도 생성 생략
umask 077

### 5) ipset 세트 보증
ipset create fw_black_ips hash:ip -exist
ipset create fw_block_ports bitmap:port range 0-65535 -exist
ipset create fw_allow_ports bitmap:port range 0-65535 -exist
ipset create fw_allow_ipports hash:ip,port -exist
ipset create fw_block_ipports hash:ip,port -exist

### 6) 방화벽 규칙
if [[ $OS_FAMILY == ubuntu ]]; then
  echo "[+] Ubuntu: UFW 체인에 ipset 룰 삽입"
  ufw allow from "$EMERGENCY_SSH_CIDR" to any port "$SSH_PORT" proto tcp comment "emergency ssh" || true
  iptables -I ufw-before-input 1 -p tcp -m set --match-set fw_block_ipports src,dst -j DROP
  iptables -I ufw-before-input 2 -p tcp -m set --match-set fw_allow_ipports src,dst -j ACCEPT
  iptables -I ufw-before-input 3 -m set --match-set fw_black_ips src -j DROP
  iptables -I ufw-before-input 4 -p tcp -m set --match-set fw_allow_ports dst -j ACCEPT
  iptables -I ufw-before-input 5 -p tcp -m set --match-set fw_block_ports dst -j DROP
  iptables -I ufw-before-input 6 -p tcp --dport "$FTP_PORT" -j DROP
  netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4
else
  echo "[+] CentOS: iptables 직접 구성"
  ensure_iptables_dir
  RULE=/etc/iptables/rd-fw.rules
  cat > "$RULE" <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -s $EMERGENCY_SSH_CIDR -p tcp --dport $SSH_PORT -j ACCEPT
-A INPUT -p tcp -m set --match-set fw_block_ipports src,dst -j DROP
-A INPUT -p tcp -m set --match-set fw_allow_ipports src,dst -j ACCEPT
-A INPUT -m set --match-set fw_black_ips src -j DROP
-A INPUT -p tcp -m set --match-set fw_allow_ports dst -j ACCEPT
-A INPUT -p tcp -m set --match-set fw_block_ports dst -j DROP
-A INPUT -p tcp --dport $FTP_PORT -j DROP
COMMIT
EOF
  iptables-restore < "$RULE"
  iptables-save > /etc/sysconfig/iptables
fi

### 7) systemd 서비스
SERVICE=/etc/systemd/system/redis-fw-agent.service
cat > "$SERVICE" <<'UNIT'
[Unit]
Description=Redis → ipset/iptables firewall agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/redis-fw-agent.conf
ExecStart=/usr/bin/python3 -u /usr/local/bin/redis-fw-agent.py
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=true
ProtectSystem=full
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable redis-fw-agent
systemctl restart redis-fw-agent

echo "[OK] 설치 완료"
echo "- Ubuntu: UFW 체인에 ipset 삽입 완료"
echo "- CentOS7: Vault 레포 자동 전환 + iptables 규칙 반영 완료"
