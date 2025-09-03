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

calc_sha256() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$f" | awk '{print $1}';
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 -r "$f" | awk '{print $1}';
  else echo ""; fi
}

fetch() {
  local url="$1" dst="$2" tmp tmp_sum expected localhash
  tmp="$(mktemp)"; tmp_sum="$(mktemp)"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 "$url" -o "$tmp" || true
    curl -fsSL --retry 3 "$url.sha256" -o "$tmp_sum" || true
  else
    wget -q "$url" -O "$tmp" || true
    wget -q "$url.sha256" -O "$tmp_sum" || true
  fi
  [ -s "$tmp" ] || { echo "[!] 다운로드 실패: $url" >&2; rm -f "$tmp" "$tmp_sum"; exit 2; }

  # 체크섬 검증 (가능한 경우)
  if [ -s "$tmp_sum" ]; then
    expected=$(awk '{for(i=1;i<=NF;i++){ if (length($i)==64 && $i ~ /^[0-9A-Fa-f]+$/){print tolower($i); exit}}}' "$tmp_sum")
    localhash=$(calc_sha256 "$tmp" | tr 'A-F' 'a-f')
    if [ -n "$expected" ] && [ -n "$localhash" ]; then
      if [ "$expected" != "$localhash" ]; then
        echo "[!] SHA256 불일치: $url" >&2
        echo "    expected=$expected" >&2
        echo "    actual  =$localhash" >&2
        rm -f "$tmp" "$tmp_sum"; exit 3
      else
        echo "[OK] 체크섬 검증 통과: $url"
      fi
    else
      echo "[!] 체크섬 도구 또는 형식을 인식하지 못해 검증 생략: $url" >&2
    fi
  else
    echo "[!] 체크섬 파일 없음(.sha256): $url — 검증 생략" >&2
  fi

  install -m 0644 "$tmp" "$dst"; rm -f "$tmp" "$tmp_sum"
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

## 내장 에이전트 코드 블록 제거됨(원격 다운로드 방식 사용)

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
