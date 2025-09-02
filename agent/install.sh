#!/bin/bash
# IPTables Agent 설치 스크립트

# root 권한 확인
if [ "$EUID" -ne 0 ]; then 
   echo "root 권한으로 실행해주세요."
   exit 1
fi

echo "IPTables Redis Agent 설치 시작..."

# Python3 및 pip 설치 확인
if ! command -v python3 &> /dev/null; then
    echo "Python3 설치..."
    apt-get update
    apt-get install -y python3 python3-pip
fi

# Redis 클라이언트 설치
echo "Redis Python 클라이언트 설치..."
pip3 install redis

# 에이전트 디렉토리 생성
mkdir -p /opt/iptables-agent
mkdir -p /var/log

# 에이전트 파일 복사
cp iptables_agent.py /opt/iptables-agent/
chmod +x /opt/iptables-agent/iptables_agent.py

# systemd 서비스 설치
cp iptables_agent.service /etc/systemd/system/
systemctl daemon-reload

# iptables 기본 정책 설정 (선택사항)
echo "iptables 기본 정책 설정..."
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# 기본 보안 규칙 추가 (선택사항)
# SSH 포트는 항상 열어둠
iptables -I INPUT -p tcp --dport 22 -j ACCEPT

# 로컬호스트는 항상 허용
iptables -I INPUT -i lo -j ACCEPT
iptables -I OUTPUT -o lo -j ACCEPT

# ESTABLISHED 연결 허용
iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# iptables 규칙 저장
if command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4
fi

# 서비스 시작
echo "서비스 시작..."
systemctl enable iptables_agent.service
systemctl start iptables_agent.service

# 상태 확인
systemctl status iptables_agent.service

echo "설치 완료!"
echo ""
echo "사용법:"
echo "  서비스 상태: systemctl status iptables_agent"
echo "  서비스 시작: systemctl start iptables_agent"
echo "  서비스 중지: systemctl stop iptables_agent"
echo "  로그 확인: journalctl -u iptables_agent -f"