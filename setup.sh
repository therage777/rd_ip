#!/bin/bash

echo "========================================="
echo "  IPTables 관리 시스템 설치 스크립트"
echo "========================================="
echo ""

# 색상 코드
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 루트 권한 체크
if [ "$EUID" -ne 0 ]; then 
   echo -e "${RED}[ERROR] 이 스크립트는 root 권한으로 실행해야 합니다.${NC}"
   echo "사용법: sudo ./setup.sh"
   exit 1
fi

echo -e "${GREEN}[1/8] 시스템 패키지 업데이트${NC}"
apt-get update

echo -e "${GREEN}[2/8] 필수 패키지 설치${NC}"
apt-get install -y \
    apache2 \
    php5.6 \
    php5.6-mysql \
    php5.6-mbstring \
    php5.6-xml \
    php5.6-json \
    mysql-server \
    redis-server \
    python3 \
    python3-pip \
    composer \
    git

echo -e "${GREEN}[3/8] PHP Composer 의존성 설치${NC}"
composer install --no-dev

echo -e "${GREEN}[4/8] Python Redis 클라이언트 설치${NC}"
pip3 install redis

echo -e "${GREEN}[5/8] 데이터베이스 설정${NC}"
echo -e "${YELLOW}MySQL root 비밀번호를 입력하세요:${NC}"
read -s MYSQL_ROOT_PASS

mysql -u root -p${MYSQL_ROOT_PASS} << EOF
CREATE DATABASE IF NOT EXISTS rd_ip DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'rdips'@'localhost' IDENTIFIED BY 'qX8Hvq4VfhzjxQ0b';
GRANT ALL PRIVILEGES ON rd_ip.* TO 'rdips'@'localhost';
FLUSH PRIVILEGES;
EOF

# 테이블 생성
mysql -u root -p${MYSQL_ROOT_PASS} rd_ip < schema.sql
mysql -u root -p${MYSQL_ROOT_PASS} rd_ip < schema_update.sql

echo -e "${GREEN}[6/8] 디렉토리 권한 설정${NC}"
WEBROOT="/var/www/rd_ip"
mkdir -p ${WEBROOT}
cp -r * ${WEBROOT}/
chown -R www-data:www-data ${WEBROOT}
chmod -R 755 ${WEBROOT}
chmod 600 ${WEBROOT}/config.php

echo -e "${GREEN}[7/8] Apache 설정${NC}"
cat > /etc/apache2/sites-available/rd_ip.conf << 'APACHE_CONFIG'
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/rd_ip
    
    <Directory /var/www/rd_ip>
        Options -Indexes
        AllowOverride All
        Require all granted
    </Directory>
    
    # 보안 헤더
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    
    ErrorLog ${APACHE_LOG_DIR}/rd_ip_error.log
    CustomLog ${APACHE_LOG_DIR}/rd_ip_access.log combined
</VirtualHost>
APACHE_CONFIG

# 사이트 활성화
a2ensite rd_ip.conf
a2enmod headers
a2enmod rewrite
systemctl reload apache2

echo -e "${GREEN}[8/8] IPTables Agent 설치${NC}"
cd ${WEBROOT}/agent
chmod +x install.sh
./install.sh

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}         설치가 완료되었습니다!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "접속 정보:"
echo "-----------------------------------------"
echo "URL: http://$(hostname -I | awk '{print $1}')/login.php"
echo "기본 계정: admin"
echo "기본 비밀번호: Admin@2024!"
echo ""
echo -e "${YELLOW}⚠️  주의사항:${NC}"
echo "1. 첫 로그인 후 반드시 비밀번호를 변경하세요"
echo "2. config.php 파일의 API_TOKEN을 변경하세요"
echo "3. 관리자 IP 화이트리스트를 설정하세요"
echo "4. HTTPS 설정을 권장합니다 (certbot 사용)"
echo ""
echo "Agent 상태 확인:"
echo "  systemctl status iptables_agent"
echo ""
echo "로그 확인:"
echo "  tail -f /var/log/iptables_agent.log"
echo "-----------------------------------------"