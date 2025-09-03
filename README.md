# Redis 기반 iptables/ipset 방화벽 관리 시스템

## 개요
Redis Pub/Sub과 세트를 사용해 방화벽 규칙을 실시간 분배하고, 웹 UI/API(PHP)로 규칙을 관리합니다. 에이전트는 로컬 ipset/iptables에 규칙을 반영하며, 모든 작업은 MySQL에 감사 로그로 기록됩니다.

## 구성 요소
- 웹/API(PHP 5.6+): `index.php`, `dashboard.php`, `api_*.php`
- 에이전트/스크립트: `scripts/agent/*`, 설치 스크립트 `scripts/rd-fw-install.sh`
- 데이터: `schema.sql`(DB), `config.php`(DB/Redis/토큰), Composer 의존성 `vendor/`

## Redis 키와 Pub/Sub
- 세트 키(Global):
  - 차단 IP: `fw:black_ips`
  - 차단 포트: `fw:block:ports`
  - 허용 포트: `fw:allow:ports`
  - 허용 IP:PORT: `fw:allow:ipports`
  - 차단 IP:PORT: `fw:block:ipports`
- 스코프 키(선택): `...:server:<id>`, `...:group:<name>`
- 채널: `fw:events`
  - 예: `ban_ip 192.168.1.100`, `block_port 25`, `allow_ipport 1.2.3.4 2193 @server=web01`

## 설치
웹 앱(필수):
1) DB 준비: `mysql -u root -p < schema.sql`
2) 의존성: `composer install`
3) 설정: `config.php`에 DB/Redis/토큰 설정

에이전트(서버별):
1) 루트 권한으로 실행: `sudo bash scripts/rd-fw-install.sh`
2) 프롬프트에 Redis/SSH/FTP/채널 입력(무결성 검증 및 systemd 서비스 자동 구성)
3) 상태 점검: `scripts/agent/rd-fw-agent.sh health`

## 주요 API 예시(POST, token 필요)
- IP 차단/해제: `/api_add_ip.php`, `/api_del_ip.php`
- 포트 차단/해제: `/api_block_port.php`, `/api_unblock_port.php`
- 포트 허용/해제: `/api_allow_port.php`, `/api_unallow_port.php` (단일/범위 `20000-30000` 지원)
- IP+포트 허용/차단/해제: `/api_allow_ipport.php`, `/api_block_ipport.php`, `/api_unallow_ipport.php`
- 스코프 파라미터: `target_server`, `target_servers`, `target_group`, `target_groups`

## API 인증·요청/응답 스키마
- 인증: 로그인 세션(쿠키) + CSRF 토큰(`csrf_token` POST 필드) 필수. 비로그인/토큰 불일치 시 401/403 반환.
- 공통 응답: `{ "ok": true|false, "err"?: string, "warning"?: string }`
- 공통 파라미터(선택): `comment`, 스코프(`target_server|target_servers|target_group|target_groups`)

예시: IP:PORT 허용(전역)
```bash
# 브라우저 로그인 후, 페이지의 hidden input csrf_token 값을 사용하세요.
curl -s -b cookie.txt -c cookie.txt \
  -X POST https://<host>/api_allow_ipport.php \
  -d csrf_token=<CSRF_TOKEN> -d ip=1.2.3.4 -d port=2193 -d comment="FTP allow"
```

예시: 여러 IP와 여러 포트 동시 허용(전역)
```bash
curl -s -b cookie.txt -c cookie.txt \
  -X POST https://<host>/api_allow_ipport.php \
  -d csrf_token=<CSRF_TOKEN> \
  -d ip="1.1.1.1,2.2.2.2" \
  -d port="22,3306" \
  -d comment="VPN IP 다중 허용"
# 생성되는 조합: 1.1.1.1:22, 1.1.1.1:3306, 2.2.2.2:22, 2.2.2.2:3306
```

예시: 포트 범위 차단(그룹 한정)
```bash
curl -s -b cookie.txt -c cookie.txt \
  -X POST https://<host>/api_block_port.php \
  -d csrf_token=<CSRF_TOKEN> -d port=20000-30000 -d target_group=seoul -d comment="block range"
```

필드 요약
- `api_add_ip.php`/`api_del_ip.php`: `ip`(필수), `comment`(선택) + 스코프
- `api_block_port.php`/`api_unblock_port.php`: `port` 또는 `port` 범위 문자열(필수), `comment`(선택) + 스코프
- `api_allow_port.php`/`api_unallow_port.php`: `port` 또는 범위(필수), `comment`(선택) + 스코프
- `api_allow_ipport.php`/`api_unallow_ipport.php`/`api_block_ipport.php`/`api_unblock_ipport.php`: `ip`(필수, 콤마로 여러 개 가능), `port`(필수, 콤마로 여러 개 가능), `comment`(선택) + 스코프

## 에이전트 동작 요약
- 로컬 ipset 세트: `fw_black_ips`, `fw_block_ports`, `fw_allow_ports`, `fw_allow_ipports`, `fw_block_ipports`
- 체인: Ubuntu=UFW `ufw-before-input`, CentOS/기타=`INPUT`에 룰 보증
- 보호 포트: `PROTECTED_PORTS`(SSH 포함)는 기본 허용 금지. `@force` 또는 `ALLOW_PROTECTED_PORTS=1`로만 허용

## 보안 가이드
- HTTPS/HSTS 권장, 관리자 IP 화이트리스트(Nginx 샘플: `nginx_*`), 중요 경로 차단
- Redis 바인드/ACL, 강력한 비밀번호, 네트워크 분리
- 설정 파일 권한: `/etc/redis-fw-agent.conf`는 600 유지, 비밀은 VCS에 커밋 금지

## 문제 해결
- Redis PING: `redis-cli -h <HOST> -a '<PASS>' PING` → PONG
- ipset/iptables 확인: `ipset list fw_allow_ipports | sed -n '1,20p'`, `iptables -S <CHAIN> | nl | grep -E 'fw_(allow|block)_'`
- 서비스 로그: `journalctl -u redis-fw-agent -n 100 --no-pager`

## Nginx 설정 스니펫(요약)
server {
    listen 80;
    server_name <your-domain>;
    root /home/www/rd_ip;
    index index.php;

    # 중요 경로/파일 차단
    location ^~ /vendor/ { deny all; }
    location ^~ /agent/  { deny all; }
    location ^~ /script/ { deny all; }  # 환경에 따라 scripts/ 경로도 차단
    location ^~ /scripts/ { deny all; }
    location ~ \.(sql|md|sh|py|yml|yaml|lock|json|env)$ { deny all; return 404; }

    # API는 POST만 허용
    location ~ ^/api_.*\.php$ {
        if ($request_method !~ ^(POST)$ ) { return 405; }
        include enable-php-pathinfo.conf;
        # Rate limit 적용(사전 http 블록에 zone 선언 필요)
        limit_req zone=api burst=10 nodelay;
    }

    # 로그인 제한
    location = /login.php {
        include enable-php-pathinfo.conf;
        limit_req zone=login burst=5 nodelay;
    }

    # 일반 PHP 처리
    include enable-php-pathinfo.conf;
}

http {
    # 요청 제한 존 선언(nginx.conf의 http 블록)
    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=2r/s;
}

자세한 샘플은 `NGINX_SETUP.md`, `nginx_secure.conf`, `nginx_rate_limit.conf`, `nginx_ip_whitelist.conf`를 참고하세요.

## CSRF 토큰 획득 방법(테스트용)
- 브라우저로 `/login.php`에 로그인한 뒤, 대시보드/폼 소스에서 hidden input `csrf_token` 값을 확인하여 사용합니다.
- curl로 세션 유지 중이라면 다음과 같이 추출할 수 있습니다(예시, 환경에 따라 조정):
```bash
# 1) 브라우저로 먼저 로그인하여 세션을 만든 뒤, 그 쿠키를 cookie.txt로 가져왔다고 가정
# 2) 대시보드에서 토큰 추출(폼에 csrf_token hidden이 포함되어 있어야 함)
curl -s -b cookie.txt -c cookie.txt https://<host>/dashboard.php \
  | grep -oE 'name="csrf_token" value="[^"]+' | sed 's/.*value="//'
```
주의: CSRF 토큰은 세션과 결합되어 있으므로 같은 cookie로 요청해야 합니다.
