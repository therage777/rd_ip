# Repository Guidelines

## 프로젝트 구조
- `scripts/agent/`: 방화벽 에이전트(`redis-fw-agent.py`), 운영 유틸(`rd-fw-agent.sh`), 샘플 설정(`redis-fw-agent.conf`).
- `scripts/rd-fw-install.sh`: 설치 스크립트(서비스, ipset/iptables, 설정 자동화). 원격 아티팩트와 SHA256 검증 지원.
- `api_*.php` 등 PHP API는 Redis 세트/이벤트를 발행합니다. Redis 키는 `fw:black_ips`, `fw:block:ports`, `fw:allow:ports`, `fw:allow:ipports`, `fw:block:ipports`를 사용합니다.

## 빌드·테스트·개발 명령
- 설치: `sudo bash scripts/rd-fw-install.sh` (프롬프트에 Redis/포트/SSH 등 입력).
- 상태점검: `sudo scripts/agent/rd-fw-agent.sh health` (ipset/iptables 보증, Redis PING, 요약 출력).
- 운영 유틸: `rd-fw-agent.sh ban <IP> | unban <IP> | block <PORT> | unblock <PORT>`.
- 수동 발행 예: `redis-cli -h <HOST> -a '<PASS>' PUBLISH fw:events "allow_ipport 1.2.3.4 2193 @server=web01"`.

## 코딩 스타일·네이밍
- Bash: `set -euo pipefail`, 함수는 `lower_snake_case`, 환경변수는 UPPER_CASE.
- Python: 4칸 들여쓰기, 작은 함수 단위, 기본 로그 레벨 `INFO`(환경변수 `LOG_LEVEL`로 조정).
- Redis 키: 전역과 선택적 스코프 키를 병행(`...:server:<id>`, `...:group:<name>`).

## 테스트 가이드
- 동기화/룰 확인: `ipset list fw_allow_ipports | sed -n '1,20p'`, `iptables -S INPUT | grep -E 'fw_(allow|block)_'`.
- 저수준 확인: `journalctl -u redis-fw-agent -n 100 --no-pager`, `rd-fw-agent.sh status`.
- 보호 포트: `PROTECTED_PORTS`(SSH 포함)는 기본 허용 금지. 강제 허용은 `@force` 플래그 또는 `ALLOW_PROTECTED_PORTS=1`로만.

## 커밋·PR 규칙
- 커밋: 간결한 명령형. 예) `feat(agent): health 체크 보강`, `fix(iptables): UFW 체인 순서 보정`.
- 브랜치: `feat/...`, `fix/...`, `chore/...` 패턴 권장.
- PR 필수사항: 배경/의도, 영향 범위(체인/세트), 재현·검증 절차(예: redis-cli 발행/ipset 확인), 관련 이슈 링크.

## 보안·설정 팁
- 비밀번호·토큰은 절대 커밋 금지. `scripts/agent/redis-fw-agent.conf`를 `/etc/redis-fw-agent.conf`로 배치하고 권한 `600` 유지.
- 설치 무결성: `STRICT_VERIFY=1` 유지, 필요 시 `PIN_SHA_*`로 해시 고정.
- Redis 노출 최소화(바인드/ACL), 에이전트 권한 최소화(systemd 제한 옵션 유지), 긴급 SSH는 `EMERGENCY_SSH_CIDR`로만 허용.

## 스코프 키·이벤트 예시
- 전역 허용(모든 서버):
  - `SADD fw:allow:ipports "1.2.3.4:2193"`
  - `PUBLISH fw:events "allow_ipport 1.2.3.4 2193"`
- 특정 서버만:
  - `SADD fw:allow:ipports:server:web01 "1.2.3.4:2193"`
  - `PUBLISH fw:events "allow_ipport 1.2.3.4 2193 @server=web01"`
- 특정 그룹만:
  - `SADD fw:allow:ipports:group:seoul "1.2.3.4:2193"`
  - `PUBLISH fw:events "block_port 25 @group=seoul"`
- 블랙리스트 예:
  - `SADD fw:black_ips "9.9.9.9"`
  - `PUBLISH fw:events "ban_ip 9.9.9.9 @servers=web02,db02"`

## 추가 예시·운용 팁
- 포트 허용/해제: `PUBLISH fw:events "allow_port 2193"`, `PUBLISH fw:events "unallow_port 2193"`
- 여러 그룹 동시 적용: `PUBLISH fw:events "block_ipport 8.8.8.8 25 @groups=seoul,edge"`
- 에이전트 유틸 예: `scripts/agent/rd-fw-agent.sh ban 1.2.3.4`, `... unblock 25`, `... fix`, `... logs`
- 서비스 관리: `systemctl restart redis-fw-agent`, 로그: `journalctl -u redis-fw-agent -n 100 --no-pager`

## 설치 옵션(무결성·버전 고정) 예시
- 엄격 검증(기본): `STRICT_VERIFY=1 sudo bash scripts/rd-fw-install.sh`
- 검증 완화(권장하지 않음): `STRICT_VERIFY=0 sudo bash scripts/rd-fw-install.sh`
- 아티팩트 버전 고정: `ARTIFACT_VERSION=v1.2.3 sudo bash scripts/rd-fw-install.sh`
- 해시 고정 설치:
  - `PIN_SHA_AGENT=<64hex> PIN_SHA_HELPER=<64hex> PIN_SHA_CONF=<64hex> sudo bash scripts/rd-fw-install.sh`
  - 해시 계산: `sha256sum redis-fw-agent.py | awk '{print $1}'`

## 환경 변수 요약
- 필수: `REDIS_HOST`, `REDIS_PORT`, `REDIS_DB`, `REDIS_PASS`, `FW_CHANNEL`
- 스코프: `SERVER_ID`(기본 hostname), `SERVER_GROUPS`(콤마)
- 보안: `SSH_PORT`, `PROTECTED_PORTS`(기본 SSH 포함), `EMERGENCY_SSH_CIDR`, `ALLOW_PROTECTED_PORTS`
- 정책: `FTP_PORT`(즉시 DROP 예외), `LOG_LEVEL`(DEBUG/INFO/...) 

## 키·ipset 매핑
- Redis 세트 → ipset
  - `fw:black_ips` → `fw_black_ips`
  - `fw:block:ports` → `fw_block_ports`
  - `fw:allow:ports` → `fw_allow_ports`
  - `fw:allow:ipports` → `fw_allow_ipports`
  - `fw:block:ipports` → `fw_block_ipports`

## Nginx 연동 체크리스트
- 가이드: `NGINX_SETUP.md` 참고. 샘플: `nginx_secure.conf`, `nginx_rate_limit.conf`, `nginx_ip_whitelist.conf`.
- 요청 제한(zone 선언은 http 블록): `limit_req_zone $binary_remote_addr zone=api:10m rate=2r/s;`
- API POST 전용: `location ~ ^/api_.*\.php$ { return 405 if not POST; include enable-php-pathinfo.conf; }`
- 관리자 페이지 화이트리스트: `location ~ ^/(login|dashboard|admin_manage)\.php$ { include /usr/local/nginx/conf/ip_whitelist.conf; }`
- 중요 파일/디렉토리 차단: `vendor/`, `agent/`, `script(s)/`, `*.sql|*.md|*.sh|*.py` 등 접근 거부.
- HTTPS 권장: 80 → 443 리다이렉트, HSTS 활성화.

## 헬스체크·체인 순서 점검
- 서비스: `systemctl status redis-fw-agent --no-pager` (active 확인), `scripts/agent/rd-fw-agent.sh health`.
- Redis: `redis-cli -h <HOST> -a '<PASS>' PING` → `PONG`.
- ipset 존재: `ipset list fw_allow_ipports | sed -n '1,10p'`.
- 체인/순서: Ubuntu는 `ufw-before-input`, CentOS/기타는 `INPUT` 사용.
  - 확인: `iptables -S ufw-before-input | nl | grep -E 'fw_(allow|block)_'` 또는 `iptables -S INPUT | nl | grep -E 'fw_(allow|block)_'`.
  - 필요한 경우 유틸이 자동 삽입: `scripts/agent/rd-fw-agent.sh fix`.
