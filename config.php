<?php
// DB
define('DB_DSN', 'mysql:host=127.0.0.1;dbname=rd_ip;charset=utf8mb4');
define('DB_USER', 'rdips');
define('DB_PASS', 'qX8Hvq4VfhzjxQ0b');

// Redis
define('REDIS_HOST', '42.125.244.4');
define('REDIS_PORT', 6379);
define('REDIS_PASS', 'K9mX#vL8@pN2$qR5*wT7&uY1!zA4^bE6+cF3%dG9-hJ0~iM8'); // URL 인코딩 불필요
define('REDIS_DB',   0);
define('REDIS_CH',   'fw:events');

// 쉐어드 비밀키(간단 보호용, POST에 같이 보냄)
define('API_TOKEN', 'R5%2AwT7%26u2BcF3%25dGvL8%40pN2%24q');

// 슈퍼관리자 사용자명 목록(콤마 구분). 여기에 포함된 계정은 대시보드에서 모든 내역을 볼 수 있습니다.
// 기본값: 'admin'
if (!defined('SUPER_ADMINS')) {
    define('SUPER_ADMINS', 'admin');
}
