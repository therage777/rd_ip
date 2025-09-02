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
