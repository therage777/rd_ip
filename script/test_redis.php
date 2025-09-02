<?php
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/config.php';
$c = new Predis\Client(
    [
        'scheme'  => 'tcp',
        'host'    => REDIS_HOST,
        'port'    => REDIS_PORT,
        'database' => REDIS_DB,
    ],
    [
        'parameters' => [
            // ★ 비번은 "원문" 그대로
            'password' => REDIS_PASS,
            // Redis 6+ ACL 쓰는 환경이면 주석 해제:
            // 'username' => 'default',
        ],
        'read_write_timeout' => 2,
        'timeout' => 1.0,
        'exceptions' => true,
    ]
);

try {
    echo "PING: " . $c->ping() . "\n";
} catch (Exception $e) {
    echo "ERR: " . $e->getMessage() . "\n";
}
