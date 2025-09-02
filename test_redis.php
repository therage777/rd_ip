<?php
require_once __DIR__ . '/lib.php';

try {
    $r = redisClient();
    
    // 테스트 데이터 추가
    echo "Adding test data to Redis...\n";
    
    // 전체 서버용 규칙
    $r->sadd('fw:allow:ipports', ['192.168.1.100:8080']);
    $r->sadd('fw:block:ipports', ['10.0.0.1:3306']);
    
    // 특정 서버용 규칙
    $r->sadd('fw:allow:ipports:server:ubuntu01', ['10.211.55.2:2197']);
    $r->sadd('fw:allow:ipports:server:ubuntu02', ['10.211.55.2:2197']);
    
    // 그룹용 규칙
    $r->sadd('fw:allow:ipports:group:web', ['172.16.0.0:443']);
    
    echo "Test data added successfully!\n\n";
    
    // 데이터 확인
    echo "Checking data...\n";
    echo "fw:allow:ipports: " . print_r($r->smembers('fw:allow:ipports'), true) . "\n";
    echo "fw:block:ipports: " . print_r($r->smembers('fw:block:ipports'), true) . "\n";
    echo "fw:allow:ipports:server:ubuntu01: " . print_r($r->smembers('fw:allow:ipports:server:ubuntu01'), true) . "\n";
    echo "fw:allow:ipports:server:ubuntu02: " . print_r($r->smembers('fw:allow:ipports:server:ubuntu02'), true) . "\n";
    echo "fw:allow:ipports:group:web: " . print_r($r->smembers('fw:allow:ipports:group:web'), true) . "\n";
    
    // keys 명령어 테스트
    echo "\nTesting keys command...\n";
    $server_keys = $r->keys('fw:allow:ipports:server:*');
    echo "Server keys: " . print_r($server_keys, true) . "\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}