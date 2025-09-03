<?php
require_once __DIR__ . '/security.php';
requireLogin();
header('Content-Type: application/json');

mustToken();

$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : 'list';

try {
    $r = redisClient();
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'err' => 'redis_connect_failed']);
    exit;
}

if ($action === 'list') {
    try {
        $servers = $r->smembers('fw:known_servers') ?: [];
        sort($servers);
        echo json_encode(['ok' => true, 'servers' => $servers]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'err' => 'redis_error']);
    }
    exit;
}

if ($action === 'add' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $sid = isset($_POST['server_id']) ? trim($_POST['server_id']) : '';
    if ($sid === '') { echo json_encode(['ok' => false, 'err' => 'empty']); exit; }
    if (!function_exists('validateScopeName')) require_once __DIR__ . '/lib.php';
    if (!validateScopeName($sid)) { echo json_encode(['ok' => false, 'err' => 'invalid']); exit; }

    try {
        $r->sadd('fw:known_servers', [$sid]);
        // 감사 로그
        $admin = getCurrentAdmin();
        if ($admin && isset($admin['id'])) {
            auditLog($admin['id'], 'ADD_SERVER', 'server', $sid, null, null);
        }
        echo json_encode(['ok' => true]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'err' => 'redis_error']);
    }
    exit;
}

http_response_code(400);
echo json_encode(['ok' => false, 'err' => 'bad_request']);
