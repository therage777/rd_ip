<?php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/lib.php';

// 로그인한 관리자 정보 가져오기
$admin = getCurrentAdmin();
if (!$admin) {
    echo json_encode(['ok' => false, 'err' => '관리자 정보를 가져올 수 없습니다.']);
    exit;
}

$port    = isset($_POST['port']) ? (int)$_POST['port'] : 0;
$comment = isset($_POST['comment']) ? trim($_POST['comment']) : '';
$uid     = $admin['id'];
$uname   = $admin['name'];

// 스코프 파라미터
$target_server  = isset($_POST['target_server'])  ? trim($_POST['target_server'])  : '';
$target_servers = isset($_POST['target_servers']) ? trim($_POST['target_servers']) : '';
$target_group   = isset($_POST['target_group'])   ? trim($_POST['target_group'])   : '';
$target_groups  = isset($_POST['target_groups'])  ? trim($_POST['target_groups'])  : '';

// 스코프 값 검증 및 정규화
if ($target_server !== '' && !validateScopeName($target_server)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'err' => 'invalid target_server']);
    exit;
}
if ($target_group !== '' && !validateScopeName($target_group)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'err' => 'invalid target_group']);
    exit;
}
if ($target_servers !== '') {
    $norm = normalizeScopeCsv($target_servers);
    if ($norm === false) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'invalid target_servers']); exit; }
    $target_servers = $norm;
}
if ($target_groups !== '') {
    $norm = normalizeScopeCsv($target_groups);
    if ($norm === false) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'invalid target_groups']); exit; }
    $target_groups = $norm;
}

if (!validPort($port)) {
    echo json_encode(['ok' => false, 'err' => 'invalid port']);
    exit;
}

$ok = true; $err = null;

try {
    $r = redisClient();
    // 스코프별 저장
    if ($target_server) {
        $r->sadd("fw:allow:ports:server:{$target_server}", [$port]);
        $msg = "allow_port {$port} @server={$target_server}";
    } elseif ($target_servers) {
        $servers = array_filter(array_map('trim', explode(',', $target_servers)));
        foreach ($servers as $server) if ($server !== '') $r->sadd("fw:allow:ports:server:{$server}", [$port]);
        $msg = "allow_port {$port} @servers={$target_servers}";
    } elseif ($target_group) {
        $r->sadd("fw:allow:ports:group:{$target_group}", [$port]);
        $msg = "allow_port {$port} @group={$target_group}";
    } elseif ($target_groups) {
        $groups = array_filter(array_map('trim', explode(',', $target_groups)));
        foreach ($groups as $group) if ($group !== '') $r->sadd("fw:allow:ports:group:{$group}", [$port]);
        $msg = "allow_port {$port} @groups={$target_groups}";
    } else {
        $r->sadd('fw:allow:ports', [$port]);
        $msg = "allow_port {$port}";
    }
    $r->publish(REDIS_CH, $msg);
} catch (Exception $e) { $ok=false; $err=$e->getMessage(); }

try {
    logFirewall([
        'action' => 'allow_port',
        'port' => $port,
        'comment' => $comment,
        'target_server' => $target_server,
        'target_servers' => $target_servers,
        'target_group' => $target_group,
        'target_groups' => $target_groups,
        'uid' => $uid,
        'uname' => $uname,
        'status' => $ok ? 'OK' : 'ERR',
        'error' => $ok ? null : $err
    ]);
} catch (Exception $e) { /* ignore logging error */ }

echo json_encode(['ok' => $ok, 'err' => $err]);

