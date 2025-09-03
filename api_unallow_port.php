<?php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/lib.php';

$admin = getCurrentAdmin();
if (!$admin) { echo json_encode(['ok'=>false,'err'=>'관리자 정보를 가져올 수 없습니다.']); exit; }

$portRaw = isset($_POST['port']) ? trim($_POST['port']) : '';
$comment = isset($_POST['comment']) ? trim($_POST['comment']) : '';
$uid     = $admin['id'];
$uname   = $admin['name'];

$target_server  = isset($_POST['target_server'])  ? trim($_POST['target_server'])  : '';
$target_servers = isset($_POST['target_servers']) ? trim($_POST['target_servers']) : '';
$target_group   = isset($_POST['target_group'])   ? trim($_POST['target_group'])   : '';
$target_groups  = isset($_POST['target_groups'])  ? trim($_POST['target_groups'])  : '';

if ($target_server !== '' && !validateScopeName($target_server)) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'invalid target_server']); exit; }
if ($target_group  !== '' && !validateScopeName($target_group )) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'invalid target_group']); exit; }
if ($target_servers !== '') { $norm = normalizeScopeCsv($target_servers); if ($norm===false){ http_response_code(400); echo json_encode(['ok'=>false,'err'=>'invalid target_servers']); exit; } $target_servers=$norm; }
if ($target_groups  !== '') { $norm = normalizeScopeCsv($target_groups ); if ($norm===false){ http_response_code(400); echo json_encode(['ok'=>false,'err'=>'invalid target_groups']);  exit; } $target_groups =$norm; }

if (!validPortOrRange($portRaw)) { echo json_encode(['ok'=>false,'err'=>'invalid port or range']); exit; }

$ok=true; $err=null;

try {
    $r = redisClient();
    if ($target_server) {
        $r->srem("fw:allow:ports:server:{$target_server}", [$portRaw]);
        $msg = "unallow_port {$portRaw} @server={$target_server}";
    } elseif ($target_servers) {
        $servers = array_filter(array_map('trim', explode(',', $target_servers)));
        foreach ($servers as $server) if ($server!=='') $r->srem("fw:allow:ports:server:{$server}", [$portRaw]);
        $msg = "unallow_port {$portRaw} @servers={$target_servers}";
    } elseif ($target_group) {
        $r->srem("fw:allow:ports:group:{$target_group}", [$portRaw]);
        $msg = "unallow_port {$portRaw} @group={$target_group}";
    } elseif ($target_groups) {
        $groups = array_filter(array_map('trim', explode(',', $target_groups)));
        foreach ($groups as $group) if ($group!=='') $r->srem("fw:allow:ports:group:{$group}", [$portRaw]);
        $msg = "unallow_port {$portRaw} @groups={$target_groups}";
    } else {
        $r->srem('fw:allow:ports', [$portRaw]);
        $msg = "unallow_port {$portRaw}";
    }
    $r->publish(REDIS_CH, $msg);
} catch (Exception $e) { $ok=false; $err=$e->getMessage(); }

try {
    logFirewall([
        'action' => 'unallow_port',
        'port' => ctype_digit($portRaw) ? (int)$portRaw : null,
        'port_from' => (strpos($portRaw,'-')!==false) ? (int)explode('-', $portRaw, 2)[0] : null,
        'port_to' => (strpos($portRaw,'-')!==false) ? (int)explode('-', $portRaw, 2)[1] : null,
        'comment' => (ctype_digit($portRaw) ? $comment : trim($comment === '' ? '' : ($comment.' '))."(range: {$portRaw})"),
        'target_server' => $target_server,
        'target_servers' => $target_servers,
        'target_group' => $target_group,
        'target_groups' => $target_groups,
        'uid' => $uid,
        'uname' => $uname,
        'status' => $ok ? 'OK' : 'ERR',
        'error' => $ok ? null : $err
    ]);
} catch (Exception $e) { /* ignore */ }

echo json_encode(['ok'=>$ok,'err'=>$err]);
