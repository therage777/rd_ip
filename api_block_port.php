<?php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/lib.php';

// 로그인한 관리자 정보 가져오기
$admin = getCurrentAdmin();

$portRaw = isset($_POST['port']) ? trim($_POST['port']) : '';
$comment = isset($_POST['comment']) ? trim($_POST['comment']) : '';

// 관리자 정보 확인 (비활성화 등으로 null 가능)
if (!$admin) {
    echo json_encode(['ok' => false, 'err' => '관리자 정보를 가져올 수 없습니다.']);
    exit;
}

$uid = $admin['id'];
$uname = $admin['name'];

// Target parameters for scope filtering
$target_server = isset($_POST['target_server']) ? trim($_POST['target_server']) : '';
$target_servers = isset($_POST['target_servers']) ? trim($_POST['target_servers']) : '';
$target_group = isset($_POST['target_group']) ? trim($_POST['target_group']) : '';
$target_groups = isset($_POST['target_groups']) ? trim($_POST['target_groups']) : '';

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
    if ($norm === false) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'err' => 'invalid target_servers']);
        exit;
    }
    $target_servers = $norm;
}
if ($target_groups !== '') {
    $norm = normalizeScopeCsv($target_groups);
    if ($norm === false) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'err' => 'invalid target_groups']);
        exit;
    }
    $target_groups = $norm;
}

if (!validPortOrRange($portRaw)) {
    echo json_encode(['ok' => false, 'err' => 'invalid port or range']);
    exit;
}

$ok = true;
$err = null;

try {
    $r = redisClient();
    // 전역/스코프 저장 (에이전트 sync_all과 호환)
    if ($target_server) {
        $r->sadd("fw:block:ports:server:{$target_server}", [$portRaw]);
    } elseif ($target_servers) {
        $servers = array_filter(array_map('trim', explode(',', $target_servers)));
        foreach ($servers as $server) {
            if ($server !== '') {
                $r->sadd("fw:block:ports:server:{$server}", [$portRaw]);
            }
        }
    } elseif ($target_group) {
        $r->sadd("fw:block:ports:group:{$target_group}", [$portRaw]);
    } elseif ($target_groups) {
        $groups = array_filter(array_map('trim', explode(',', $target_groups)));
        foreach ($groups as $group) {
            if ($group !== '') {
                $r->sadd("fw:block:ports:group:{$group}", [$portRaw]);
            }
        }
    } else {
        // 전체 서버 (기본)
        $r->sadd('fw:block:ports', [$portRaw]);
    }

    // Build publish message with scope
    $msg = "block_port $portRaw";
    if ($target_server) {
        $msg .= " @server={$target_server}";
    } elseif ($target_servers) {
        $msg .= " @servers={$target_servers}";
    } elseif ($target_group) {
        $msg .= " @group={$target_group}";
    } elseif ($target_groups) {
        $msg .= " @groups={$target_groups}";
    }

    $r->publish(REDIS_CH, $msg);
} catch (Exception $e) {
	$ok = false;
	$err = $e->getMessage();
}

logFirewall([
    'action' => 'block_port',
    'port' => ctype_digit($portRaw) ? (int)$portRaw : null,
    'port_from' => (strpos($portRaw,'-')!==false) ? (int)explode('-', $portRaw, 2)[0] : null,
    'port_to' => (strpos($portRaw,'-')!==false) ? (int)explode('-', $portRaw, 2)[1] : null,
    'comment' => (ctype_digit($portRaw) ? $comment : trim($comment === '' ? '' : ($comment.' '))."(range: {$portRaw})"),
	'uid' => $uid,
	'uname' => $uname,
	'status' => $ok ? 'OK' : 'ERR',
	'error' => $err
]);

echo json_encode(['ok' => $ok, 'err' => $err]);
