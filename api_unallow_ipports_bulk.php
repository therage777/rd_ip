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

$uid   = $admin['id'];
$uname = $admin['name'];

// 코멘트(옵션)
$comment = isset($_POST['comment']) ? trim((string)$_POST['comment']) : '대시보드에서 일괄 허용 해제';

// entries: JSON 배열 [{ip, port, target_type, target_value}]
$entriesRaw = isset($_POST['entries']) ? $_POST['entries'] : '';

// pairs: "ip:port,ip:port" 형식(레거시 호환)
$pairsRaw = isset($_POST['pairs']) ? $_POST['pairs'] : '';

$entries = [];

// 1) entries(JSON) 우선 처리
if ($entriesRaw) {
    if (is_array($entriesRaw)) {
        $entries = $entriesRaw;
    } else {
        $decoded = json_decode((string)$entriesRaw, true);
        if (is_array($decoded)) {
            $entries = $decoded;
        }
    }
}

// 2) pairs CSV 보조 처리
if (empty($entries) && $pairsRaw) {
    if (is_array($pairsRaw)) {
        $pairs = $pairsRaw;
    } else {
        $pairs = array_filter(array_map('trim', explode(',', (string)$pairsRaw)), 'strlen');
    }
    foreach ($pairs as $p) {
        $parts = explode(':', $p, 2);
        if (count($parts) === 2) {
            $entries[] = [
                'ip' => trim($parts[0]),
                'port' => trim($parts[1]),
                'target_type' => 'all',
                'target_value' => ''
            ];
        }
    }
}

if (empty($entries)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'err' => 'no entries']);
    exit;
}

// 유효성 검사 및 정규화
$clean = [];
foreach ($entries as $e) {
    $ip = isset($e['ip']) ? trim((string)$e['ip']) : '';
    $port = isset($e['port']) ? trim((string)$e['port']) : '';
    $tt = isset($e['target_type']) ? trim((string)$e['target_type']) : 'all';
    $tv = isset($e['target_value']) ? trim((string)$e['target_value']) : '';

    if (!validIp($ip)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'err' => 'invalid ip: ' . $ip]);
        exit;
    }
    if (!validPort($port)) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'err' => 'invalid port: ' . $port]);
        exit;
    }

    if ($tt === 'server' || $tt === 'group') {
        if ($tv === '' || !validateScopeName($tv)) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'err' => 'invalid target_value for ' . $tt]);
            exit;
        }
    } else {
        // all, or any other -> treat as all
        $tt = 'all';
        $tv = '';
    }

    $clean[] = [
        'ip' => $ip,
        'port' => (int)$port,
        'target_type' => $tt,
        'target_value' => $tv,
    ];
}

$ok = true;
$err = null;
$affected = 0;

try {
    $r = redisClient();
    foreach ($clean as $e) {
        $ip = $e['ip'];
        $port = (int)$e['port'];
        $ipport = $ip . ':' . $port;

        if ($e['target_type'] === 'server') {
            $r->srem('fw:allow:ipports:server:' . $e['target_value'], [$ipport]);
            $msg = "unallow_ipport {$ip} {$port} @server={$e['target_value']}";
        } elseif ($e['target_type'] === 'group') {
            $r->srem('fw:allow:ipports:group:' . $e['target_value'], [$ipport]);
            $msg = "unallow_ipport {$ip} {$port} @group={$e['target_value']}";
        } else {
            $r->srem('fw:allow:ipports', [$ipport]);
            $msg = "unallow_ipport {$ip} {$port}";
        }

        $r->publish(REDIS_CH, $msg);
        $affected++;

        // 로깅
        logFirewall([
            'action' => 'unallow_ipport',
            'ip' => $ip,
            'port' => $port,
            'comment' => $comment,
            'target_server' => $e['target_type'] === 'server' ? $e['target_value'] : '',
            'target_group' => $e['target_type'] === 'group' ? $e['target_value'] : '',
            'uid' => $uid,
            'uname' => $uname,
            'status' => 'OK',
            'error' => null
        ]);
    }
} catch (Exception $e) {
    $ok = false;
    $err = $e->getMessage();
}

echo json_encode(['ok' => $ok, 'err' => $err, 'affected' => $affected]);

