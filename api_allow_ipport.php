<?php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/api_auth.php';

require_once __DIR__ . '/lib.php';

if (!defined('REDIS_CH')) {
	define('REDIS_CH', 'fw:events'); // fallback to agent's default channel
}

// 로그인한 관리자 정보 가져오기
$admin = getCurrentAdmin();
// last_activity가 없으면 초기화
if (!isset($_SESSION['last_activity'])) {
	$_SESSION['last_activity'] = time();
}

// getCurrentAdmin()이 null/false 반환 체크 (중요!)
if (!$admin) {
	echo json_encode(['ok' => false, 'err' => '관리자 정보를 가져올 수 없습니다.']);
	exit;
}

$ip      = isset($_POST['ip'])   ? trim($_POST['ip'])   : '';
$portRaw = isset($_POST['port']) ? trim((string)$_POST['port']) : '';
$comment = isset($_POST['comment']) ? trim($_POST['comment']) : '';
$uid     = $admin['id'];
$uname   = $admin['name'];

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

// 다중 입력 지원: ip와 port에 콤마(,)로 여러개 입력 가능
$ips = array_values(array_filter(array_map('trim', explode(',', $ip)), 'strlen'));
$ports = array_values(array_filter(array_map('trim', explode(',', $portRaw)), 'strlen'));

if (empty($ips)) {
    echo json_encode(['ok' => false, 'err' => 'invalid ip']);
    exit;
}
if (empty($ports)) {
    echo json_encode(['ok' => false, 'err' => 'invalid port']);
    exit;
}

// 유효성 검사 (전체가 유효해야 진행)
$invalidIps = [];
foreach ($ips as $ipItem) {
    if (!validIp($ipItem)) $invalidIps[] = $ipItem;
}
if (!empty($invalidIps)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'err' => 'invalid ip(s): ' . implode(', ', $invalidIps)]);
    exit;
}

$invalidPorts = [];
foreach ($ports as $pItem) {
    if (!validPort($pItem)) $invalidPorts[] = $pItem;
}
if (!empty($invalidPorts)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'err' => 'invalid port(s): ' . implode(', ', $invalidPorts)]);
    exit;
}

$ok = true;
$err = null;
$redis_success = false;

// Redis 연결 시도 (실패해도 계속 진행)
try {
    $r = redisClient();
    if ($r) {
        // 모든 조합에 대해 처리
        foreach ($ips as $ipItem) {
            foreach ($ports as $portItem) {
                $ipport = "{$ipItem}:{$portItem}";

                if ($target_server) {
                    // 특정 서버
                    $r->sadd("fw:allow:ipports:server:{$target_server}", [$ipport]);
                    $msg = "allow_ipport {$ipItem} {$portItem} @server={$target_server}";
                } elseif ($target_servers) {
                    // 여러 서버
                    $servers = array_map('trim', explode(',', $target_servers));
                    foreach ($servers as $server) {
                        if ($server) {
                            $r->sadd("fw:allow:ipports:server:{$server}", [$ipport]);
                        }
                    }
                    $msg = "allow_ipport {$ipItem} {$portItem} @servers={$target_servers}";
                } elseif ($target_group) {
                    // 특정 그룹
                    $r->sadd("fw:allow:ipports:group:{$target_group}", [$ipport]);
                    $msg = "allow_ipport {$ipItem} {$portItem} @group={$target_group}";
                } elseif ($target_groups) {
                    // 여러 그룹
                    $groups = array_map('trim', explode(',', $target_groups));
                    foreach ($groups as $group) {
                        if ($group) {
                            $r->sadd("fw:allow:ipports:group:{$group}", [$ipport]);
                        }
                    }
                    $msg = "allow_ipport {$ipItem} {$portItem} @groups={$target_groups}";
                } else {
                    // 전체 서버 (기본)
                    $r->sadd('fw:allow:ipports', [$ipport]);
                    $msg = "allow_ipport {$ipItem} {$portItem}";
                }

                // 조합별 이벤트 발행
                $r->publish(REDIS_CH, $msg);
            }
        }

        $redis_success = true;
    }
} catch (Exception $e) {
	// Redis 실패를 경고로만 처리
	$err = 'Redis 연결 실패 (DB에는 기록됨): ' . substr($e->getMessage(), 0, 100);
}

// DB에 기록
try {
    // 각 조합을 개별 로그로 기록
    foreach ($ips as $ipItem) {
        foreach ($ports as $portItem) {
            logFirewall([
                'action' => 'allow_ipport',
                'ip' => $ipItem,
                'port' => (int)$portItem,
                'comment' => $comment,
                'target_server' => $target_server,
                'target_servers' => $target_servers,
                'target_group' => $target_group,
                'target_groups' => $target_groups,
                'uid' => $uid,
                'uname' => $uname,
                'status' => $redis_success ? 'OK' : 'ERR',
                'error' => $redis_success ? null : $err
            ]);
        }
    }
} catch (Exception $e) {
	$ok = false;
	$err = 'DB 기록 실패: ' . substr($e->getMessage(), 0, 100);
}

// 응답
$response = ['ok' => $ok];
if (!$ok && $err) {
	$response['err'] = $err;
} elseif (!$redis_success && $err) {
	$response['warning'] = $err;
}

echo json_encode($response);
