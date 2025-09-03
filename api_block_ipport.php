<?php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/lib.php';

// 로그인한 관리자 정보 가져오기
$admin = getCurrentAdmin();

$ip      = isset($_POST['ip'])   ? trim($_POST['ip'])   : '';
$portRaw = isset($_POST['port']) ? trim((string)$_POST['port']) : '';
$comment = isset($_POST['comment']) ? trim($_POST['comment']) : '';

// 관리자 정보 확인 (비활성화 등으로 null 가능)
if (!$admin) {
    echo json_encode(['ok' => false, 'err' => '관리자 정보를 가져올 수 없습니다.']);
    exit;
}

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

// 다중 입력 지원: ip, port 둘 다 콤마(,)로 여러 개 처리
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

try {
	$r = redisClient();
	// 모든 조합 처리
	foreach ($ips as $ipItem) {
		foreach ($ports as $portItem) {
			$ipport = "{$ipItem}:{$portItem}";

			if ($target_server) {
				$r->sadd("fw:block:ipports:server:{$target_server}", [$ipport]);
				$msg = "block_ipport {$ipItem} {$portItem} @server={$target_server}";
			} elseif ($target_servers) {
				$servers = array_map('trim', explode(',', $target_servers));
				foreach ($servers as $server) {
					if ($server) {
						$r->sadd("fw:block:ipports:server:{$server}", [$ipport]);
					}
				}
				$msg = "block_ipport {$ipItem} {$portItem} @servers={$target_servers}";
			} elseif ($target_group) {
				$r->sadd("fw:block:ipports:group:{$target_group}", [$ipport]);
				$msg = "block_ipport {$ipItem} {$portItem} @group={$target_group}";
			} elseif ($target_groups) {
				$groups = array_map('trim', explode(',', $target_groups));
				foreach ($groups as $group) {
					if ($group) {
						$r->sadd("fw:block:ipports:group:{$group}", [$ipport]);
					}
				}
				$msg = "block_ipport {$ipItem} {$portItem} @groups={$target_groups}";
			} else {
				$r->sadd('fw:block:ipports', [$ipport]);
				$msg = "block_ipport {$ipItem} {$portItem}";
			}

			$r->publish(REDIS_CH, $msg);
		}
	}
} catch (Exception $e) {
	$ok = false;
	$err = $e->getMessage();
}

// 각 조합별로 감사 로그 기록
foreach ($ips as $ipItem) {
    foreach ($ports as $portItem) {
        logFirewall([
            'action' => 'block_ipport',
            'ip' => $ipItem,
            'port' => (int)$portItem,
            'comment' => $comment,
            'target_server' => $target_server,
            'target_servers' => $target_servers,
            'target_group' => $target_group,
            'target_groups' => $target_groups,
            'uid' => $uid,
            'uname' => $uname,
            'status' => $ok ? 'OK' : 'ERR',
            'error' => $err
        ]);
    }
}

echo json_encode(['ok' => $ok, 'err' => $err]);
