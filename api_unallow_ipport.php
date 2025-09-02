<?php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/lib.php';

// 로그인한 관리자 정보 가져오기
$admin = getCurrentAdmin();

$ip      = isset($_POST['ip'])   ? trim($_POST['ip'])   : '';
$port    = isset($_POST['port']) ? (int)$_POST['port']  : 0;
$comment = isset($_POST['comment']) ? trim($_POST['comment']) : '';
$uid     = $admin['id'];
$uname   = $admin['name'];

// Target parameters for scope filtering
$target_server = isset($_POST['target_server']) ? trim($_POST['target_server']) : '';
$target_servers = isset($_POST['target_servers']) ? trim($_POST['target_servers']) : '';
$target_group = isset($_POST['target_group']) ? trim($_POST['target_group']) : '';
$target_groups = isset($_POST['target_groups']) ? trim($_POST['target_groups']) : '';

if (!validIp($ip)) {
	echo json_encode(['ok' => false, 'err' => 'invalid ip']);
	exit;
}
if (!validPort($port)) {
	echo json_encode(['ok' => false, 'err' => 'invalid port']);
	exit;
}

$ok = true;
$err = null;

try {
	$r = redisClient();
	$ipport = "{$ip}:{$port}";
	
	// 타겟별로 다른 Redis 키에서 삭제
	if ($target_server) {
		// 특정 서버용 키에서 삭제
		$r->srem("fw:allow:ipports:server:{$target_server}", [$ipport]);
		$msg = "unallow_ipport {$ip} {$port} @server={$target_server}";
	} elseif ($target_servers) {
		// 여러 서버 - 각각의 서버 키에서 삭제
		$servers = array_map('trim', explode(',', $target_servers));
		foreach ($servers as $server) {
			if ($server) {
				$r->srem("fw:allow:ipports:server:{$server}", [$ipport]);
			}
		}
		$msg = "unallow_ipport {$ip} {$port} @servers={$target_servers}";
	} elseif ($target_group) {
		// 특정 그룹용 키에서 삭제
		$r->srem("fw:allow:ipports:group:{$target_group}", [$ipport]);
		$msg = "unallow_ipport {$ip} {$port} @group={$target_group}";
	} elseif ($target_groups) {
		// 여러 그룹 - 각각의 그룹 키에서 삭제
		$groups = array_map('trim', explode(',', $target_groups));
		foreach ($groups as $group) {
			if ($group) {
				$r->srem("fw:allow:ipports:group:{$group}", [$ipport]);
			}
		}
		$msg = "unallow_ipport {$ip} {$port} @groups={$target_groups}";
	} else {
		// 전체 서버 (기본)
		$r->srem('fw:allow:ipports', [$ipport]);
		$msg = "unallow_ipport {$ip} {$port}";
	}
	
	$r->publish(REDIS_CH, $msg);
} catch (Exception $e) {
	$ok = false;
	$err = $e->getMessage();
}

logFirewall([
	'action' => 'unallow_ipport',
	'ip' => $ip,
	'port' => $port,
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

echo json_encode(['ok' => $ok, 'err' => $err]);
