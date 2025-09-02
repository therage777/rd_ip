<?php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/lib.php';

// 로그인한 관리자 정보 가져오기
$admin = getCurrentAdmin();

$port = isset($_POST['port']) ? (int)$_POST['port'] : 0;
$comment = isset($_POST['comment']) ? trim($_POST['comment']) : '';
$uid = $admin['id'];
$uname = $admin['name'];

// Target parameters for scope filtering
$target_server = isset($_POST['target_server']) ? trim($_POST['target_server']) : '';
$target_servers = isset($_POST['target_servers']) ? trim($_POST['target_servers']) : '';
$target_group = isset($_POST['target_group']) ? trim($_POST['target_group']) : '';
$target_groups = isset($_POST['target_groups']) ? trim($_POST['target_groups']) : '';

if (!validPort($port)) {
	echo json_encode(['ok' => false, 'err' => 'invalid port']);
	exit;
}

$ok = true;
$err = null;

try {
	$r = redisClient();
	$r->sadd('fw:block:ports', [$port]);
	
	// Build publish message with scope
	$msg = "block_port $port";
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
	'port' => $port,
	'comment' => $comment,
	'uid' => $uid,
	'uname' => $uname,
	'status' => $ok ? 'OK' : 'ERR',
	'error' => $err
]);

echo json_encode(['ok' => $ok, 'err' => $err]);
