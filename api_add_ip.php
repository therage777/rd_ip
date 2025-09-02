<?php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/lib.php';

// 로그인한 관리자 정보 가져오기
$admin = getCurrentAdmin();

$ip = isset($_POST['ip']) ? trim($_POST['ip']) : '';
$comment = isset($_POST['comment']) ? trim($_POST['comment']) : '';
$uid = $admin['id'];
$uname = $admin['name'];

if (!validIp($ip)) {
	echo json_encode(['ok' => false, 'err' => 'invalid ip']);
	exit;
}

$ok = true;
$err = null;

try {
	$r = redisClient();
	// 상태 저장
	$r->sadd('fw:blacklist:ips', [$ip]);
	// 에이전트에 이벤트
	$r->publish(REDIS_CH, "ban_ip $ip");
} catch (Exception $e) {
	$ok = false;
	$err = $e->getMessage();
}

logFirewall([
	'action' => 'ban_ip',
	'ip' => $ip,
	'comment' => $comment,
	'uid' => $uid,
	'uname' => $uname,
	'status' => $ok ? 'OK' : 'ERR',
	'error' => $err
]);

echo json_encode(['ok' => $ok, 'err' => $err]);
