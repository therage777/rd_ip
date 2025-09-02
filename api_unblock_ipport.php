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
	$r->srem('fw:block:ipports', ["{$ip}:{$port}"]);
	$r->publish(REDIS_CH, "unblock_ipport {$ip} {$port}");
} catch (Exception $e) {
	$ok = false;
	$err = $e->getMessage();
}

logFirewall([
	'action' => 'unblock_ipport',
	'ip' => $ip,
	'port' => $port,
	'comment' => $comment,
	'uid' => $uid,
	'uname' => $uname,
	'status' => $ok ? 'OK' : 'ERR',
	'error' => $err
]);

echo json_encode(['ok' => $ok, 'err' => $err]);
