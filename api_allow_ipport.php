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
$redis_success = false;

// Redis 연결 시도 (실패해도 계속 진행)
try {
	$r = redisClient();
	if ($r) {
		$r->sadd('fw:allow:ipports', ["{$ip}:{$port}"]);

		// Build publish message with scope
		$msg = "allow_ipport {$ip} {$port}";
		if ($target_server) {
			$msg .= " @server={$target_server}";
		} elseif ($target_servers) {
			$msg .= " @servers={$target_servers}";
		} elseif ($target_group) {
			$msg .= " @group={$target_group}";
		} elseif ($target_groups) {
			$msg .= " @groups={$target_groups}";
		}
		// publish to channel: " . REDIS_CH
		$r->publish(REDIS_CH, $msg);
		$redis_success = true;
	}
} catch (Exception $e) {
	// Redis 실패를 경고로만 처리
	$err = 'Redis 연결 실패 (DB에는 기록됨): ' . substr($e->getMessage(), 0, 100);
}

// DB에 기록
try {
	logFirewall([
		'action' => 'allow_ipport',
		'ip' => $ip,
		'port' => $port,
		'comment' => $comment,
		'uid' => $uid,
		'uname' => $uname,
		'status' => $redis_success ? 'OK' : 'ERR',
		'error' => $redis_success ? null : $err
	]);
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