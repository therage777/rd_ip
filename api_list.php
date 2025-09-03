<?php
header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/lib.php';

try {
	$r = redisClient();
    $ips   = $r->smembers('fw:black_ips');
	$ports = $r->smembers('fw:block:ports');

	// Predis가 PHP5.6에서 반환하는 값은 string 배열일 수 있음
	if ($ips === null) {
		$ips = array();
	}
	if ($ports === null) {
		$ports = array();
	}

	$allow_ipports = $r->smembers('fw:allow:ipports');
	$block_ipports = $r->smembers('fw:block:ipports');

	if ($allow_ipports === null) {
		$allow_ipports = array();
	}
	if ($block_ipports === null) {
		$block_ipports = array();
	}

	$out = array(
		'ok'            => true,
		'black_ips'     => array_values($ips),
		'block_ports'   => array_map('intval', $ports),
		'allow_ipports' => array_values($allow_ipports),
		'block_ipports' => array_values($block_ipports),
		'ts'            => time()
	);

	echo json_encode($out, JSON_UNESCAPED_UNICODE);
} catch (Exception $e) {
	http_response_code(500);
	echo json_encode(array('ok' => false, 'err' => $e->getMessage()), JSON_UNESCAPED_UNICODE);
}
