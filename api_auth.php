<?php

/**
 * API 보안 인증 파일
 * 모든 API 접근 시 로그인 여부 확인
 */

require_once __DIR__ . '/security.php';

// 세션 시작
secureSessionStart();

// 로그인 체크
if (!isLoggedIn()) {
	header('Content-Type: application/json; charset=utf-8');
	http_response_code(401);
	echo json_encode([
		'ok' => false,
		'err' => 'Unauthorized: 로그인이 필요합니다.'
	], JSON_UNESCAPED_UNICODE);
	exit;
}

// CSRF 토큰 검증 (POST 요청일 경우)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$csrfToken = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '';

	if (!verifyCSRFToken($csrfToken)) {
		header('Content-Type: application/json; charset=utf-8');
		http_response_code(403);
		echo json_encode([
			'ok' => false,
			'err' => 'CSRF token validation failed'
		], JSON_UNESCAPED_UNICODE);
		exit;
	}
}

// 세션 타임아웃 체크는 isLoggedIn()에서 이미 처리됨
// checkSessionTimeout(); // 제거 - 정의되지 않은 함수

// getCurrentAdmin() 함수는 security.php에 이미 정의되어 있음
// 중복 정의 제거