<?php
require_once __DIR__ . '/security.php';

secureSessionStart();

if (isset($_SESSION['admin_id'])) {
	// 감사 로그 기록
	auditLog($_SESSION['admin_id'], 'LOGOUT', 'admin', $_SESSION['admin_id']);

	// 로그아웃 로그
	logLogin(
		$_SESSION['admin_id'],
		$_SESSION['username'],
		$_SERVER['REMOTE_ADDR'],
		$_SERVER['HTTP_USER_AGENT'],
		'SUCCESS',
		'Logout',
		session_id()
	);
}

// 세션 파괴
session_destroy();

// 로그인 페이지로 리다이렉트
header('Location: index.php');
exit;
