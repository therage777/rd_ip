<?php
/**
 * index.php - 로그인 페이지로 리다이렉트
 * 
 * 모든 API는 이제 로그인이 필요하므로
 * 직접 접근은 차단하고 로그인 페이지로 리다이렉트합니다.
 */

// 로그인 페이지로 리다이렉트
header('Location: login.php');
exit;