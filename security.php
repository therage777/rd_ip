<?php
/**
 * 보안 관련 함수 라이브러리
 * PHP 5.6 호환
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib.php';

// 보안 설정
define('MAX_LOGIN_ATTEMPTS', 5);           // 최대 로그인 시도 횟수
define('LOCKOUT_TIME', 1800);              // 계정 잠금 시간 (30분)
define('SESSION_LIFETIME', 3600);          // 세션 유효 시간 (1시간)
define('SESSION_REGENERATE_TIME', 900);    // 세션 ID 재생성 주기 (15분)
define('PASSWORD_MIN_LENGTH', 8);          // 최소 비밀번호 길이
define('PASSWORD_EXPIRE_DAYS', 90);        // 비밀번호 만료 기간

/**
 * 세션 시작 (보안 강화)
 */
function secureSessionStart() {
    if (session_status() === PHP_SESSION_NONE) {
        // 세션 쿠키 설정
        ini_set('session.use_only_cookies', 1);
        ini_set('session.use_strict_mode', 1);
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) ? 1 : 0);
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
        
        // 세션 이름 변경
        session_name('RDIPSESS');
        
        // 세션 시작
        session_start();
        
        // 세션 하이재킹 방지
        if (!isset($_SESSION['created'])) {
            $_SESSION['created'] = time();
            $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
            $_SESSION['ua'] = $_SERVER['HTTP_USER_AGENT'];
        } else {
            // IP 체크
            if ($_SESSION['ip'] !== $_SERVER['REMOTE_ADDR']) {
                session_destroy();
                die('Security violation: IP mismatch');
            }
            
            // User Agent 체크
            if ($_SESSION['ua'] !== $_SERVER['HTTP_USER_AGENT']) {
                session_destroy();
                die('Security violation: User agent mismatch');
            }
            
            // 세션 ID 재생성
            if (time() - $_SESSION['created'] > SESSION_REGENERATE_TIME) {
                session_regenerate_id(true);
                $_SESSION['created'] = time();
            }
        }
    }
}

/**
 * CSRF 토큰 생성
 */
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(openssl_random_pseudo_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * CSRF 토큰 검증
 */
function verifyCSRFToken($token) {
    if (!isset($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * IP 주소가 허용 목록에 있는지 확인
 */
function isIPAllowed($allowedIPs, $currentIP) {
    if (empty($allowedIPs)) {
        return true; // 제한 없음
    }
    
    $allowed = json_decode($allowedIPs, true);
    if (!is_array($allowed)) {
        return false;
    }
    
    foreach ($allowed as $ip) {
        // CIDR 표기법 지원
        if (strpos($ip, '/') !== false) {
            if (ipInCIDR($currentIP, $ip)) {
                return true;
            }
        } else {
            if ($ip === $currentIP || $ip === '*') {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * IP가 CIDR 범위에 포함되는지 확인
 */
function ipInCIDR($ip, $cidr) {
    list($subnet, $bits) = explode('/', $cidr);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask;
    return ($ip & $mask) == $subnet;
}

/**
 * 브루트포스 공격 체크
 */
function checkBruteForce($ip, $username = null) {
    $pdo = pdo();
    
    // IP 기반 체크
    $sql = "SELECT * FROM login_attempts 
            WHERE ip_address = :ip 
            AND (username = :username OR username IS NULL)
            AND (blocked_until IS NULL OR blocked_until > NOW())
            ORDER BY blocked_until DESC 
            LIMIT 1";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':ip' => $ip, ':username' => $username]);
    $attempt = $stmt->fetch();
    
    if ($attempt && $attempt['blocked_until'] && strtotime($attempt['blocked_until']) > time()) {
        return ['blocked' => true, 'until' => $attempt['blocked_until']];
    }
    
    if ($attempt && $attempt['attempt_count'] >= MAX_LOGIN_ATTEMPTS) {
        // 차단 시간 설정
        $blockedUntil = date('Y-m-d H:i:s', time() + LOCKOUT_TIME);
        $updateSql = "UPDATE login_attempts 
                      SET blocked_until = :blocked 
                      WHERE id = :id";
        $pdo->prepare($updateSql)->execute([
            ':blocked' => $blockedUntil,
            ':id' => $attempt['id']
        ]);
        
        return ['blocked' => true, 'until' => $blockedUntil];
    }
    
    return ['blocked' => false];
}

/**
 * 로그인 시도 기록
 */
function recordLoginAttempt($ip, $username, $success) {
    $pdo = pdo();
    
    if ($success) {
        // 성공 시 시도 횟수 리셋
        $sql = "DELETE FROM login_attempts 
                WHERE ip_address = :ip 
                AND (username = :username OR username IS NULL)";
        $pdo->prepare($sql)->execute([':ip' => $ip, ':username' => $username]);
    } else {
        // 실패 시 카운트 증가
        $sql = "INSERT INTO login_attempts (ip_address, username, attempt_count, first_attempt, last_attempt)
                VALUES (:ip, :username, 1, NOW(), NOW())
                ON DUPLICATE KEY UPDATE 
                attempt_count = attempt_count + 1,
                last_attempt = NOW()";
        $pdo->prepare($sql)->execute([':ip' => $ip, ':username' => $username]);
    }
}

/**
 * 로그인 로그 기록
 */
function logLogin($adminId, $username, $ip, $userAgent, $status, $reason = null, $sessionId = null) {
    $pdo = pdo();
    $sql = "INSERT INTO login_logs 
            (admin_id, username, ip_address, user_agent, login_status, failure_reason, session_id)
            VALUES (:admin_id, :username, :ip, :ua, :status, :reason, :session)";
    
    $pdo->prepare($sql)->execute([
        ':admin_id' => $adminId,
        ':username' => $username,
        ':ip' => $ip,
        ':ua' => substr($userAgent, 0, 255),
        ':status' => $status,
        ':reason' => $reason,
        ':session' => $sessionId
    ]);
}

/**
 * 감사 로그 기록
 */
function auditLog($adminId, $action, $targetType = null, $targetId = null, $oldValue = null, $newValue = null) {
    $pdo = pdo();
    $sql = "INSERT INTO audit_logs 
            (admin_id, action, target_type, target_id, old_value, new_value, ip_address, user_agent)
            VALUES (:admin_id, :action, :target_type, :target_id, :old_value, :new_value, :ip, :ua)";
    
    $pdo->prepare($sql)->execute([
        ':admin_id' => $adminId,
        ':action' => $action,
        ':target_type' => $targetType,
        ':target_id' => $targetId,
        ':old_value' => $oldValue,
        ':new_value' => $newValue,
        ':ip' => $_SERVER['REMOTE_ADDR'],
        ':ua' => substr($_SERVER['HTTP_USER_AGENT'], 0, 255)
    ]);
}

/**
 * 비밀번호 강도 검증
 */
function validatePasswordStrength($password) {
    $errors = [];
    
    if (strlen($password) < PASSWORD_MIN_LENGTH) {
        $errors[] = "비밀번호는 최소 " . PASSWORD_MIN_LENGTH . "자 이상이어야 합니다.";
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "대문자를 포함해야 합니다.";
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "소문자를 포함해야 합니다.";
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "숫자를 포함해야 합니다.";
    }
    if (!preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
        $errors[] = "특수문자를 포함해야 합니다.";
    }
    
    return $errors;
}

/**
 * 세션 유효성 검사
 */
function isLoggedIn() {
    secureSessionStart();
    
    if (!isset($_SESSION['admin_id']) || !isset($_SESSION['created'])) {
        return false;
    }
    
    // last_activity가 없으면 초기화
    if (!isset($_SESSION['last_activity'])) {
        $_SESSION['last_activity'] = time();
    }
    
    // 세션 타임아웃 체크
    if (time() - $_SESSION['last_activity'] > SESSION_LIFETIME) {
        session_destroy();
        return false;
    }
    
    $_SESSION['last_activity'] = time();
    return true;
}

/**
 * 로그인 필수 체크
 */
function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit;
    }
}

/**
 * 현재 관리자 정보 가져오기
 */
function getCurrentAdmin() {
    if (!isLoggedIn()) {
        return null;
    }
    
    $pdo = pdo();
    $stmt = $pdo->prepare("SELECT * FROM admins WHERE id = :id AND is_active = 1");
    $stmt->execute([':id' => $_SESSION['admin_id']]);
    return $stmt->fetch();
}

/**
 * 랜덤 문자열 생성
 */
function generateRandomString($length = 32) {
    return bin2hex(openssl_random_pseudo_bytes($length / 2));
}