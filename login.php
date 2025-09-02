<?php
require_once __DIR__ . '/security.php';

secureSessionStart();

// 이미 로그인된 경우 대시보드로 리다이렉트
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$blocked = false;
$blockedUntil = '';

// 로그인 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    $csrfToken = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '';
    
    // CSRF 토큰 검증
    if (!verifyCSRFToken($csrfToken)) {
        $error = '보안 토큰이 유효하지 않습니다.';
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        
        // 브루트포스 체크
        $bruteForce = checkBruteForce($ip, $username);
        if ($bruteForce['blocked']) {
            $blocked = true;
            $blockedUntil = $bruteForce['until'];
            $error = '너무 많은 로그인 시도로 차단되었습니다. ' . date('H:i', strtotime($blockedUntil)) . '까지 기다려주세요.';
            logLogin(null, $username, $ip, $userAgent, 'BLOCKED', 'Brute force protection');
        } else {
            // 사용자 확인
            $pdo = pdo();
            $stmt = $pdo->prepare("SELECT * FROM admins WHERE username = :username AND is_active = 1");
            $stmt->execute([':username' => $username]);
            $admin = $stmt->fetch();
            
            if ($admin && password_verify($password, $admin['password'])) {
                // IP 허용 체크
                if (!isIPAllowed($admin['allowed_ips'], $ip)) {
                    $error = '현재 IP에서 접근이 허용되지 않습니다.';
                    logLogin($admin['id'], $username, $ip, $userAgent, 'FAILED', 'IP not allowed');
                    recordLoginAttempt($ip, $username, false);
                } else {
                    // 로그인 성공
                    $_SESSION['admin_id'] = $admin['id'];
                    $_SESSION['username'] = $admin['username'];
                    $_SESSION['name'] = $admin['name'];
                    $_SESSION['last_activity'] = time();
                    
                    // 로그인 기록
                    $sessionId = session_id();
                    logLogin($admin['id'], $username, $ip, $userAgent, 'SUCCESS', null, $sessionId);
                    recordLoginAttempt($ip, $username, true);
                    
                    // 마지막 로그인 시간 업데이트
                    $updateSql = "UPDATE admins SET last_login = NOW() WHERE id = :id";
                    $pdo->prepare($updateSql)->execute([':id' => $admin['id']]);
                    
                    // 감사 로그
                    auditLog($admin['id'], 'LOGIN', 'admin', $admin['id']);
                    
                    // 대시보드로 리다이렉트
                    header('Location: dashboard.php');
                    exit;
                }
            } else {
                $error = '아이디 또는 비밀번호가 잘못되었습니다.';
                logLogin(null, $username, $ip, $userAgent, 'FAILED', 'Invalid credentials');
                recordLoginAttempt($ip, $username, false);
            }
        }
    }
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPTables 관리 시스템 - 로그인</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 400px;
            padding: 40px;
            animation: slideUp 0.5s ease;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 40px;
        }
        
        .login-header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .login-header p {
            color: #666;
            font-size: 14px;
        }
        
        .security-badge {
            display: inline-flex;
            align-items: center;
            background: #f0f9ff;
            color: #0369a1;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 12px;
            margin-top: 10px;
        }
        
        .security-badge svg {
            width: 16px;
            height: 16px;
            margin-right: 5px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            color: #4a5568;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s;
        }
        
        .form-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .form-input.error {
            border-color: #f56565;
        }
        
        .error-message {
            background: #fff5f5;
            border: 1px solid #feb2b2;
            color: #c53030;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            display: flex;
            align-items: center;
        }
        
        .error-message svg {
            width: 20px;
            height: 20px;
            margin-right: 8px;
            flex-shrink: 0;
        }
        
        .btn-login {
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 14px;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .btn-login:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }
        
        .btn-login:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .security-info {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            text-align: center;
        }
        
        .security-info p {
            color: #718096;
            font-size: 12px;
            line-height: 1.5;
        }
        
        .ip-info {
            margin-top: 10px;
            padding: 8px;
            background: #f7fafc;
            border-radius: 6px;
            font-family: monospace;
            font-size: 11px;
            color: #4a5568;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🔐 IPTables 관리 시스템</h1>
            <p>보안 관리자 인증</p>
            <div class="security-badge">
                <svg fill="currentColor" viewBox="0 0 20 20">
                    <path d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"/>
                </svg>
                보안 연결
            </div>
        </div>
        
        <?php if ($error): ?>
        <div class="error-message" role="alert" aria-live="assertive">
            <svg fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
            </svg>
            <?php echo htmlspecialchars($error); ?>
        </div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
            
            <div class="form-group">
                <label class="form-label" for="username">사용자명</label>
                <input 
                    type="text" 
                    id="username" 
                    name="username" 
                    class="form-input <?php echo $error ? 'error' : ''; ?>"
                    required 
                    autocomplete="username"
                    placeholder="관리자 아이디"
                    <?php echo $blocked ? 'disabled' : 'autofocus'; ?>
                    value="<?php echo isset($username) ? htmlspecialchars($username) : '' ?>"
                >
            </div>
            
            <div class="form-group">
                <label class="form-label" for="password">비밀번호</label>
                <div style="position: relative;">
                    <input 
                        type="password" 
                        id="password" 
                        name="password" 
                        class="form-input <?php echo $error ? 'error' : ''; ?>"
                        required 
                        autocomplete="current-password"
                        <?php echo $blocked ? 'disabled' : ''; ?>
                        placeholder="비밀번호"
                        aria-describedby="password-hint"
                    >
                    <button type="button" id="toggle-password" aria-label="비밀번호 표시" style="position:absolute; right:10px; top:50%; transform:translateY(-50%); background:transparent; border:none; color:#667eea; font-weight:600; cursor:pointer;">
                        보기
                    </button>
                </div>
                <div id="password-hint" style="margin-top:8px; font-size:12px; color:#718096;"></div>
            </div>
            
            <button type="submit" class="btn-login" <?php echo $blocked ? 'disabled' : ''; ?>>
                로그인
            </button>
        </form>
        
        <div class="security-info">
            <p>
                이 시스템은 승인된 관리자만 접근 가능합니다.<br>
                모든 접속 시도는 기록되며 모니터링됩니다.
            </p>
            <div class="ip-info">
                접속 IP: <?php echo htmlspecialchars($_SERVER['REMOTE_ADDR']); ?>
            </div>
        </div>
    </div>
<script>
// 비밀번호 보기/숨기기 토글 및 Caps Lock 안내
(function() {
  const pwdInput = document.getElementById('password');
  const toggleBtn = document.getElementById('toggle-password');
  const hint = document.getElementById('password-hint');
  if (!pwdInput || !toggleBtn) return;

  let isVisible = false;
  toggleBtn.addEventListener('click', function () {
    isVisible = !isVisible;
    pwdInput.type = isVisible ? 'text' : 'password';
    toggleBtn.textContent = isVisible ? '숨기기' : '보기';
    toggleBtn.setAttribute('aria-label', isVisible ? '비밀번호 숨기기' : '비밀번호 표시');
  });

  function updateCapsLock(e) {
    try {
      const on = e.getModifierState && e.getModifierState('CapsLock');
      if (on) {
        hint.textContent = 'Caps Lock이 켜져 있습니다.';
        hint.style.color = '#c53030';
      } else {
        hint.textContent = '';
        hint.style.color = '#718096';
      }
    } catch (_) {}
  }

  pwdInput.addEventListener('keyup', updateCapsLock);
  pwdInput.addEventListener('keydown', updateCapsLock);
})();
</script>
</body>
</html>