<?php
require_once __DIR__ . '/security.php';
requireLogin();

$admin = getCurrentAdmin();
$csrfToken = generateCSRFToken();

// 관리자 목록 가져오기
$pdo = pdo();
$admins = $pdo->query("SELECT * FROM admins ORDER BY created_at DESC")->fetchAll();

// 관리자 추가 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!verifyCSRFToken($_POST['csrf_token'])) {
        die('CSRF token mismatch');
    }
    
    $action = $_POST['action'];
    
    if ($action === 'add_admin') {
        $username = trim($_POST['username']);
        $password = $_POST['password'];
        $name = trim($_POST['name']);
        $email = trim($_POST['email']);
        $allowedIPs = isset($_POST['allowed_ips']) ? $_POST['allowed_ips'] : '';
        
        // 비밀번호 강도 검증
        $passwordErrors = validatePasswordStrength($password);
        if (!empty($passwordErrors)) {
            $error = implode(', ', $passwordErrors);
        } else {
            // IP 목록 파싱
            $ipArray = array_filter(array_map('trim', explode("\n", $allowedIPs)));
            $ipJson = json_encode($ipArray);
            
            // 관리자 추가
            $stmt = $pdo->prepare("
                INSERT INTO admins (username, password, name, email, allowed_ips, created_at)
                VALUES (:username, :password, :name, :email, :allowed_ips, NOW())
            ");
            
            $stmt->execute([
                ':username' => $username,
                ':password' => password_hash($password, PASSWORD_DEFAULT),
                ':name' => $name,
                ':email' => $email,
                ':allowed_ips' => $ipJson
            ]);
            
            auditLog($_SESSION['admin_id'], 'ADD_ADMIN', 'admin', $username);
            header('Location: admin_manage.php?success=1');
            exit;
        }
    } elseif ($action === 'toggle_admin') {
        $adminId = (int)$_POST['admin_id'];
        if ($adminId != $_SESSION['admin_id']) { // 자기 자신은 비활성화 못함
            $stmt = $pdo->prepare("UPDATE admins SET is_active = NOT is_active WHERE id = :id");
            $stmt->execute([':id' => $adminId]);
            
            auditLog($_SESSION['admin_id'], 'TOGGLE_ADMIN', 'admin', $adminId);
            header('Location: admin_manage.php');
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>관리자 관리 - IPTables 관리 시스템</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f7fafc;
            color: #2d3748;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .header-content {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-size: 24px;
            font-weight: 600;
        }
        
        .nav-links {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        
        .nav-link {
            color: white;
            text-decoration: none;
            opacity: 0.9;
            transition: opacity 0.3s;
        }
        
        .nav-link:hover {
            opacity: 1;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .card-header {
            background: #f7fafc;
            padding: 16px 20px;
            border-bottom: 1px solid #e2e8f0;
            border-radius: 12px 12px 0 0;
        }
        
        .card-title {
            font-size: 18px;
            font-weight: 600;
        }
        
        .card-body {
            padding: 20px;
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
        
        .form-input, .form-textarea {
            width: 100%;
            padding: 10px 14px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .form-textarea {
            resize: vertical;
            min-height: 100px;
            font-family: monospace;
        }
        
        .form-input:focus, .form-textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .form-hint {
            font-size: 12px;
            color: #718096;
            margin-top: 4px;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        }
        
        .btn-danger {
            background: #f56565;
            color: white;
        }
        
        .btn-success {
            background: #48bb78;
            color: white;
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 12px;
        }
        
        .admin-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .admin-table th {
            text-align: left;
            padding: 12px;
            background: #f7fafc;
            font-weight: 600;
            color: #4a5568;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .admin-table td {
            padding: 12px;
            border-bottom: 1px solid #f1f5f9;
        }
        
        .admin-table tr:hover {
            background: #f7fafc;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }
        
        .badge-active {
            background: #c6f6d5;
            color: #22543d;
        }
        
        .badge-inactive {
            background: #fed7d7;
            color: #742a2a;
        }
        
        .ip-list {
            font-family: monospace;
            font-size: 12px;
            color: #4a5568;
        }
        
        .alert {
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .alert-success {
            background: #c6f6d5;
            color: #22543d;
            border: 1px solid #9ae6b4;
        }
        
        .alert-error {
            background: #fed7d7;
            color: #742a2a;
            border: 1px solid #fc8181;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>👥 관리자 관리</h1>
            <div class="nav-links">
                <a href="dashboard.php" class="nav-link">대시보드</a>
                <a href="logout.php" class="nav-link">로그아웃</a>
            </div>
        </div>
    </div>
    
    <div class="container">
        <?php if (isset($_GET['success'])): ?>
        <div class="alert alert-success">
            관리자가 성공적으로 추가되었습니다.
        </div>
        <?php endif; ?>
        
        <?php if (isset($error)): ?>
        <div class="alert alert-error">
            <?php echo htmlspecialchars($error); ?>
        </div>
        <?php endif; ?>
        
        <!-- 새 관리자 추가 -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">새 관리자 추가</h3>
            </div>
            <div class="card-body">
                <form method="POST" action="">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <input type="hidden" name="action" value="add_admin">
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                        <div class="form-group">
                            <label class="form-label" for="username">사용자명 *</label>
                            <input type="text" id="username" name="username" class="form-input" required>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label" for="password">비밀번호 *</label>
                            <input type="password" id="password" name="password" class="form-input" required>
                            <div class="form-hint">최소 8자, 대소문자, 숫자, 특수문자 포함</div>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label" for="name">이름 *</label>
                            <input type="text" id="name" name="name" class="form-input" required>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label" for="email">이메일</label>
                            <input type="email" id="email" name="email" class="form-input">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label" for="allowed_ips">허용 IP 목록</label>
                        <textarea id="allowed_ips" name="allowed_ips" class="form-textarea" placeholder="192.168.1.100&#10;10.0.0.0/24&#10;*"></textarea>
                        <div class="form-hint">한 줄에 하나씩 입력. CIDR 표기법 지원. 비워두면 모든 IP 허용</div>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">관리자 추가</button>
                </form>
            </div>
        </div>
        
        <!-- 관리자 목록 -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">관리자 목록</h3>
            </div>
            <div class="card-body">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>사용자명</th>
                            <th>이름</th>
                            <th>이메일</th>
                            <th>허용 IP</th>
                            <th>마지막 로그인</th>
                            <th>상태</th>
                            <th>작업</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($admins as $adm): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($adm['username']); ?></td>
                            <td><?php echo htmlspecialchars($adm['name']); ?></td>
                            <td><?php echo htmlspecialchars($adm['email'] ?: '-'); ?></td>
                            <td>
                                <div class="ip-list">
                                    <?php 
                                    $ips = json_decode($adm['allowed_ips'], true);
                                    if (empty($ips)) {
                                        echo '모든 IP';
                                    } else {
                                        echo implode(', ', array_slice($ips, 0, 3));
                                        if (count($ips) > 3) echo ' ...';
                                    }
                                    ?>
                                </div>
                            </td>
                            <td>
                                <?php 
                                echo $adm['last_login'] ? date('Y-m-d H:i', strtotime($adm['last_login'])) : '-';
                                ?>
                            </td>
                            <td>
                                <?php if ($adm['is_active']): ?>
                                    <span class="badge badge-active">활성</span>
                                <?php else: ?>
                                    <span class="badge badge-inactive">비활성</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($adm['id'] != $_SESSION['admin_id']): ?>
                                <form method="POST" action="" style="display: inline;">
                                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                    <input type="hidden" name="action" value="toggle_admin">
                                    <input type="hidden" name="admin_id" value="<?php echo $adm['id']; ?>">
                                    <button type="submit" class="btn btn-sm <?php echo $adm['is_active'] ? 'btn-danger' : 'btn-success'; ?>">
                                        <?php echo $adm['is_active'] ? '비활성화' : '활성화'; ?>
                                    </button>
                                </form>
                                <?php else: ?>
                                <span style="color: #a0aec0; font-size: 12px;">현재 사용자</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>