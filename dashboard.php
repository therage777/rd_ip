<?php
require_once __DIR__ . '/security.php';
requireLogin();

$admin = getCurrentAdmin();
$csrfToken = generateCSRFToken();

// 현재 규칙 가져오기 (API 호출)
function getCurrentRules() {
    try {
        $r = redisClient();
        $rules = [
            'blocked_ips' => $r->smembers('fw:blacklist:ips'),
            'blocked_ports' => $r->smembers('fw:block:ports'),
            'blocked_ip_ports' => $r->smembers('fw:block:ipports'),
            'allowed_ip_ports' => $r->smembers('fw:allow:ipports')
        ];
        return $rules;
    } catch (Exception $e) {
        return [
            'blocked_ips' => [],
            'blocked_ports' => [],
            'blocked_ip_ports' => [],
            'allowed_ip_ports' => []
        ];
    }
}

$rules = getCurrentRules();

// 최근 로그 가져오기
$pdo = pdo();
$recentLogs = $pdo->query("
    SELECT * FROM firewall_logs 
    ORDER BY created_at DESC 
    LIMIT 10
")->fetchAll();

// 통계 가져오기
$stats = $pdo->query("
    SELECT 
        COUNT(*) as total_actions,
        SUM(CASE WHEN status = 'OK' THEN 1 ELSE 0 END) as success_count,
        SUM(CASE WHEN status = 'ERR' THEN 1 ELSE 0 END) as error_count,
        COUNT(DISTINCT actor_ip) as unique_ips
    FROM firewall_logs 
    WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
")->fetch();
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPTables 관리 대시보드</title>
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
        
        /* Header */
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
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .user-name {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .btn-logout {
            background: rgba(255,255,255,0.2);
            color: white;
            border: 1px solid rgba(255,255,255,0.3);
            padding: 8px 16px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .btn-logout:hover {
            background: rgba(255,255,255,0.3);
        }
        
        /* Container */
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .stat-label {
            font-size: 12px;
            color: #718096;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: 700;
            color: #2d3748;
        }
        
        .stat-value.success {
            color: #48bb78;
        }
        
        .stat-value.error {
            color: #f56565;
        }
        
        /* Main Grid */
        .main-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        @media (max-width: 1024px) {
            .main-grid {
                grid-template-columns: 1fr;
            }
        }
        
        /* Card */
        .card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .card-header {
            background: #f7fafc;
            padding: 16px 20px;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .card-title {
            font-size: 16px;
            font-weight: 600;
            color: #2d3748;
        }
        
        .card-body {
            padding: 20px;
        }
        
        /* Forms */
        .form-inline {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .form-input {
            flex: 1;
            padding: 10px 14px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 14px;
            transition: all 0.3s;
        }
        
        .form-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
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
        
        .btn-danger:hover {
            background: #e53e3e;
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 12px;
        }
        
        /* Lists */
        .rule-list {
            max-height: 300px;
            overflow-y: auto;
        }
        
        .rule-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            border-bottom: 1px solid #e2e8f0;
            transition: background 0.2s;
        }
        
        .rule-item:hover {
            background: #f7fafc;
        }
        
        .rule-item:last-child {
            border-bottom: none;
        }
        
        .rule-text {
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 14px;
            color: #4a5568;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-ip {
            background: #e6fffa;
            color: #234e52;
        }
        
        .badge-port {
            background: #fef5e7;
            color: #7d4e00;
        }
        
        .badge-combo {
            background: #f0e6ff;
            color: #44337a;
        }
        
        /* Activity Log */
        .log-table {
            width: 100%;
            font-size: 13px;
        }
        
        .log-table th {
            text-align: left;
            padding: 12px;
            background: #f7fafc;
            font-weight: 600;
            color: #4a5568;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .log-table td {
            padding: 12px;
            border-bottom: 1px solid #f1f5f9;
        }
        
        .log-table tr:hover {
            background: #f7fafc;
        }
        
        .status-ok {
            color: #48bb78;
            font-weight: 600;
        }
        
        .status-err {
            color: #f56565;
            font-weight: 600;
        }
        
        /* Loading */
        .loading {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            z-index: 9999;
            justify-content: center;
            align-items: center;
        }
        
        .loading.active {
            display: flex;
        }
        
        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid #fff;
            border-top-color: transparent;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* Alert */
        .alert {
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        
        .alert.show {
            display: block;
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
        
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #a0aec0;
        }
        
        .empty-state svg {
            width: 48px;
            height: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <div class="header-content">
            <h1>🔐 IPTables 관리 대시보드</h1>
            <div class="user-info">
                <span class="user-name">👤 <?php echo htmlspecialchars($admin['name']); ?></span>
                <a href="admin_manage.php" class="btn-logout" style="margin-right: 10px;">관리자 관리</a>
                <a href="logout.php" class="btn-logout">로그아웃</a>
            </div>
        </div>
    </div>
    
    <!-- Container -->
    <div class="container">
        <!-- Alert -->
        <div id="alert" class="alert"></div>
        
        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">🚫 차단된 IP</div>
                <div class="stat-value"><?php echo count($rules['blocked_ips']); ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">🔒 차단된 포트</div>
                <div class="stat-value"><?php echo count($rules['blocked_ports']); ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">❌ 차단된 IP:PORT</div>
                <div class="stat-value" style="color: #f56565;"><?php echo count($rules['blocked_ip_ports']); ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">✅ 허용된 IP:PORT</div>
                <div class="stat-value" style="color: #48bb78;"><?php echo count($rules['allowed_ip_ports']); ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">📊 24시간 작업</div>
                <div class="stat-value"><?php echo $stats['total_actions']; ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">✨ 성공률</div>
                <div class="stat-value success">
                    <?php echo $stats['total_actions'] > 0 ? round($stats['success_count'] / $stats['total_actions'] * 100) : 0; ?>%
                </div>
            </div>
        </div>
        
        <!-- IP:PORT 허용 관리 섹션 (화이트리스트) -->
        <div class="card" style="margin-bottom: 30px;">
            <div class="card-header">
                <h3 class="card-title">✅ IP:PORT 허용 관리 (화이트리스트)</h3>
                <span class="badge badge-combo" style="background: #c6f6d5; color: #22543d;"><?php echo count($rules['allowed_ip_ports']); ?>개</span>
            </div>
            <div class="card-body">
                <form class="form-inline" onsubmit="return allowIPPort(event)">
                    <input type="text" class="form-input" id="allow-ip-input" placeholder="IP 주소" pattern="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$" required>
                    <input type="number" class="form-input" id="allow-port-input" placeholder="포트" min="1" max="65535" required>
                    <input type="text" class="form-input" id="allow-comment-input" placeholder="메모 (선택)" style="flex: 2;">
                    <button type="submit" class="btn btn-primary" style="background: #48bb78;">허용 추가</button>
                </form>
                
                <div class="rule-list">
                    <?php if (empty($rules['allowed_ip_ports'])): ?>
                    <div class="empty-state">
                        <svg fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                        </svg>
                        <p>허용된 IP:PORT 조합이 없습니다</p>
                    </div>
                    <?php else: ?>
                        <?php foreach ($rules['allowed_ip_ports'] as $ipport): ?>
                        <?php 
                            $parts = explode(':', $ipport);
                            $ip = isset($parts[0]) ? $parts[0] : '';
                            $port = isset($parts[1]) ? $parts[1] : '';
                        ?>
                        <div class="rule-item" id="allow-<?php echo md5($ipport); ?>">
                            <span class="rule-text"><?php echo htmlspecialchars($ipport); ?></span>
                            <button class="btn btn-danger btn-sm" onclick="unallowIPPort('<?php echo htmlspecialchars($ip); ?>', '<?php echo htmlspecialchars($port); ?>')">허용 해제</button>
                        </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <!-- Main Grid -->
        <div class="main-grid">
            <!-- IP 차단 관리 -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">🚫 IP 차단 관리</h3>
                    <span class="badge badge-ip"><?php echo count($rules['blocked_ips']); ?>개</span>
                </div>
                <div class="card-body">
                    <form class="form-inline" onsubmit="return blockIP(event)">
                        <input type="text" class="form-input" id="ip-input" placeholder="예: 192.168.1.100" pattern="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$" required>
                        <input type="text" class="form-input" id="ip-comment-input" placeholder="메모 (선택)" style="flex: 1.5;">
                        <button type="submit" class="btn btn-primary">차단 추가</button>
                    </form>
                    
                    <div class="rule-list">
                        <?php if (empty($rules['blocked_ips'])): ?>
                        <div class="empty-state">
                            <svg fill="currentColor" viewBox="0 0 20 20">
                                <path d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z"/>
                            </svg>
                            <p>차단된 IP가 없습니다</p>
                        </div>
                        <?php else: ?>
                            <?php foreach ($rules['blocked_ips'] as $ip): ?>
                            <div class="rule-item" id="ip-<?php echo md5($ip); ?>">
                                <span class="rule-text"><?php echo htmlspecialchars($ip); ?></span>
                                <button class="btn btn-danger btn-sm" onclick="unblockIP('<?php echo htmlspecialchars($ip); ?>')">해제</button>
                            </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            
            <!-- 포트 차단 관리 -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">🔒 포트 차단 관리</h3>
                    <span class="badge badge-port"><?php echo count($rules['blocked_ports']); ?>개</span>
                </div>
                <div class="card-body">
                    <form class="form-inline" onsubmit="return blockPort(event)">
                        <input type="number" class="form-input" id="port-input" placeholder="예: 8080" min="1" max="65535" required>
                        <input type="text" class="form-input" id="port-comment-input" placeholder="메모 (선택)" style="flex: 1.5;">
                        <button type="submit" class="btn btn-primary">차단 추가</button>
                    </form>
                    
                    <div class="rule-list">
                        <?php if (empty($rules['blocked_ports'])): ?>
                        <div class="empty-state">
                            <svg fill="currentColor" viewBox="0 0 20 20">
                                <path d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z"/>
                            </svg>
                            <p>차단된 포트가 없습니다</p>
                        </div>
                        <?php else: ?>
                            <?php foreach ($rules['blocked_ports'] as $port): ?>
                            <div class="rule-item" id="port-<?php echo $port; ?>">
                                <span class="rule-text">포트 <?php echo htmlspecialchars($port); ?></span>
                                <button class="btn btn-danger btn-sm" onclick="unblockPort('<?php echo htmlspecialchars($port); ?>')">해제</button>
                            </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- IP:PORT 차단 관리 섹션 (블랙리스트) -->
        <div class="card" style="margin-bottom: 30px;">
            <div class="card-header">
                <h3 class="card-title">🔐 IP:PORT 차단 관리 (블랙리스트)</h3>
                <span class="badge badge-combo"><?php echo count($rules['blocked_ip_ports']); ?>개</span>
            </div>
            <div class="card-body">
                <form class="form-inline" onsubmit="return blockIPPort(event)">
                    <input type="text" class="form-input" id="ipport-ip-input" placeholder="IP 주소" pattern="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$" required>
                    <input type="number" class="form-input" id="ipport-port-input" placeholder="포트" min="1" max="65535" required>
                    <input type="text" class="form-input" id="ipport-comment-input" placeholder="메모 (선택)" style="flex: 2;">
                    <button type="submit" class="btn btn-primary">차단 추가</button>
                </form>
                
                <div class="rule-list">
                    <?php if (empty($rules['blocked_ip_ports'])): ?>
                    <div class="empty-state">
                        <svg fill="currentColor" viewBox="0 0 20 20">
                            <path d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z"/>
                        </svg>
                        <p>차단된 IP:PORT 조합이 없습니다</p>
                    </div>
                    <?php else: ?>
                        <?php foreach ($rules['blocked_ip_ports'] as $ipport): ?>
                        <?php 
                            $parts = explode(':', $ipport);
                            $ip = isset($parts[0]) ? $parts[0] : '';
                            $port = isset($parts[1]) ? $parts[1] : '';
                        ?>
                        <div class="rule-item" id="ipport-<?php echo md5($ipport); ?>">
                            <span class="rule-text"><?php echo htmlspecialchars($ipport); ?></span>
                            <button class="btn btn-danger btn-sm" onclick="unblockIPPort('<?php echo htmlspecialchars($ip); ?>', '<?php echo htmlspecialchars($port); ?>')">해제</button>
                        </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <!-- 최근 활동 로그 -->
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">📊 최근 활동 로그</h3>
            </div>
            <div class="card-body">
                <table class="log-table">
                    <thead>
                        <tr>
                            <th>시간</th>
                            <th>작업</th>
                            <th>대상</th>
                            <th>메모</th>
                            <th>수행자</th>
                            <th>IP</th>
                            <th>상태</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentLogs as $log): ?>
                        <tr>
                            <td><?php echo date('m-d H:i', strtotime($log['created_at'])); ?></td>
                            <td><?php echo htmlspecialchars($log['action']); ?></td>
                            <td>
                                <?php 
                                if ($log['target_ip']) echo htmlspecialchars($log['target_ip']);
                                if ($log['target_port']) echo ':' . htmlspecialchars($log['target_port']);
                                ?>
                            </td>
                            <td title="<?php echo htmlspecialchars($log['comment'] ?: ''); ?>">
                                <?php 
                                $comment = $log['comment'] ?: '-';
                                echo strlen($comment) > 20 
                                    ? htmlspecialchars(substr($comment, 0, 20)) . '...' 
                                    : htmlspecialchars($comment);
                                ?>
                            </td>
                            <td><?php echo htmlspecialchars($log['actor_name'] ?: '-'); ?></td>
                            <td><?php echo htmlspecialchars($log['actor_ip']); ?></td>
                            <td>
                                <span class="status-<?php echo strtolower($log['status']); ?>">
                                    <?php echo $log['status']; ?>
                                </span>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <!-- Loading -->
    <div id="loading" class="loading">
        <div class="spinner"></div>
    </div>
    
    <script>
        const API_TOKEN = '<?php echo API_TOKEN; ?>';
        const CSRF_TOKEN = '<?php echo $csrfToken; ?>';
        
        function showLoading() {
            document.getElementById('loading').classList.add('active');
        }
        
        function hideLoading() {
            document.getElementById('loading').classList.remove('active');
        }
        
        function showAlert(message, type = 'success') {
            const alert = document.getElementById('alert');
            alert.className = 'alert show alert-' + type;
            alert.textContent = message;
            
            setTimeout(() => {
                alert.classList.remove('show');
            }, 5000);
        }
        
        async function apiCall(endpoint, data) {
            showLoading();
            
            const formData = new FormData();
            formData.append('token', API_TOKEN);
            formData.append('csrf_token', CSRF_TOKEN);
            
            for (const key in data) {
                formData.append(key, data[key]);
            }
            
            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                hideLoading();
                
                if (result.ok) {
                    showAlert('작업이 성공적으로 완료되었습니다.');
                    setTimeout(() => location.reload(), 1000);
                } else {
                    showAlert('오류: ' + (result.err || '알 수 없는 오류'), 'error');
                }
                
                return result;
            } catch (error) {
                hideLoading();
                showAlert('네트워크 오류가 발생했습니다.', 'error');
                return { ok: false, err: error.message };
            }
        }
        
        function blockIP(event) {
            event.preventDefault();
            const ip = document.getElementById('ip-input').value;
            const comment = document.getElementById('ip-comment-input').value || '대시보드에서 추가';
            
            apiCall('api_add_ip.php', {
                ip: ip,
                comment: comment
            });
            
            return false;
        }
        
        function unblockIP(ip) {
            if (!confirm(`정말로 ${ip}의 차단을 해제하시겠습니까?`)) {
                return;
            }
            
            apiCall('api_del_ip.php', {
                ip: ip,
                comment: '대시보드에서 해제'
            });
        }
        
        function blockPort(event) {
            event.preventDefault();
            const port = document.getElementById('port-input').value;
            const comment = document.getElementById('port-comment-input').value || '대시보드에서 추가';
            
            apiCall('api_block_port.php', {
                port: port,
                comment: comment
            });
            
            return false;
        }
        
        function unblockPort(port) {
            if (!confirm(`정말로 포트 ${port}의 차단을 해제하시겠습니까?`)) {
                return;
            }
            
            apiCall('api_unblock_port.php', {
                port: port,
                comment: '대시보드에서 해제'
            });
        }
        
        function blockIPPort(event) {
            event.preventDefault();
            const ip = document.getElementById('ipport-ip-input').value;
            const port = document.getElementById('ipport-port-input').value;
            const comment = document.getElementById('ipport-comment-input').value || '대시보드에서 추가';
            
            apiCall('api_block_ipport.php', {
                ip: ip,
                port: port,
                comment: comment
            });
            
            return false;
        }
        
        function unblockIPPort(ip, port) {
            if (!confirm(`정말로 ${ip}:${port}의 차단을 해제하시겠습니까?`)) {
                return;
            }
            
            apiCall('api_unblock_ipport.php', {
                ip: ip,
                port: port,
                comment: '대시보드에서 해제'
            });
        }
        
        function allowIPPort(event) {
            event.preventDefault();
            const ip = document.getElementById('allow-ip-input').value;
            const port = document.getElementById('allow-port-input').value;
            const comment = document.getElementById('allow-comment-input').value || '대시보드에서 허용 추가';
            
            apiCall('api_allow_ipport.php', {
                ip: ip,
                port: port,
                comment: comment
            });
            
            return false;
        }
        
        function unallowIPPort(ip, port) {
            if (!confirm(`정말로 ${ip}:${port}의 허용을 해제하시겠습니까?`)) {
                return;
            }
            
            apiCall('api_unallow_ipport.php', {
                ip: ip,
                port: port,
                comment: '대시보드에서 허용 해제'
            });
        }
        
        // 자동 새로고침 (30초마다)
        setInterval(() => {
            location.reload();
        }, 30000);
    </script>
</body>
</html>