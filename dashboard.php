<?php
require_once __DIR__ . '/security.php';
requireLogin();

$admin = getCurrentAdmin();
$csrfToken = generateCSRFToken();

// 현재 규칙 가져오기 (API 호출)
function getCurrentRules()
{
	try {
		$r = redisClient();
		
		// 기본 규칙 (전체 서버)
        $rules = [
            'blocked_ips' => [],
            'blocked_ports' => [],
            'allowed_ports' => [],
            'blocked_ip_ports' => [],
            'allowed_ip_ports' => []
        ];
		
        // 전체 서버 규칙
        $global_blocked_ips = $r->smembers('fw:black_ips') ?: [];
        $global_blocked_ports = $r->smembers('fw:block:ports') ?: [];
        $global_allowed_ports = $r->smembers('fw:allow:ports') ?: [];
		$global_blocked_ipports = $r->smembers('fw:block:ipports') ?: [];
		$global_allowed_ipports = $r->smembers('fw:allow:ipports') ?: [];
		
		// 규칙에 타겟 정보 추가
        foreach ($global_blocked_ips as $ip) {
            $rules['blocked_ips'][] = ['rule' => $ip, 'target' => 'all'];
        }
        foreach ($global_blocked_ports as $port) {
            $rules['blocked_ports'][] = ['rule' => $port, 'target' => 'all'];
        }
        foreach ($global_allowed_ports as $port) {
            $rules['allowed_ports'][] = ['rule' => $port, 'target' => 'all'];
        }
		foreach ($global_blocked_ipports as $ipport) {
			$rules['blocked_ip_ports'][] = ['rule' => $ipport, 'target' => 'all'];
		}
		foreach ($global_allowed_ipports as $ipport) {
			$rules['allowed_ip_ports'][] = ['rule' => $ipport, 'target' => 'all'];
		}
		
        // 서버별/그룹별 키 패턴 검색
        // fw:allow:ipports:server:* 와 fw:allow:ipports:group:* 패턴 검색
		try {
			$server_keys = $r->keys('fw:allow:ipports:server:*');
			if ($server_keys) {
				foreach ($server_keys as $key) {
					$server = str_replace('fw:allow:ipports:server:', '', $key);
					$ipports = $r->smembers($key);
					if ($ipports) {
						foreach ($ipports as $ipport) {
							$rules['allowed_ip_ports'][] = ['rule' => $ipport, 'target' => 'server', 'target_value' => $server];
						}
					}
				}
			}
		} catch (Exception $e) {
			// keys 명령어 실패시 무시
		}
		
		try {
			$group_keys = $r->keys('fw:allow:ipports:group:*');
			if ($group_keys) {
				foreach ($group_keys as $key) {
					$group = str_replace('fw:allow:ipports:group:', '', $key);
					$ipports = $r->smembers($key);
					if ($ipports) {
						foreach ($ipports as $ipport) {
							$rules['allowed_ip_ports'][] = ['rule' => $ipport, 'target' => 'group', 'target_value' => $group];
						}
					}
				}
			}
		} catch (Exception $e) {
			// keys 명령어 실패시 무시
		}
		
		// fw:block:ipports:server:* 와 fw:block:ipports:group:* 패턴 검색
		try {
			$server_keys = $r->keys('fw:block:ipports:server:*');
			if ($server_keys) {
				foreach ($server_keys as $key) {
					$server = str_replace('fw:block:ipports:server:', '', $key);
					$ipports = $r->smembers($key);
					if ($ipports) {
						foreach ($ipports as $ipport) {
							$rules['blocked_ip_ports'][] = ['rule' => $ipport, 'target' => 'server', 'target_value' => $server];
						}
					}
				}
			}
		} catch (Exception $e) {
			// keys 명령어 실패시 무시
		}
		
		try {
			$group_keys = $r->keys('fw:block:ipports:group:*');
			if ($group_keys) {
				foreach ($group_keys as $key) {
					$group = str_replace('fw:block:ipports:group:', '', $key);
					$ipports = $r->smembers($key);
					if ($ipports) {
						foreach ($ipports as $ipport) {
							$rules['blocked_ip_ports'][] = ['rule' => $ipport, 'target' => 'group', 'target_value' => $group];
						}
					}
				}
			}
		} catch (Exception $e) {
			// keys 명령어 실패시 무시
        }

        // fw:allow:ports:server:* / fw:allow:ports:group:* (포트 허용 스코프)
        try {
            $server_keys = $r->keys('fw:allow:ports:server:*');
            if ($server_keys) {
                foreach ($server_keys as $key) {
                    $server = str_replace('fw:allow:ports:server:', '', $key);
                    $ports = $r->smembers($key);
                    if ($ports) {
                        foreach ($ports as $p) {
                            $rules['allowed_ports'][] = ['rule' => $p, 'target' => 'server', 'target_value' => $server];
                        }
                    }
                }
            }
        } catch (Exception $e) { /* ignore */ }

        try {
            $group_keys = $r->keys('fw:allow:ports:group:*');
            if ($group_keys) {
                foreach ($group_keys as $key) {
                    $group = str_replace('fw:allow:ports:group:', '', $key);
                    $ports = $r->smembers($key);
                    if ($ports) {
                        foreach ($ports as $p) {
                            $rules['allowed_ports'][] = ['rule' => $p, 'target' => 'group', 'target_value' => $group];
                        }
                    }
                }
            }
        } catch (Exception $e) { /* ignore */ }

        // fw:black_ips:server:* / fw:black_ips:group:* (IP 차단 스코프)
        try {
            $server_keys = $r->keys('fw:black_ips:server:*');
            if ($server_keys) {
                foreach ($server_keys as $key) {
                    $server = str_replace('fw:black_ips:server:', '', $key);
                    $ips = $r->smembers($key);
                    if ($ips) {
                        foreach ($ips as $ip) {
                            $rules['blocked_ips'][] = ['rule' => $ip, 'target' => 'server', 'target_value' => $server];
                        }
                    }
                }
            }
        } catch (Exception $e) { /* ignore */ }

        try {
            $group_keys = $r->keys('fw:black_ips:group:*');
            if ($group_keys) {
                foreach ($group_keys as $key) {
                    $group = str_replace('fw:black_ips:group:', '', $key);
                    $ips = $r->smembers($key);
                    if ($ips) {
                        foreach ($ips as $ip) {
                            $rules['blocked_ips'][] = ['rule' => $ip, 'target' => 'group', 'target_value' => $group];
                        }
                    }
                }
            }
        } catch (Exception $e) { /* ignore */ }

        // fw:block:ports:server:* / fw:block:ports:group:* (포트 차단 스코프)
        try {
            $server_keys = $r->keys('fw:block:ports:server:*');
            if ($server_keys) {
                foreach ($server_keys as $key) {
                    $server = str_replace('fw:block:ports:server:', '', $key);
                    $ports = $r->smembers($key);
                    if ($ports) {
                        foreach ($ports as $p) {
                            $rules['blocked_ports'][] = ['rule' => $p, 'target' => 'server', 'target_value' => $server];
                        }
                    }
                }
            }
        } catch (Exception $e) { /* ignore */ }

        try {
            $group_keys = $r->keys('fw:block:ports:group:*');
            if ($group_keys) {
                foreach ($group_keys as $key) {
                    $group = str_replace('fw:block:ports:group:', '', $key);
                    $ports = $r->smembers($key);
                    if ($ports) {
                        foreach ($ports as $p) {
                            $rules['blocked_ports'][] = ['rule' => $p, 'target' => 'group', 'target_value' => $group];
                        }
                    }
                }
            }
        } catch (Exception $e) { /* ignore */ }

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

// 규칙별 최신 메모 및 타겟 정보 가져오기
function getRuleMetadata()
{
	$pdo = pdo();
	$metadata = [];

	// 가장 최근 메모와 타겟 정보를 가져오기 위한 쿼리
	$sql = "
        SELECT 
            CONCAT_WS(':', target_ip, target_port) as rule_key,
            action,
            comment,
            target_server,
            target_servers,
            target_group,
            target_groups,
            created_at
        FROM firewall_logs
        WHERE (target_ip IS NOT NULL OR target_port IS NOT NULL)
        ORDER BY created_at DESC
    ";

	$stmt = $pdo->query($sql);
	while ($row = $stmt->fetch()) {
		$key = $row['rule_key'];
		// 각 규칙에 대해 가장 최근 정보만 저장
		if (!isset($metadata[$key])) {
			$targetType = 'all';
			if (!empty($row['target_server'])) $targetType = 'server';
			elseif (!empty($row['target_servers'])) $targetType = 'servers';
			elseif (!empty($row['target_group'])) $targetType = 'group';
			elseif (!empty($row['target_groups'])) $targetType = 'groups';

			$metadata[$key] = [
				'comment' => $row['comment'] ?: '',
				'target_type' => $targetType,
				'target_value' => $row['target_server'] ?: $row['target_servers'] ?: $row['target_group'] ?: $row['target_groups'] ?: ''
			];
		}
	}

	return $metadata;
}

$rules = getCurrentRules();
$ruleMetadata = getRuleMetadata();

// 규칙 소유자 매핑 가져오기 (최근 생성자)
function getRuleOwners()
{
    $pdo = pdo();
    $owners = [
        'ipports' => [], // key: "IP:PORT" => ['id'=>int,'name'=>string]
        'ips' => [],     // key: "IP" => ['id'=>int,'name'=>string]
        'ports' => [],   // key: "<n>" or "<from>-<to>" => ['id'=>int,'name'=>string]
    ];

    // 1) IP:PORT 생성자
    $sql1 = "SELECT actor_user_id, actor_name, target_ip, target_port, action, created_at
             FROM firewall_logs
             WHERE target_ip IS NOT NULL AND target_port IS NOT NULL
               AND action IN ('allow_ipport','block_ipport')
             ORDER BY created_at DESC";
    try {
        foreach ($pdo->query($sql1) as $row) {
            $key = $row['target_ip'] . ':' . $row['target_port'];
            if (!isset($owners['ipports'][$key])) {
                $owners['ipports'][$key] = ['id' => (int)$row['actor_user_id'], 'name' => (string)$row['actor_name']];
            }
        }
    } catch (Exception $e) { /* ignore */ }

    // 2) IP 생성자 (ban_ip)
    $sql2 = "SELECT actor_user_id, actor_name, target_ip, action, created_at
             FROM firewall_logs
             WHERE target_ip IS NOT NULL AND action IN ('ban_ip')
             ORDER BY created_at DESC";
    try {
        foreach ($pdo->query($sql2) as $row) {
            $key = $row['target_ip'];
            if (!isset($owners['ips'][$key])) {
                $owners['ips'][$key] = ['id' => (int)$row['actor_user_id'], 'name' => (string)$row['actor_name']];
            }
        }
    } catch (Exception $e) { /* ignore */ }

    // 3) 포트 생성자 (단일/범위)
    // 우선 단일 포트
    $sql3a = "SELECT actor_user_id, actor_name, target_port, action, created_at
              FROM firewall_logs
              WHERE target_port IS NOT NULL AND action IN ('allow_port','block_port')
              ORDER BY created_at DESC";
    try {
        foreach ($pdo->query($sql3a) as $row) {
            $key = (string)((int)$row['target_port']);
            if (!isset($owners['ports'][$key])) {
                $owners['ports'][$key] = ['id' => (int)$row['actor_user_id'], 'name' => (string)$row['actor_name']];
            }
        }
    } catch (Exception $e) { /* ignore */ }

    // 범위 포트 (컬럼이 있을 때만)
    try {
        $hasRange = false;
        try {
            $chk = $pdo->query("SHOW COLUMNS FROM firewall_logs LIKE 'target_port_from'");
            $hasRange = (bool)$chk->fetch();
        } catch (Exception $ie) { $hasRange = false; }

        if ($hasRange) {
            $sql3b = "SELECT actor_user_id, actor_name, target_port_from, target_port_to, action, created_at
                      FROM firewall_logs
                      WHERE target_port_from IS NOT NULL AND target_port_to IS NOT NULL
                        AND action IN ('allow_port','block_port')
                      ORDER BY created_at DESC";
            foreach ($pdo->query($sql3b) as $row) {
                $key = ((int)$row['target_port_from']) . '-' . ((int)$row['target_port_to']);
                if (!isset($owners['ports'][$key])) {
                    $owners['ports'][$key] = ['id' => (int)$row['actor_user_id'], 'name' => (string)$row['actor_name']];
                }
            }
        }
    } catch (Exception $e) { /* ignore */ }

    return $owners;
}

$owners = getRuleOwners();

// 슈퍼관리자가 아니면 본인이 생성한 항목만 표시
if (!isSuperAdmin($admin)) {
    $uid = (int)$admin['id'];
    $filterByOwner = function($arr, $type) use ($owners, $uid) {
        $out = [];
        foreach ($arr as $item) {
            $rule = is_array($item) ? $item['rule'] : $item;
            $key = (string)$rule;
            if ($type === 'ips') {
                if (isset($owners['ips'][$key]) && $owners['ips'][$key]['id'] === $uid) $out[] = $item;
            } elseif ($type === 'ports') {
                if (isset($owners['ports'][$key]) && $owners['ports'][$key]['id'] === $uid) $out[] = $item;
            } elseif ($type === 'ipports') {
                if (isset($owners['ipports'][$key]) && $owners['ipports'][$key]['id'] === $uid) $out[] = $item;
            }
        }
        return $out;
    };

    $rules['blocked_ips'] = $filterByOwner($rules['blocked_ips'], 'ips');
    $rules['allowed_ports'] = $filterByOwner($rules['allowed_ports'], 'ports');
    $rules['blocked_ports'] = $filterByOwner($rules['blocked_ports'], 'ports');
    $rules['allowed_ip_ports'] = $filterByOwner($rules['allowed_ip_ports'], 'ipports');
    $rules['blocked_ip_ports'] = $filterByOwner($rules['blocked_ip_ports'], 'ipports');
}

// 최근 로그 가져오기
$pdo = pdo();
if (isSuperAdmin($admin)) {
    $recentLogs = $pdo->query("
    SELECT * FROM firewall_logs 
    ORDER BY created_at DESC 
    LIMIT 10
    ")->fetchAll();
} else {
    $stmt = $pdo->prepare("
    SELECT * FROM firewall_logs 
    WHERE actor_user_id = :uid 
    ORDER BY created_at DESC 
    LIMIT 10
    ");
    $stmt->execute([':uid' => (int)$admin['id']]);
    $recentLogs = $stmt->fetchAll();
}

// 통계 가져오기
if (isSuperAdmin($admin)) {
    $stats = $pdo->query("
    SELECT 
        COUNT(*) as total_actions,
        SUM(CASE WHEN status = 'OK' THEN 1 ELSE 0 END) as success_count,
        SUM(CASE WHEN status = 'ERR' THEN 1 ELSE 0 END) as error_count,
        COUNT(DISTINCT actor_ip) as unique_ips
    FROM firewall_logs 
    WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    ")->fetch();
} else {
    $stmt = $pdo->prepare("
    SELECT 
        COUNT(*) as total_actions,
        SUM(CASE WHEN status = 'OK' THEN 1 ELSE 0 END) as success_count,
        SUM(CASE WHEN status = 'ERR' THEN 1 ELSE 0 END) as error_count,
        COUNT(DISTINCT actor_ip) as unique_ips
    FROM firewall_logs 
    WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
      AND actor_user_id = :uid
    ");
    $stmt->execute([':uid' => (int)$admin['id']]);
    $stats = $stmt->fetch();
}
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
			box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
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
			background: rgba(255, 255, 255, 0.2);
			color: white;
			border: 1px solid rgba(255, 255, 255, 0.3);
			padding: 8px 16px;
			border-radius: 6px;
			text-decoration: none;
			font-size: 14px;
			transition: all 0.3s;
		}

		.btn-logout:hover {
			background: rgba(255, 255, 255, 0.3);
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
			box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
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
			box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
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

        /* List tools (search + pagination) */
        .list-tools { display:flex; gap:12px; align-items:center; margin:8px 0 12px 0; }
        .list-tools .pager { display:flex; gap:8px; align-items:center; }
        .btn-secondary { background:#edf2f7; color:#2d3748; border:1px solid #e2e8f0; }
        .btn-secondary:hover { background:#e2e8f0; }

        /* Hide misplaced static empty placeholders; JS will manage dynamic message */
        .empty-state[id^="empty-"] { display: none !important; }

		/* Clickable rows when checkboxes exist */
		.rule-item.has-checkbox { cursor: pointer; }
		.rule-item.has-checkbox button,
		.rule-item.has-checkbox a,
		.rule-item.has-checkbox input { cursor: auto; }

		.rule-text {
			font-family: 'Monaco', 'Courier New', monospace;
			font-size: 14px;
			color: #4a5568;
		}

		.rule-memo {
			display: block;
			font-size: 12px;
			color: #718096;
			margin-top: 4px;
			font-style: italic;
		}

		.filter-section {
			background: #f7fafc;
			padding: 12px;
			border-radius: 8px;
			margin-bottom: 15px;
		}

		.filter-checkboxes {
			display: flex;
			gap: 15px;
			flex-wrap: wrap;
			align-items: center;
		}

		.filter-checkbox {
			display: flex;
			align-items: center;
			gap: 5px;
		}

		.filter-checkbox input[type="checkbox"] {
			cursor: pointer;
		}

		.filter-checkbox label {
			cursor: pointer;
			font-size: 14px;
			color: #4a5568;
		}

		.target-select-inline {
			display: inline-block;
			margin-right: 10px;
			padding: 10px 14px;
			border: 2px solid #e2e8f0;
			border-radius: 8px;
			font-size: 14px;
			background: white;
			cursor: pointer;
			transition: all 0.3s;
		}

		.target-select-inline:focus {
			outline: none;
			border-color: #667eea;
			box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
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
			background: rgba(0, 0, 0, 0.5);
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
			to {
				transform: rotate(360deg);
			}
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

		<!-- Server/Group Target Selection -->
		<div class="card" style="margin-bottom: 20px;">
			<div class="card-header">
				<h3 class="card-title">🎯 타겟 서버/그룹 선택</h3>
				<span class="badge badge-ip">선택적 적용</span>
			</div>
			<div class="card-body">
				<div style="display: grid; grid-template-columns: 1fr 2fr 1fr; gap: 20px;">
					<div>
						<label style="display: block; margin-bottom: 8px; font-weight: 600; color: #4a5568;">적용 대상</label>
						<select id="target-type" class="form-input" onchange="updateTargetOptions()">
							<option value="all">전체 서버 (기본)</option>
							<option value="server">특정 서버</option>
							<option value="servers">여러 서버</option>
							<option value="group">서버 그룹</option>
							<option value="groups">여러 그룹</option>
						</select>
					</div>
					<div>
                            <div id="target-server-container" style="display: none;">
                                <label style="display: block; margin-bottom: 8px; font-weight: 600; color: #4a5568;">서버 ID</label>
                                <input type="text" id="target-server" class="form-input" placeholder="예: web01" oninput="updateTargetDisplay()" list="known-servers" />
                                <datalist id="known-servers"></datalist>
                                <div style="display:flex; gap:8px; align-items:center; margin-top:8px;">
                                    <input type="text" id="new-server-id" class="form-input" placeholder="서버 추가 (ID)" style="flex:1;">
                                    <button type="button" class="btn btn-primary btn-sm" onclick="addServer()">서버 추가</button>
                                </div>
                                <div id="server-tags" style="margin-top:8px; display:flex; gap:6px; flex-wrap:wrap;"></div>
                            </div>
						<div id="target-servers-container" style="display: none;">
							<label style="display: block; margin-bottom: 8px; font-weight: 600; color: #4a5568;">서버 ID 목록 (쉼표 구분)</label>
							<input type="text" id="target-servers" class="form-input" placeholder="예: web01,web02,db01" oninput="updateTargetDisplay()" />
						</div>
						<div id="target-group-container" style="display: none;">
							<label style="display: block; margin-bottom: 8px; font-weight: 600; color: #4a5568;">그룹 이름</label>
							<input type="text" id="target-group" class="form-input" placeholder="예: seoul" oninput="updateTargetDisplay()" />
						</div>
						<div id="target-groups-container" style="display: none;">
							<label style="display: block; margin-bottom: 8px; font-weight: 600; color: #4a5568;">그룹 이름 목록 (쉼표 구분)</label>
							<input type="text" id="target-groups" class="form-input" placeholder="예: seoul,edge" oninput="updateTargetDisplay()" />
						</div>
					</div>
					<div>
						<label style="display: block; margin-bottom: 8px; font-weight: 600; color: #4a5568;">현재 선택</label>
						<div id="target-display" style="padding: 10px; background: #f7fafc; border-radius: 8px; border: 2px solid #e2e8f0; font-family: monospace; font-size: 14px; min-height: 40px; display: flex; align-items: center;">전체 서버</div>
					</div>
				</div>
				<div style="margin-top: 15px; padding: 12px; background: #e6fffa; border-radius: 8px; border: 1px solid #81e6d9;">
					<p style="margin: 0; color: #234e52; font-size: 13px;">
						<strong>💡 참고:</strong> 타겟을 지정하지 않으면 모든 서버에 적용됩니다.
						각 서버의 SERVER_ID와 SERVER_GROUPS는 환경변수 또는 /etc/redis-fw-agent.conf에서 설정됩니다.
					</p>
				</div>
			</div>
		</div>

		<!-- Stats -->
		<div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">🚫 차단된 IP</div>
                <div class="stat-value" id="stat-blocked-ips"><?php echo count($rules['blocked_ips']); ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">🔒 차단된 포트</div>
                <div class="stat-value" id="stat-blocked-ports"><?php echo count($rules['blocked_ports']); ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">❌ 차단된 IP:PORT</div>
                <div class="stat-value" id="stat-blocked-ipports" style="color: #f56565;">
                    <?php echo count($rules['blocked_ip_ports']); ?>
                </div>
            </div>
			<div class="stat-card">
                <div class="stat-label">✅ 허용된 IP:PORT</div>
                <div class="stat-value" id="stat-allowed-ipports" style="color: #48bb78;">
                    <?php echo count($rules['allowed_ip_ports']); ?>
                </div>
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
                    <span class="badge badge-combo" id="badge-allow-ipports" style="background: #c6f6d5; color: #22543d;"><?php echo count($rules['allowed_ip_ports']); ?>개</span>
                </div>
			<div class="card-body">
				<!-- 일괄 작업 툴바 -->
				<div style="display:flex; gap:10px; align-items:center; margin-bottom:12px;">
					<label style="display:flex; align-items:center; gap:6px; font-size:14px; color:#4a5568;">
						<input type="checkbox" id="allow-ipport-select-all" onclick="toggleSelectAll('allow-ipport', this.checked)"> 전체 선택
					</label>
					<button class="btn btn-danger btn-sm" onclick="bulkUnallowIPPorts()">선택 허용 해제</button>
				</div>
				<!-- 필터링 옵션 -->
				<div class="filter-section">
					<div class="filter-checkboxes">
						<span style="font-weight: 600; color: #4a5568; margin-right: 10px;">표시 대상:</span>
						<div class="filter-checkbox">
							<input type="checkbox" id="filter-all" value="all" checked onchange="filterRules(); saveFilterState()">
							<label for="filter-all">전체 서버</label>
						</div>
						<div class="filter-checkbox">
							<input type="checkbox" id="filter-server" value="server" checked onchange="filterRules(); saveFilterState()">
							<label for="filter-server">특정 서버</label>
						</div>
						<div class="filter-checkbox">
							<input type="checkbox" id="filter-servers" value="servers" checked onchange="filterRules(); saveFilterState()">
							<label for="filter-servers">여러 서버</label>
						</div>
						<div class="filter-checkbox">
							<input type="checkbox" id="filter-group" value="group" checked onchange="filterRules(); saveFilterState()">
							<label for="filter-group">서버 그룹</label>
						</div>
						<div class="filter-checkbox">
							<input type="checkbox" id="filter-groups" value="groups" checked onchange="filterRules(); saveFilterState()">
							<label for="filter-groups">여러 서버 그룹</label>
						</div>
					</div>
				</div>

				<form class="form-inline" onsubmit="return allowIPPort(event)">
					<select class="target-select-inline" id="allow-target-type">
						<option value="all">전체 서버</option>
						<option value="server">특정 서버</option>
						<option value="servers">여러 서버</option>
						<option value="group">서버 그룹</option>
						<option value="groups">여러 서버 그룹</option>
					</select>
					<input type="text" class="form-input" id="allow-ip-input" placeholder="IP 주소 (여러 개는 , 로 구분)" required>
					<input type="text" class="form-input" id="allow-port-input" placeholder="포트 (여러 개는 , 로 구분)" required>
					<input type="text" class="form-input" id="allow-comment-input" placeholder="메모 (선택)" style="flex: 2;">
					<button type="submit" class="btn btn-primary" style="background: #48bb78;">허용 추가</button>
				</form>

                <div class="list-tools">
                    <input type="text" class="form-input" id="search-allow-ipports" placeholder="검색 (IP, 포트, 서버ID, 메모)" oninput="setSearch('allow-ipports', this.value)">
                    <button class="btn btn-secondary btn-sm" onclick="resetSearch('allow-ipports')">검색 초기화</button>
                    <select class="form-input" style="width:auto;" id="perpage-allow-ipports" onchange="setPerPage('allow-ipports', this.value)">
                        <option value="10" selected>10개</option>
                        <option value="20">20개</option>
                        <option value="50">50개</option>
                    </select>
                    <div class="pager">
                        <button class="btn btn-secondary btn-sm" onclick="prevPage('allow-ipports')">이전</button>
                        <span id="page-allow-ipports">1 / 1</span>
                        <button class="btn btn-secondary btn-sm" onclick="nextPage('allow-ipports')">다음</button>
                    </div>
                    <span class="badge" id="selcount-allow-ipports">선택 0</span>
                </div>
                <div class="rule-list" id="list-allow-ipports">
					<?php if (empty($rules['allowed_ip_ports'])): ?>
						<div class="empty-state">
							<svg fill="currentColor" viewBox="0 0 20 20">
								<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
							</svg>
							<p>허용된 IP:PORT 조합이 없습니다</p>
						</div>
					<?php else: ?>
						<?php foreach ($rules['allowed_ip_ports'] as $rule_data): ?>
							<?php
							$ipport = is_array($rule_data) ? $rule_data['rule'] : $rule_data;
							$parts = explode(':', $ipport);
							$ip = isset($parts[0]) ? $parts[0] : '';
							$port = isset($parts[1]) ? $parts[1] : '';
							
							// 타겟 정보 추출 - 실제 규칙 데이터를 우선 사용
							if (is_array($rule_data)) {
								$targetType = isset($rule_data['target']) ? $rule_data['target'] : 'all';
								$targetValue = isset($rule_data['target_value']) ? $rule_data['target_value'] : '';
								
								// servers, groups 타입도 필터링을 위해 단수형으로 변환
								if ($targetType === 'servers') $targetType = 'server';
								if ($targetType === 'groups') $targetType = 'group';
							} else {
								$targetType = 'all';
								$targetValue = '';
							}
							
							// 메모는 규칙 타입에 관계없이 가져오기
							$comment = isset($ruleMetadata[$ipport]['comment']) ? $ruleMetadata[$ipport]['comment'] : '';
							
							// 표시용 텍스트 생성 및 메모 처리
							$displayText = $ipport;
							$displayMemo = '';
							
							if ($targetType === 'server' && $targetValue) {
								$displayText .= ' <span style="color: #667eea;">[@' . htmlspecialchars($targetValue) . ']</span>';
								$displayMemo = $comment; // 서버별 규칙은 메모 표시
							} elseif ($targetType === 'group' && $targetValue) {
								$displayText .= ' <span style="color: #48bb78;">[#' . htmlspecialchars($targetValue) . ']</span>';
								$displayMemo = $comment; // 그룹별 규칙은 메모 표시
							} else {
								// 전체 서버 규칙 - 메타데이터에서 SSH 관련 메모만 표시
								if ($comment && strpos(strtolower($comment), 'ssh') !== false) {
									$displayMemo = 'ssh';
								} else {
									$displayMemo = ''; // 타겟 정보가 포함된 메모는 표시하지 않음
								}
							}
							?>
							<div class="rule-item has-checkbox" id="allow-<?php echo md5($ipport); ?>" data-target-type="<?php echo htmlspecialchars($targetType); ?>" data-ip="<?php echo htmlspecialchars($ip); ?>" data-port="<?php echo htmlspecialchars($port); ?>" data-scope-type="<?php echo htmlspecialchars($targetType); ?>" data-scope-value="<?php echo htmlspecialchars($targetValue); ?>">
								<div style="margin-right:10px; display:flex; align-items:center;">
									<input type="checkbox" class="allow-ipport-checkbox">
								</div>
								<div style="flex: 1;">
									<span class="rule-text"><?php echo $displayText; ?></span>
                                    <?php if ($displayMemo): ?>
                                        <span class="rule-memo"><?php echo htmlspecialchars($displayMemo); ?><?php $__okey = $ip . ':' . $port; $__on = isset($owners['ipports'][$__okey]['name']) ? $owners['ipports'][$__okey]['name'] : ''; if ($__on) { echo ' · ' . htmlspecialchars($__on); } ?></span>
                                    <?php endif; ?>
								</div>
								<button class="btn btn-danger btn-sm" onclick="unallowIPPort('<?php echo htmlspecialchars($ip); ?>', '<?php echo htmlspecialchars($port); ?>', '<?php echo htmlspecialchars($targetType); ?>', '<?php echo htmlspecialchars($targetValue); ?>')">허용 해제</button>
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
                    <span class="badge badge-ip" id="badge-block-ips"><?php echo count($rules['blocked_ips']); ?>개</span>
                </div>
			<div class="card-body">
				<!-- 일괄 작업 툴바 (IP 차단) -->
				<div style="display:flex; gap:10px; align-items:center; margin-bottom:12px;">
					<label style="display:flex; align-items:center; gap:6px; font-size:14px; color:#4a5568;">
						<input type="checkbox" id="block-ip-select-all" onclick="toggleSelectAll('block-ip', this.checked)"> 전체 선택
					</label>
					<button class="btn btn-danger btn-sm" onclick="bulkUnbanIPs()">선택 차단 해제</button>
				</div>
					<form class="form-inline" onsubmit="return blockIP(event)">
						<select class="target-select-inline" id="ip-target-type">
							<option value="all">전체 서버</option>
							<option value="server">특정 서버</option>
							<option value="servers">여러 서버</option>
							<option value="group">서버 그룹</option>
							<option value="groups">여러 서버 그룹</option>
						</select>
						<input type="text" class="form-input" id="ip-input" placeholder="예: 192.168.1.100" pattern="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$" required>
						<input type="text" class="form-input" id="ip-comment-input" placeholder="메모 (선택)" style="flex: 1.5;">
						<button type="submit" class="btn btn-primary">차단 추가</button>
					</form>

                <div class="list-tools">
                    <input type="text" class="form-input" id="search-block-ips" placeholder="검색 (IP, 서버ID, 메모)" oninput="setSearch('block-ips', this.value)">
                    <button class="btn btn-secondary btn-sm" onclick="resetSearch('block-ips')">검색 초기화</button>
                    <select class="form-input" style="width:auto;" id="perpage-block-ips" onchange="setPerPage('block-ips', this.value)">
                        <option value="10" selected>10개</option>
                        <option value="20">20개</option>
                        <option value="50">50개</option>
                    </select>
                    <div class="pager">
                        <button class="btn btn-secondary btn-sm" onclick="prevPage('block-ips')">이전</button>
                        <span id="page-block-ips">1 / 1</span>
                        <button class="btn btn-secondary btn-sm" onclick="nextPage('block-ips')">다음</button>
                    </div>
                    <span class="badge" id="selcount-block-ips">선택 0</span>
                </div>
                <div class="rule-list" id="list-block-ips">
						<?php if (empty($rules['blocked_ips'])): ?>
							<div class="empty-state">
								<svg fill="currentColor" viewBox="0 0 20 20">
									<path d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" />
								</svg>
								<p>차단된 IP가 없습니다</p>
							</div>
						<?php else: ?>
                            <?php foreach ($rules['blocked_ips'] as $rule_data): ?>
                                <?php
                                $ip = is_array($rule_data) ? $rule_data['rule'] : $rule_data;
                                $comment = isset($ruleMetadata[$ip]['comment']) ? $ruleMetadata[$ip]['comment'] : '';
                                $targetType = 'all';
                                $targetValue = '';
                                if (is_array($rule_data)) {
                                    $targetType = isset($rule_data['target']) ? $rule_data['target'] : 'all';
                                    $targetValue = isset($rule_data['target_value']) ? $rule_data['target_value'] : '';
                                }

                                $displayText = htmlspecialchars($ip);
                                if ($targetType === 'server' && $targetValue) {
                                    $displayText .= ' <span style="color: #667eea;">[@' . htmlspecialchars($targetValue) . ']</span>';
                                } elseif ($targetType === 'group' && $targetValue) {
                                    $displayText .= ' <span style="color: #48bb78;">[#' . htmlspecialchars($targetValue) . ']</span>';
                                }
                                ?>
                                <div class="rule-item has-checkbox" id="ip-<?php echo md5($ip . '|' . $targetType . '|' . $targetValue); ?>" data-target-type="<?php echo htmlspecialchars($targetType); ?>" data-ip="<?php echo htmlspecialchars($ip); ?>" data-scope-type="<?php echo htmlspecialchars($targetType); ?>" data-scope-value="<?php echo htmlspecialchars($targetValue); ?>">
                                    <div style="margin-right:10px; display:flex; align-items:center;">
                                        <input type="checkbox" class="block-ip-checkbox">
                                    </div>
                                    <div style="flex: 1;">
                                        <span class="rule-text"><?php echo $displayText; ?></span>
                                        <?php if ($comment): ?>
                                            <span class="rule-memo"><?php echo htmlspecialchars($comment); ?><?php $__on = isset($owners['ips'][$ip]['name']) ? $owners['ips'][$ip]['name'] : ''; if ($__on) { echo ' · ' . htmlspecialchars($__on); } ?></span>
                                        <?php endif; ?>
                                    </div>
                                    <button class="btn btn-danger btn-sm" onclick="unblockIP('<?php echo htmlspecialchars($ip); ?>','<?php echo htmlspecialchars($targetType); ?>','<?php echo htmlspecialchars($targetValue); ?>')">해제</button>
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
                    <span class="badge badge-port" id="badge-block-ports"><?php echo count($rules['blocked_ports']); ?>개</span>
                </div>
				<div class="card-body">
					<!-- 일괄 작업 툴바 (포트 차단) -->
					<div style="display:flex; gap:10px; align-items:center; margin-bottom:12px;">
						<label style="display:flex; align-items:center; gap:6px; font-size:14px; color:#4a5568;">
							<input type="checkbox" id="block-port-select-all" onclick="toggleSelectAll('block-port', this.checked)"> 전체 선택
						</label>
						<button class="btn btn-danger btn-sm" onclick="bulkUnblockPorts()">선택 차단 해제</button>
					</div>
					<form class="form-inline" onsubmit="return blockPort(event)">
						<select class="target-select-inline" id="port-target-type">
							<option value="all">전체 서버</option>
							<option value="server">특정 서버</option>
							<option value="servers">여러 서버</option>
							<option value="group">서버 그룹</option>
							<option value="groups">여러 서버 그룹</option>
						</select>
						<input type="text" class="form-input" id="port-input" placeholder="예: 8080 또는 20000-30000" required>
						<input type="text" class="form-input" id="port-comment-input" placeholder="메모 (선택)" style="flex: 1.5;">
						<button type="submit" class="btn btn-primary">차단 추가</button>
					</form>

                <div class="list-tools">
                    <input type="text" class="form-input" id="search-block-ports" placeholder="검색 (포트, 서버ID, 메모)" oninput="setSearch('block-ports', this.value)">
                    <button class="btn btn-secondary btn-sm" onclick="resetSearch('block-ports')">검색 초기화</button>
                    <select class="form-input" style="width:auto;" id="perpage-block-ports" onchange="setPerPage('block-ports', this.value)">
                        <option value="10" selected>10개</option>
                        <option value="20">20개</option>
                        <option value="50">50개</option>
                    </select>
                    <div class="pager">
                        <button class="btn btn-secondary btn-sm" onclick="prevPage('block-ports')">이전</button>
                        <span id="page-block-ports">1 / 1</span>
                        <button class="btn btn-secondary btn-sm" onclick="nextPage('block-ports')">다음</button>
                    </div>
                    <span class="badge" id="selcount-block-ports">선택 0</span>
                </div>
                <div class="rule-list" id="list-block-ports">
						<?php if (empty($rules['blocked_ports'])): ?>
							<div class="empty-state">
								<svg fill="currentColor" viewBox="0 0 20 20">
									<path d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" />
								</svg>
								<p>차단된 포트가 없습니다</p>
							</div>
						<?php else: ?>
                            <?php foreach ($rules['blocked_ports'] as $rule_data): ?>
                                <?php
                                $port = is_array($rule_data) ? $rule_data['rule'] : $rule_data;
                                $portKey = ':' . $port;
                                $comment = isset($ruleMetadata[$portKey]['comment']) ? $ruleMetadata[$portKey]['comment'] : '';
                                $targetType = 'all';
                                $targetValue = '';
                                if (is_array($rule_data)) {
                                    $targetType = isset($rule_data['target']) ? $rule_data['target'] : 'all';
                                    $targetValue = isset($rule_data['target_value']) ? $rule_data['target_value'] : '';
                                }

                                $displayText = '포트 ' . htmlspecialchars($port);
                                if ($targetType === 'server' && $targetValue) {
                                    $displayText .= ' <span style="color: #667eea;">[@' . htmlspecialchars($targetValue) . ']</span>';
                                } elseif ($targetType === 'group' && $targetValue) {
                                    $displayText .= ' <span style="color: #48bb78;">[#' . htmlspecialchars($targetValue) . ']</span>';
                                }
                                ?>
                                <div class="rule-item has-checkbox" id="port-<?php echo htmlspecialchars($port) . '-' . md5($targetType . '|' . $targetValue); ?>" data-target-type="<?php echo htmlspecialchars($targetType); ?>" data-port="<?php echo htmlspecialchars($port); ?>" data-scope-type="<?php echo htmlspecialchars($targetType); ?>" data-scope-value="<?php echo htmlspecialchars($targetValue); ?>">
                                    <div style="margin-right:10px; display:flex; align-items:center;">
                                        <input type="checkbox" class="block-port-checkbox">
                                    </div>
                                    <div style="flex: 1;">
                                        <span class="rule-text"><?php echo $displayText; ?></span>
                                        <?php if ($comment): ?>
                                            <span class="rule-memo"><?php echo htmlspecialchars($comment); ?><?php $__on = isset($owners['ports'][$port]['name']) ? $owners['ports'][$port]['name'] : ''; if ($__on) { echo ' · ' . htmlspecialchars($__on); } ?></span>
                                        <?php endif; ?>
                                    </div>
                                    <button class="btn btn-danger btn-sm" onclick="unblockPort('<?php echo htmlspecialchars($port); ?>','<?php echo htmlspecialchars($targetType); ?>','<?php echo htmlspecialchars($targetValue); ?>')">해제</button>
                                </div>
                            <?php endforeach; ?>
						<?php endif; ?>
			</div>
		</div>

			<!-- 포트 허용 관리 -->
			<div class="card">
                <div class="card-header">
                    <h3 class="card-title">✅ 포트 허용 관리</h3>
                    <span class="badge badge-port" id="badge-allow-ports" style="background:#c6f6d5; color:#22543d;"><?php echo count($rules['allowed_ports']); ?>개</span>
                </div>
				<div class="card-body">
					<!-- 일괄 작업 툴바 (포트 허용) -->
					<div style="display:flex; gap:10px; align-items:center; margin-bottom:12px;">
						<label style="display:flex; align-items:center; gap:6px; font-size:14px; color:#4a5568;">
							<input type="checkbox" id="allow-port-select-all" onclick="toggleSelectAll('allow-port', this.checked)"> 전체 선택
						</label>
						<button class="btn btn-danger btn-sm" style="background:#e53e3e;" onclick="bulkUnallowPorts()">선택 허용 해제</button>
					</div>
					<form class="form-inline" onsubmit="return allowPort(event)">
						<select class="target-select-inline" id="allowport-target-type">
							<option value="all">전체 서버</option>
							<option value="server">특정 서버</option>
							<option value="servers">여러 서버</option>
							<option value="group">서버 그룹</option>
							<option value="groups">여러 서버 그룹</option>
						</select>
						<input type="text" class="form-input" id="allowport-input" placeholder="예: 8080 또는 20000-30000" required>
						<input type="text" class="form-input" id="allowport-comment-input" placeholder="메모 (선택)" style="flex: 1.5;">
						<button type="submit" class="btn btn-primary" style="background:#48bb78;">허용 추가</button>
					</form>

                <div class="list-tools">
                    <input type="text" class="form-input" id="search-allow-ports" placeholder="검색 (포트, 서버ID, 메모)" oninput="setSearch('allow-ports', this.value)">
                    <button class="btn btn-secondary btn-sm" onclick="resetSearch('allow-ports')">검색 초기화</button>
                    <select class="form-input" style="width:auto;" id="perpage-allow-ports" onchange="setPerPage('allow-ports', this.value)">
                        <option value="10" selected>10개</option>
                        <option value="20">20개</option>
                        <option value="50">50개</option>
                    </select>
                    <div class="pager">
                        <button class="btn btn-secondary btn-sm" onclick="prevPage('allow-ports')">이전</button>
                        <span id="page-allow-ports">1 / 1</span>
                        <button class="btn btn-secondary btn-sm" onclick="nextPage('allow-ports')">다음</button>
                    </div>
                    <span class="badge" id="selcount-allow-ports">선택 0</span>
                </div>
                <div class="rule-list" id="list-allow-ports">
						<?php if (empty($rules['allowed_ports'])): ?>
							<div class="empty-state">
								<svg fill="currentColor" viewBox="0 0 20 20">
									<path d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" />
								</svg>
								<p>허용된 포트가 없습니다</p>
							</div>
						<?php else: ?>
							<?php foreach ($rules['allowed_ports'] as $rule_data): ?>
								<?php
								$port = is_array($rule_data) ? $rule_data['rule'] : $rule_data;
								$portKey = ':' . $port;
								$comment = isset($ruleMetadata[$portKey]['comment']) ? $ruleMetadata[$portKey]['comment'] : '';
								$targetType = 'all';
								$targetValue = '';
								if (is_array($rule_data)) {
									$targetType = isset($rule_data['target']) ? $rule_data['target'] : 'all';
									$targetValue = isset($rule_data['target_value']) ? $rule_data['target_value'] : '';
								}
								$displayText = '포트 ' . htmlspecialchars($port);
								if ($targetType === 'server' && $targetValue) {
									$displayText .= ' <span style="color: #667eea;">[@' . htmlspecialchars($targetValue) . ']</span>';
								} elseif ($targetType === 'group' && $targetValue) {
									$displayText .= ' <span style="color: #48bb78;">[#' . htmlspecialchars($targetValue) . ']</span>';
								}
								?>
								<div class="rule-item has-checkbox" id="allowport-<?php echo htmlspecialchars($port) . '-' . md5($targetType . '|' . $targetValue); ?>" data-target-type="<?php echo htmlspecialchars($targetType); ?>" data-port="<?php echo htmlspecialchars($port); ?>" data-scope-type="<?php echo htmlspecialchars($targetType); ?>" data-scope-value="<?php echo htmlspecialchars($targetValue); ?>">
									<div style="margin-right:10px; display:flex; align-items:center;">
										<input type="checkbox" class="allow-port-checkbox">
									</div>
									<div style="flex: 1;">
										<span class="rule-text"><?php echo $displayText; ?></span>
                                    <?php if ($comment): ?>
                                        <span class="rule-memo"><?php echo htmlspecialchars($comment); ?><?php $__on = isset($owners['ports'][$port]['name']) ? $owners['ports'][$port]['name'] : ''; if ($__on) { echo ' · ' . htmlspecialchars($__on); } ?></span>
                                    <?php endif; ?>
									</div>
									<button class="btn btn-danger btn-sm" onclick="unallowPort('<?php echo htmlspecialchars($port); ?>','<?php echo htmlspecialchars($targetType); ?>','<?php echo htmlspecialchars($targetValue); ?>')">허용 해제</button>
								</div>
							<?php endforeach; ?>
						<?php endif; ?>
					</div>
				</div>
			</div>
		</div>
		</div>

		<!-- IP:PORT 차단 관리 섹션 (블랙리스트) -->
		<div class="card" style="margin-bottom: 30px;">
                <div class="card-header">
                    <h3 class="card-title">🔐 IP:PORT 차단 관리 (블랙리스트)</h3>
                    <span class="badge badge-combo" id="badge-block-ipports"><?php echo count($rules['blocked_ip_ports']); ?>개</span>
                </div>
			<div class="card-body">
				<!-- 일괄 작업 툴바 -->
				<div style="display:flex; gap:10px; align-items:center; margin-bottom:12px;">
					<label style="display:flex; align-items:center; gap:6px; font-size:14px; color:#4a5568;">
						<input type="checkbox" id="block-ipport-select-all" onclick="toggleSelectAll('block-ipport', this.checked)"> 전체 선택
					</label>
					<button class="btn btn-danger btn-sm" onclick="bulkUnblockIPPorts()">선택 차단 해제</button>
				</div>
				<form class="form-inline" onsubmit="return blockIPPort(event)">
					<select class="target-select-inline" id="block-target-type">
						<option value="all">전체 서버</option>
						<option value="server">특정 서버</option>
						<option value="servers">여러 서버</option>
						<option value="group">서버 그룹</option>
						<option value="groups">여러 서버 그룹</option>
					</select>
					<input type="text" class="form-input" id="ipport-ip-input" placeholder="IP 주소 (여러 개는 , 로 구분)" required>
					<input type="text" class="form-input" id="ipport-port-input" placeholder="포트 (여러 개는 , 로 구분)" required>
					<input type="text" class="form-input" id="ipport-comment-input" placeholder="메모 (선택)" style="flex: 2;">
					<button type="submit" class="btn btn-primary">차단 추가</button>
				</form>

                <div class="list-tools">
                    <input type="text" class="form-input" id="search-block-ipports" placeholder="검색 (IP, 포트, 서버ID, 메모)" oninput="setSearch('block-ipports', this.value)">
                    <button class="btn btn-secondary btn-sm" onclick="resetSearch('block-ipports')">검색 초기화</button>
                    <select class="form-input" style="width:auto;" id="perpage-block-ipports" onchange="setPerPage('block-ipports', this.value)">
                        <option value="10" selected>10개</option>
                        <option value="20">20개</option>
                        <option value="50">50개</option>
                    </select>
                    <div class="pager">
                        <button class="btn btn-secondary btn-sm" onclick="prevPage('block-ipports')">이전</button>
                        <span id="page-block-ipports">1 / 1</span>
                        <button class="btn btn-secondary btn-sm" onclick="nextPage('block-ipports')">다음</button>
                    </div>
                    <span class="badge" id="selcount-block-ipports">선택 0</span>
                </div>
                <div class="rule-list" id="list-block-ipports">
					<?php if (empty($rules['blocked_ip_ports'])): ?>
						<div class="empty-state">
							<svg fill="currentColor" viewBox="0 0 20 20">
								<path d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" />
							</svg>
							<p>차단된 IP:PORT 조합이 없습니다</p>
						</div>
					<?php else: ?>
						<?php foreach ($rules['blocked_ip_ports'] as $rule_data): ?>
							<?php
							$ipport = is_array($rule_data) ? $rule_data['rule'] : $rule_data;
							$parts = explode(':', $ipport);
							$ip = isset($parts[0]) ? $parts[0] : '';
							$port = isset($parts[1]) ? $parts[1] : '';
							
							// 타겟 정보 추출 - 실제 규칙 데이터를 우선 사용
							if (is_array($rule_data)) {
								$targetType = isset($rule_data['target']) ? $rule_data['target'] : 'all';
								$targetValue = isset($rule_data['target_value']) ? $rule_data['target_value'] : '';
								
								// servers, groups 타입도 필터링을 위해 단수형으로 변환
								if ($targetType === 'servers') $targetType = 'server';
								if ($targetType === 'groups') $targetType = 'group';
							} else {
								$targetType = 'all';
								$targetValue = '';
							}
							
							// 메모는 규칙 타입에 관계없이 가져오기
							$comment = isset($ruleMetadata[$ipport]['comment']) ? $ruleMetadata[$ipport]['comment'] : '';
							
							// 표시용 텍스트 생성 및 메모 처리
							$displayText = $ipport;
							$displayMemo = '';
							
							if ($targetType === 'server' && $targetValue) {
								$displayText .= ' <span style="color: #667eea;">[@' . htmlspecialchars($targetValue) . ']</span>';
								$displayMemo = $comment; // 서버별 규칙은 메모 표시
							} elseif ($targetType === 'group' && $targetValue) {
								$displayText .= ' <span style="color: #48bb78;">[#' . htmlspecialchars($targetValue) . ']</span>';
								$displayMemo = $comment; // 그룹별 규칙은 메모 표시
							} else {
								// 전체 서버 규칙 - 메타데이터에서 SSH 관련 메모만 표시
								if ($comment && strpos(strtolower($comment), 'ssh') !== false) {
									$displayMemo = 'ssh';
								} else {
									$displayMemo = ''; // 타겟 정보가 포함된 메모는 표시하지 않음
								}
							}
							?>
							<div class="rule-item has-checkbox" id="ipport-<?php echo md5($ipport); ?>" data-target-type="<?php echo htmlspecialchars($targetType); ?>" data-ip="<?php echo htmlspecialchars($ip); ?>" data-port="<?php echo htmlspecialchars($port); ?>" data-scope-type="<?php echo htmlspecialchars($targetType); ?>" data-scope-value="<?php echo htmlspecialchars($targetValue); ?>">
								<div style="margin-right:10px; display:flex; align-items:center;">
									<input type="checkbox" class="block-ipport-checkbox">
								</div>
								<div style="flex: 1;">
									<span class="rule-text"><?php echo $displayText; ?></span>
                                    <?php if ($displayMemo): ?>
                                        <span class="rule-memo"><?php echo htmlspecialchars($displayMemo); ?><?php $__okey = $ip . ':' . $port; $__on = isset($owners['ipports'][$__okey]['name']) ? $owners['ipports'][$__okey]['name'] : ''; if ($__on) { echo ' · ' . htmlspecialchars($__on); } ?></span>
                                    <?php endif; ?>
								</div>
								<button class="btn btn-danger btn-sm" onclick="unblockIPPort('<?php echo htmlspecialchars($ip); ?>', '<?php echo htmlspecialchars($port); ?>', '<?php echo htmlspecialchars($targetType); ?>', '<?php echo htmlspecialchars($targetValue); ?>')">해제</button>
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
                            $targetText = '';
                            if (!empty($log['target_ip'])) {
                                $targetText .= $log['target_ip'];
                            }
                            if (!empty($log['target_port'])) {
                                $targetText .= ':' . $log['target_port'];
                            } else {
                                // 포트 범위 작업의 경우 comment에 (range: x-y)가 들어가므로 이를 표시
                                if (!empty($log['comment']) && preg_match('/\(range:\s*([0-9]+\-[0-9]+)\)/', $log['comment'], $m)) {
                                    $targetText = $m[1];
                                }
                            }
                            echo htmlspecialchars($targetText);
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

		async function loadServers() {
			try {
				const res = await fetch('api_servers.php?action=list&token=' + encodeURIComponent(API_TOKEN), { credentials: 'same-origin' });
				const data = await res.json();
				if (!data.ok) return;
				const list = Array.isArray(data.servers) ? data.servers : [];
				renderServerList(list);
			} catch (e) { /* ignore */ }
		}

		function renderServerList(list) {
			const dl = document.getElementById('known-servers');
			if (dl) {
				dl.innerHTML = '';
				list.forEach(s => {
					const opt = document.createElement('option');
					opt.value = s;
					dl.appendChild(opt);
				});
			}
			const tags = document.getElementById('server-tags');
			if (tags) {
				tags.innerHTML = '';
				list.forEach(s => {
					const el = document.createElement('span');
					el.textContent = s;
					el.style.cssText = 'background:#edf2f7;color:#2d3748;padding:4px 8px;border-radius:6px;font-size:12px;';
					tags.appendChild(el);
				});
			}
		}

		async function addServer() {
			const inp = document.getElementById('new-server-id');
			if (!inp) return;
			const val = (inp.value || '').trim();
			if (!val) { alert('서버 ID를 입력하세요.'); return; }
			try {
				const body = new URLSearchParams();
				body.set('token', API_TOKEN);
				body.set('action', 'add');
				body.set('server_id', val);
				const res = await fetch('api_servers.php', { method: 'POST', body, credentials: 'same-origin' });
				const data = await res.json();
				if (data.ok) {
					inp.value = '';
					// merge new value into list and rerender
					const dl = document.getElementById('known-servers');
					const current = dl ? Array.from(dl.querySelectorAll('option')).map(o => o.value) : [];
					if (current.indexOf(val) === -1) current.push(val);
					current.sort();
					renderServerList(current);
					showAlert('서버가 추가되었습니다.', 'success');
				} else {
					showAlert(data.err || '추가 실패', 'error');
				}
			} catch (e) {
				showAlert('네트워크 오류', 'error');
			}
		}

		function updateTargetOptions() {
			const targetType = document.getElementById('target-type').value;
			const containers = [
				'target-server-container',
				'target-servers-container',
				'target-group-container',
				'target-groups-container'
			];

			// Hide all containers
			containers.forEach(id => {
				document.getElementById(id).style.display = 'none';
			});

			// Show relevant container
			switch (targetType) {
				case 'server':
					document.getElementById('target-server-container').style.display = 'block';
					break;
				case 'servers':
					document.getElementById('target-servers-container').style.display = 'block';
					break;
				case 'group':
					document.getElementById('target-group-container').style.display = 'block';
					break;
				case 'groups':
					document.getElementById('target-groups-container').style.display = 'block';
					break;
			}

			updateTargetDisplay();
		}

		function updateTargetDisplay() {
			const targetType = document.getElementById('target-type').value;
			const targetDisplay = document.getElementById('target-display');

			switch (targetType) {
				case 'all':
					targetDisplay.textContent = '전체 서버';
					break;
				case 'server':
					const server = document.getElementById('target-server').value.trim();
					targetDisplay.textContent = server ? `@server=${server}` : '서버 ID 입력 필요';
					break;
				case 'servers':
					const servers = document.getElementById('target-servers').value.trim();
					targetDisplay.textContent = servers ? `@servers=${servers}` : '서버 ID 목록 입력 필요';
					break;
				case 'group':
					const group = document.getElementById('target-group').value.trim();
					targetDisplay.textContent = group ? `@group=${group}` : '그룹 이름 입력 필요';
					break;
				case 'groups':
					const groups = document.getElementById('target-groups').value.trim();
					targetDisplay.textContent = groups ? `@groups=${groups}` : '그룹 이름 목록 입력 필요';
					break;
			}
		}

		function getTargetParams() {
			const targetType = document.getElementById('target-type').value;
			let targetParams = {};

			switch (targetType) {
				case 'server':
					const server = document.getElementById('target-server').value.trim();
					if (server) {
						targetParams.target_server = server;
					}
					break;
				case 'servers':
					const servers = document.getElementById('target-servers').value.trim();
					if (servers) {
						targetParams.target_servers = servers;
					}
					break;
				case 'group':
					const group = document.getElementById('target-group').value.trim();
					if (group) {
						targetParams.target_group = group;
					}
					break;
				case 'groups':
					const groups = document.getElementById('target-groups').value.trim();
					if (groups) {
						targetParams.target_groups = groups;
					}
					break;
			}

			return targetParams;
		}

		function filterRules() {
			const checkedTypes = [];

        // 필터 타입만 상태에 반영하고 목록 렌더링을 갱신
        document.querySelectorAll('.filter-checkbox input[type="checkbox"]:checked').forEach(checkbox => {
            checkedTypes.push(checkbox.value);
        });
        window.ALLOW_IPPORTS_FILTER = checkedTypes; // 전역 상태 저장
        refreshSection('allow-ipports');
        }

		// 필터 상태를 localStorage에 저장
		function saveFilterState() {
			const filterState = {};
			document.querySelectorAll('.filter-checkbox input[type="checkbox"]').forEach(checkbox => {
				filterState[checkbox.id] = checkbox.checked;
			});
			localStorage.setItem('rdip_filter_state', JSON.stringify(filterState));
		}

        // 저장된 필터 상태 복원
        function restoreFilterState() {
            const savedState = localStorage.getItem('rdip_filter_state');
            if (savedState) {
                try {
                    const filterState = JSON.parse(savedState);
                    for (const [id, checked] of Object.entries(filterState)) {
                        const checkbox = document.getElementById(id);
                        if (checkbox) {
                            checkbox.checked = checked;
                        }
                    }
                    // 복원 후 목록 갱신 (필터 반영)
                    filterRules();
                } catch (e) {
                    console.error('Failed to restore filter state:', e);
                }
            }
        }

		function addTargetParams(data, targetType) {
			// 추가 입력 필드가 필요한 경우 프롬프트 표시
			switch (targetType) {
				case 'server':
					const server = prompt('서버 ID를 입력하세요 (예: web01):', '');
					if (server) data.target_server = server;
					break;
				case 'servers':
					const servers = prompt('서버 ID 목록을 입력하세요 (쉼표 구분, 예: web01,web02):', '');
					if (servers) data.target_servers = servers;
					break;
				case 'group':
					const group = prompt('서버 그룹 이름을 입력하세요 (예: seoul):', '');
					if (group) data.target_group = group;
					break;
				case 'groups':
					const groups = prompt('서버 그룹 목록을 입력하세요 (쉼표 구분, 예: seoul,edge):', '');
					if (groups) data.target_groups = groups;
					break;
				case 'all':
				default:
					// 전체 서버의 경우 추가 파라미터 없음
					break;
			}
		}

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

    async function apiCall(endpoint, data, afterOk) {
        showLoading();

			const formData = new FormData();
			formData.append('token', API_TOKEN);
			formData.append('csrf_token', CSRF_TOKEN);

			// Add target parameters
			const targetParams = getTargetParams();
			for (const key in targetParams) {
				formData.append(key, targetParams[key]);
    }

        // pagination/search helpers moved to global scope below

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
                    if (typeof afterOk === 'function') {
                        try { afterOk(result); } catch(e) { console.error(e); }
                    } else {
                        // 기존 동작 유지: 단건 호출 등은 새로고침
                        setTimeout(() => location.reload(), 800);
                    }
                } else {
					showAlert('오류: ' + (result.err || '알 수 없는 오류'), 'error');
				}

				return result;
			} catch (error) {
				hideLoading();
				showAlert('네트워크 오류가 발생했습니다.', 'error');
				return {
					ok: false,
					err: error.message
				};
			}
		}

		function blockIP(event) {
			event.preventDefault();
			const ip = document.getElementById('ip-input').value;
			const comment = document.getElementById('ip-comment-input').value || '대시보드에서 추가';
			const targetType = document.getElementById('ip-target-type').value;

			const data = {
				ip: ip,
				comment: comment
			};

			// Add target params based on type
			addTargetParams(data, targetType);

			apiCall('api_add_ip.php', data);

			return false;
		}

        function unblockIP(ip, targetType = 'all', targetValue = '') {
            if (!confirm(`정말로 ${ip}${targetType==='server'&&targetValue?`[@${targetValue}]`:''}${targetType==='group'&&targetValue?`[#${targetValue}]`:''}의 차단을 해제하시겠습니까?`)) {
                return;
            }

            const data = { ip: ip, comment: '대시보드에서 해제' };
            if (targetType === 'server' && targetValue) data.target_server = targetValue;
            else if (targetType === 'group' && targetValue) data.target_group = targetValue;

            apiCall('api_del_ip.php', data);
        }

		function blockPort(event) {
			event.preventDefault();
			const port = document.getElementById('port-input').value;
			const comment = document.getElementById('port-comment-input').value || '대시보드에서 추가';
			const targetType = document.getElementById('port-target-type').value;

			const data = {
				port: port,
				comment: comment
			};

			// Add target params based on type
			addTargetParams(data, targetType);

			apiCall('api_block_port.php', data);

			return false;
		}

		function allowPort(event) {
			event.preventDefault();
			const port = document.getElementById('allowport-input').value;
			const comment = document.getElementById('allowport-comment-input').value || '대시보드에서 허용 추가';
			const targetType = document.getElementById('allowport-target-type').value;

			const data = { port: port, comment: comment };
			addTargetParams(data, targetType);
			apiCall('api_allow_port.php', data);

			return false;
		}

		function unallowPort(port, targetType = 'all', targetValue = '') {
			if (!confirm(`정말로 포트 ${port}${targetType==='server'&&targetValue?`[@${targetValue}]`:''}${targetType==='group'&&targetValue?`[#${targetValue}]`:''}의 허용을 해제하시겠습니까?`)) {
				return;
			}
			const data = { port: port, comment: '대시보드에서 허용 해제' };
			if (targetType === 'server' && targetValue) data.target_server = targetValue;
			else if (targetType === 'group' && targetValue) data.target_group = targetValue;
			apiCall('api_unallow_port.php', data);
		}

        function unblockPort(port, targetType = 'all', targetValue = '') {
            if (!confirm(`정말로 포트 ${port}${targetType==='server'&&targetValue?`[@${targetValue}]`:''}${targetType==='group'&&targetValue?`[#${targetValue}]`:''}의 차단을 해제하시겠습니까?`)) {
                return;
            }

            const data = { port: port, comment: '대시보드에서 해제' };
            if (targetType === 'server' && targetValue) data.target_server = targetValue;
            else if (targetType === 'group' && targetValue) data.target_group = targetValue;
            apiCall('api_unblock_port.php', data);
        }

		function blockIPPort(event) {
			event.preventDefault();
			const ip = document.getElementById('ipport-ip-input').value;
			const port = document.getElementById('ipport-port-input').value;
			const comment = document.getElementById('ipport-comment-input').value || '대시보드에서 추가';
			const targetType = document.getElementById('block-target-type').value;

			const data = {
				ip: ip,
				port: port,
				comment: comment
			};

			// Add target params based on type
			addTargetParams(data, targetType);

			apiCall('api_block_ipport.php', data);

			return false;
		}

		function unblockIPPort(ip, port, targetType, targetValue) {
			if (!confirm(`정말로 ${ip}:${port}의 차단을 해제하시겠습니까?`)) {
				return;
			}

			const data = {
				ip: ip,
				port: port,
				comment: '대시보드에서 해제'
			};
			
			// 타겟 정보 추가
			if (targetType === 'server' && targetValue) {
				data.target_server = targetValue;
			} else if (targetType === 'group' && targetValue) {
				data.target_group = targetValue;
			}
			
			apiCall('api_unblock_ipport.php', data);
		}

		function allowIPPort(event) {
			event.preventDefault();
			const ip = document.getElementById('allow-ip-input').value;
			const port = document.getElementById('allow-port-input').value;
			const comment = document.getElementById('allow-comment-input').value || '대시보드에서 허용 추가';
			const targetType = document.getElementById('allow-target-type').value;

			const data = {
				ip: ip,
				port: port,
				comment: comment
			};

			// Add target params based on type
			addTargetParams(data, targetType);

			apiCall('api_allow_ipport.php', data);

			return false;
		}

		function unallowIPPort(ip, port, targetType, targetValue) {
			if (!confirm(`정말로 ${ip}:${port}의 허용을 해제하시겠습니까?`)) {
				return;
			}

			const data = {
				ip: ip,
				port: port,
				comment: '대시보드에서 허용 해제'
			};
			
			// 타겟 정보 추가
			if (targetType === 'server' && targetValue) {
				data.target_server = targetValue;
			} else if (targetType === 'group' && targetValue) {
				data.target_group = targetValue;
			}
			
			apiCall('api_unallow_ipport.php', data);
		}

		// ---- 일괄 처리 유틸 ----
        function toggleSelectAll(kind, checked) {
            const section = normalizeSection(kind);
            const cls = checkboxSelector(section);
            if (!cls) return;
            document.querySelectorAll(cls).forEach(cb => {
                const item = cb.closest('.rule-item');
                if (!item) return;
                // Only affect visible items (pagination/search filtered)
                const visible = item.style.display !== 'none';
                if (visible) cb.checked = checked;
            });
            updateSelectionCount(section);
        }

        function collectSelectedEntries(kind) {
            const section = normalizeSection(kind);
            const selector = checkboxSelector(section) || '';
            const entries = [];
            if (!selector) return entries;
            document.querySelectorAll(selector + ':checked').forEach(cb => {
                const item = cb.closest('.rule-item');
                if (!item) return;
                const ttype = item.getAttribute('data-scope-type') || 'all';
                const tval = item.getAttribute('data-scope-value') || '';

                if (section === 'allow-ipports' || section === 'block-ipports') {
                    const ip = item.getAttribute('data-ip') || '';
                    const port = item.getAttribute('data-port') || '';
                    if (ip && port) entries.push({ ip, port, target_type: ttype, target_value: tval });
                } else if (section === 'block-ips') {
                    const ip = item.getAttribute('data-ip') || '';
                    if (ip) entries.push({ ip, target_type: ttype, target_value: tval });
                } else if (section === 'block-ports' || section === 'allow-ports') {
                    const port = item.getAttribute('data-port') || '';
                    if (port) entries.push({ port, target_type: ttype, target_value: tval });
                }
            });
            return entries;
        }

        function normalizeSection(kind) {
            // accept legacy kinds and return our SECTION_STATE key
            switch (kind) {
                case 'allow-ipport': return 'allow-ipports';
                case 'block-ipport': return 'block-ipports';
                default: return kind; // already section key
            }
        }

        function checkboxSelector(section) {
            const map = {
                'allow-ipports': '.allow-ipport-checkbox',
                'block-ipports': '.block-ipport-checkbox',
                'block-ips': '.block-ip-checkbox',
                'block-ports': '.block-port-checkbox',
                'allow-ports': '.allow-port-checkbox',
            };
            return map[section] || '';
        }

        function listIdFor(section) {
            const map = {
                'allow-ipports': 'list-allow-ipports',
                'block-ipports': 'list-block-ipports',
                'block-ips': 'list-block-ips',
                'block-ports': 'list-block-ports',
                'allow-ports': 'list-allow-ports',
            };
            return map[section] || '';
        }

        function sectionFromElement(el) {
            const list = el.closest('.rule-list');
            if (!list) return '';
            const id = list.id || '';
            if (id === 'list-allow-ipports') return 'allow-ipports';
            if (id === 'list-block-ipports') return 'block-ipports';
            if (id === 'list-block-ips') return 'block-ips';
            if (id === 'list-block-ports') return 'block-ports';
            if (id === 'list-allow-ports') return 'allow-ports';
            return '';
        }

        function updateSelectionCount(section) {
            const selId = 'selcount-' + section;
            const badge = document.getElementById(selId);
            if (!badge) return;
            const cls = checkboxSelector(section);
            const list = document.getElementById(listIdFor(section));
            if (!list || !cls) { badge.textContent = '선택 0'; return; }
            const n = list.querySelectorAll(cls + ':checked').length;
            badge.textContent = '선택 ' + n;
        }

        async function bulkUnallowIPPorts() {
            const section = 'allow-ipports';
            const entries = collectSelectedEntries(section);
            if (!entries.length) { alert('선택된 항목이 없습니다.'); return; }
            apiCall('api_unallow_ipports_bulk.php', { entries: JSON.stringify(entries), comment: '대시보드에서 일괄 허용 해제' }, () => {
                removeItemsForBulk(section, entries);
            });
        }

        async function bulkUnblockIPPorts() {
            const section = 'block-ipports';
            const entries = collectSelectedEntries(section);
            if (!entries.length) { alert('선택된 항목이 없습니다.'); return; }
            apiCall('api_unblock_ipports_bulk.php', { entries: JSON.stringify(entries), comment: '대시보드에서 일괄 차단 해제' }, () => {
                removeItemsForBulk(section, entries);
            });
        }

        function setupRowCheckboxToggle() {
            // Add click listener to rows that contain our bulk checkboxes
            document.querySelectorAll('.rule-item.has-checkbox').forEach(row => {
                row.addEventListener('click', function(e) {
                    // Ignore clicks on interactive controls
                    if (e.target.closest('button') || e.target.closest('a') || e.target.closest('input')) {
                        return;
                    }

                    const cb = row.querySelector('.allow-ipport-checkbox, .block-ipport-checkbox, .block-ip-checkbox, .block-port-checkbox, .allow-port-checkbox');
                    if (!cb) return;
                    cb.checked = !cb.checked;
                    const section = sectionFromElement(row);
                    if (section) updateSelectionCount(section);
                });
                // keyboard accessibility
                row.setAttribute('tabindex', '0');
                row.addEventListener('keydown', function(e){
                    if (e.key === ' ' || e.key === 'Enter') {
                        e.preventDefault();
                        const cb = row.querySelector('.allow-ipport-checkbox, .block-ipport-checkbox, .block-ip-checkbox, .block-port-checkbox, .allow-port-checkbox');
                        if (!cb) return;
                        cb.checked = !cb.checked;
                        const section = sectionFromElement(row);
                        if (section) updateSelectionCount(section);
                    }
                });
            });
            // direct checkbox changes (click on checkbox itself)
            document.addEventListener('change', function(e){
                const t = e.target;
                if (!(t instanceof HTMLInputElement)) return;
                if (!t.matches('.allow-ipport-checkbox, .block-ipport-checkbox, .block-ip-checkbox, .block-port-checkbox, .allow-port-checkbox')) return;
                const section = sectionFromElement(t);
                if (section) updateSelectionCount(section);
            });
        }

        async function bulkUnbanIPs() {
            const section = 'block-ips';
            const entries = collectSelectedEntries(section);
            if (!entries.length) { alert('선택된 항목이 없습니다.'); return; }
            apiCall('api_del_ips_bulk.php', { entries: JSON.stringify(entries), comment: '대시보드에서 일괄 차단 해제' }, () => {
                removeItemsForBulk(section, entries);
            });
        }

        async function bulkUnblockPorts() {
            const section = 'block-ports';
            const entries = collectSelectedEntries(section);
            if (!entries.length) { alert('선택된 항목이 없습니다.'); return; }
            apiCall('api_unblock_ports_bulk.php', { entries: JSON.stringify(entries), comment: '대시보드에서 일괄 차단 해제' }, () => {
                removeItemsForBulk(section, entries);
            });
        }

        async function bulkUnallowPorts() {
            const section = 'allow-ports';
            const entries = collectSelectedEntries(section);
            if (!entries.length) { alert('선택된 항목이 없습니다.'); return; }
            apiCall('api_unallow_ports_bulk.php', { entries: JSON.stringify(entries), comment: '대시보드에서 일괄 허용 해제' }, () => {
                removeItemsForBulk(section, entries);
            });
        }

        function removeItemsForBulk(section, entries) {
            const list = document.getElementById(listIdFor(section));
            if (!list) return;
            const cls = checkboxSelector(section);
            let removed = 0;
            entries.forEach(e => {
                // match by data attributes
                const selector = (section==='block-ips')
                    ? `.rule-item[data-ip="${e.ip}"]`
                    : (section==='block-ports' || section==='allow-ports')
                        ? `.rule-item[data-port="${e.port}"]`
                        : `.rule-item[data-ip="${e.ip}"][data-port="${e.port}"]`;
                const candidates = list.querySelectorAll(selector);
                candidates.forEach(item => {
                    // scope match (if provided)
                    const ttype = item.getAttribute('data-scope-type') || 'all';
                    const tval = item.getAttribute('data-scope-value') || '';
                    const mtype = e.target_type || 'all';
                    const mval = e.target_value || '';
                    if ((ttype===mtype) && (String(tval)===String(mval))) {
                        item.remove();
                        removed++;
                    }
                });
            });
            if (removed > 0) {
                adjustCounts(section, -removed);
                refreshSection(section);
                updateSelectionCount(section);
            }
        }

        function adjustCounts(section, delta) {
            function adjust(id) {
                const el = document.getElementById(id);
                if (!el) return;
                const m = String(el.textContent).match(/\d+/);
                const num = m ? parseInt(m[0],10) : 0;
                const next = Math.max(0, num + delta);
                if (el.id.startsWith('badge-')) el.textContent = next + '개'; else el.textContent = String(next);
            }
            switch (section) {
                case 'allow-ipports':
                    adjust('badge-allow-ipports');
                    adjust('stat-allowed-ipports');
                    break;
                case 'block-ipports':
                    adjust('badge-block-ipports');
                    adjust('stat-blocked-ipports');
                    break;
                case 'block-ips':
                    adjust('badge-block-ips');
                    adjust('stat-blocked-ips');
                    break;
                case 'block-ports':
                    adjust('badge-block-ports');
                    adjust('stat-blocked-ports');
                    break;
                case 'allow-ports':
                    adjust('badge-allow-ports');
                    break;
            }
        }

        // ---- Pagination + Search (global) ----
        const SECTION_STATE = {
            'allow-ipports': { page: 1, perPage: 10, search: '' },
            'block-ipports': { page: 1, perPage: 10, search: '' },
            'block-ips': { page: 1, perPage: 10, search: '' },
            'block-ports': { page: 1, perPage: 10, search: '' },
            'allow-ports': { page: 1, perPage: 10, search: '' },
        };

        function setSearch(section, q) {
            if (!SECTION_STATE[section]) return;
            const st = SECTION_STATE[section];
            st.search = (q || '').toLowerCase();
            st.page = 1;
            if (st._timer) clearTimeout(st._timer);
            st._timer = setTimeout(() => refreshSection(section), 200);
        }

        function setPerPage(section, n) {
            if (!SECTION_STATE[section]) return;
            const v = parseInt(n, 10);
            SECTION_STATE[section].perPage = (v === 20 || v === 50) ? v : 10;
            SECTION_STATE[section].page = 1;
            refreshSection(section);
            try { localStorage.setItem('rdip_perpage_'+section, String(SECTION_STATE[section].perPage)); } catch(e){}
        }

        function resetSearch(section) {
            const input = document.getElementById('search-'+section);
            if (input) input.value = '';
            setSearch(section, '');
        }

        function prevPage(section) {
            if (!SECTION_STATE[section]) return;
            SECTION_STATE[section].page = Math.max(1, SECTION_STATE[section].page - 1);
            refreshSection(section);
        }
        function nextPage(section) {
            if (!SECTION_STATE[section]) return;
            SECTION_STATE[section].page += 1; // clamp in refresh
            refreshSection(section);
        }

        function matchesSearch(item, q) {
            if (!q) return true;
            const text = (item.querySelector('.rule-text')?.textContent || '').toLowerCase();
            const memo = (item.querySelector('.rule-memo')?.textContent || '').toLowerCase();
            const ip = (item.getAttribute('data-ip') || '').toLowerCase();
            const port = (item.getAttribute('data-port') || '').toLowerCase();
            const scopeVal = (item.getAttribute('data-scope-value') || '').toLowerCase();
            return text.includes(q) || memo.includes(q) || ip.includes(q) || port.includes(q) || scopeVal.includes(q);
        }

        function allowedIpportsTypePass(item) {
            const selected = window.ALLOW_IPPORTS_FILTER || ['all','server','servers','group','groups'];
            const t = item.getAttribute('data-target-type') || 'all';
            return selected.includes(t);
        }

        function refreshSection(section) {
            const state = SECTION_STATE[section];
            if (!state) return;

            const listIdMap = {
                'allow-ipports': 'list-allow-ipports',
                'block-ipports': 'list-block-ipports',
                'block-ips': 'list-block-ips',
                'block-ports': 'list-block-ports',
                'allow-ports': 'list-allow-ports',
            };
            const pageLabelId = {
                'allow-ipports': 'page-allow-ipports',
                'block-ipports': 'page-block-ipports',
                'block-ips': 'page-block-ips',
                'block-ports': 'page-block-ports',
                'allow-ports': 'page-allow-ports',
            };

            const listEl = document.getElementById(listIdMap[section]);
            if (!listEl) return;

            const items = Array.from(listEl.querySelectorAll('.rule-item'));

            // If there are no rule items at all (server-side empty list),
            // do NOT show client-side "검색 결과 없음"; leave server message visible.
            if (items.length === 0) {
                const label = document.getElementById(pageLabelId[section]);
                if (label) label.textContent = `0 / 0`;
                // Hide any residual search-empty blocks if previously injected
                const residual = listEl.querySelectorAll('.search-empty');
                residual.forEach(es => { es.style.display = 'none'; });
                return;
            }

            // Compute filtered items
            const filtered = items.filter(it => {
                // type filter only for allow-ipports
                if (section === 'allow-ipports' && !allowedIpportsTypePass(it)) return false;
                return matchesSearch(it, state.search);
            });

            const totalPagesRaw = Math.ceil(filtered.length / state.perPage);
            const totalPages = Math.max(1, totalPagesRaw || 1);
            if (state.page > totalPages) state.page = totalPages;

            // First hide all rule-items; leave server-side empties alone
            items.forEach(it => { it.style.display = 'none'; });

            // Show only current page slice
            const start = (state.page - 1) * state.perPage;
            const end = start + state.perPage;
            filtered.slice(start, end).forEach(it => { it.style.display = 'flex'; });

            const label = document.getElementById(pageLabelId[section]);
            if (label) {
                if (filtered.length === 0) label.textContent = `0 / 0`;
                else label.textContent = `${state.page} / ${Math.ceil(filtered.length / state.perPage)}`;
            }

            // Dynamic "검색 결과 없음" inside listEl (ensure single instance visible state only when items exist)
            let dynEmpty = listEl.querySelector('.search-empty');
            if (!dynEmpty) {
                dynEmpty = document.createElement('div');
                dynEmpty.className = 'empty-state search-empty';
                dynEmpty.innerHTML = '<svg fill="currentColor" viewBox="0 0 20 20"><path d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" /></svg><p>검색 결과 없음</p>';
                dynEmpty.style.display = 'none';
                listEl.appendChild(dynEmpty);
            }
            // Hide any other search-empty nodes if present, then toggle current
            listEl.querySelectorAll('.search-empty').forEach(es => {
                es.style.display = (filtered.length === 0) ? 'block' : 'none';
            });
        }

        // 페이지 로드 시 초기화
        document.addEventListener('DOMContentLoaded', function() {
            restoreFilterState();
            setupRowCheckboxToggle();
            // 초기 렌더링
            try {
                // restore perPage from localStorage
                Object.keys(SECTION_STATE).forEach(sec => {
                    const saved = localStorage.getItem('rdip_perpage_'+sec);
                    if (saved) {
                        const v = parseInt(saved,10);
                        if (v===10||v===20||v===50) {
                            SECTION_STATE[sec].perPage = v;
                            const sel = document.getElementById('perpage-'+sec);
                            if (sel) sel.value = String(v);
                        }
                    }
                });
            } catch(e){}
            refreshSection('allow-ipports');
            refreshSection('block-ipports');
            refreshSection('block-ips');
            refreshSection('block-ports');
            refreshSection('allow-ports');
            // init selection counters
            updateSelectionCount('allow-ipports');
            updateSelectionCount('block-ipports');
            updateSelectionCount('block-ips');
            updateSelectionCount('block-ports');
            updateSelectionCount('allow-ports');
            // 서버 목록 로드
            loadServers();
        });

		// 자동 새로고침 (5분마다)
		setInterval(() => {
			location.reload();
		}, 180000);
	</script>
</body>

</html>
