<?php
require __DIR__ . '/config.php';
require __DIR__ . '/vendor/autoload.php'; // Predis

function pdo()
{
    static $pdo;
    if (!$pdo) {
        $pdo = new PDO(DB_DSN, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    }
    return $pdo;
}

function redisClient()
{
    static $r;
    if (!$r) {
        $r = new Predis\Client(
            [
                'scheme'   => 'tcp',
                'host'     => REDIS_HOST,
                'port'     => REDIS_PORT,
                'database' => REDIS_DB,
            ],
            [
                'parameters' => [
                    'password' => REDIS_PASS, // ← 원문 비번 그대로
                    // 'username' => 'default', // Redis 6 ACL 사용 시
                ],
                'read_write_timeout' => 2,
                'timeout'            => 1.0,
                'exceptions'         => true,
            ]
        );
    }
    return $r;
}

function actorIp()
{
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'cli';
}
function userAgent()
{
    return isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 250) : 'cli';
}
function mustToken()
{
    if (php_sapi_name() === 'cli') return;
    $t = isset($_POST['token']) ? $_POST['token'] : (isset($_GET['token']) ? $_GET['token'] : '');
    if ($t !== API_TOKEN) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'err' => 'forbidden']);
        exit;
    }
}

function validIp($ip)
{
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}
function validPort($p)
{
    return is_numeric($p) && $p >= 1 && $p <= 65535;
}

function logFirewall($data)
{
    $sql = "INSERT INTO firewall_logs
            (action,target_ip,target_port,comment,target_server,target_servers,target_group,target_groups,actor_user_id,actor_name,actor_ip,user_agent,status,error_msg)
            VALUES (:action,:target_ip,:target_port,:comment,:target_server,:target_servers,:target_group,:target_groups,:actor_user_id,:actor_name,:actor_ip,:user_agent,:status,:error_msg)";
    pdo()->prepare($sql)->execute([
        ':action' => $data['action'],
        ':target_ip' => isset($data['ip']) ? $data['ip'] : null,
        ':target_port' => isset($data['port']) ? $data['port'] : null,
        ':comment' => isset($data['comment']) ? $data['comment'] : null,
        ':target_server' => isset($data['target_server']) ? $data['target_server'] : null,
        ':target_servers' => isset($data['target_servers']) ? $data['target_servers'] : null,
        ':target_group' => isset($data['target_group']) ? $data['target_group'] : null,
        ':target_groups' => isset($data['target_groups']) ? $data['target_groups'] : null,
        ':actor_user_id' => isset($data['uid']) ? (int)$data['uid'] : null,
        ':actor_name' => isset($data['uname']) ? $data['uname'] : null,
        ':actor_ip' => actorIp(),
        ':user_agent' => userAgent(),
        ':status' => $data['status'],
        ':error_msg' => isset($data['error']) ? substr($data['error'], 0, 250) : null,
    ]);
}

// ---- Scope validation helpers ----
// Allow only letters, digits, underscore, hyphen, dot. Limit length to 64.
function validateScopeName($name)
{
    if (!is_string($name)) return false;
    $name = trim($name);
    if ($name === '') return false;
    return preg_match('/^[A-Za-z0-9_.-]{1,64}$/', $name) === 1;
}

// Normalize comma-separated list: trim, deduplicate, validate all.
// Returns normalized CSV string or false on invalid.
function normalizeScopeCsv($csv)
{
    if (!is_string($csv) || trim($csv) === '') return '';
    $items = array_filter(array_map('trim', explode(',', $csv)), 'strlen');
    $items = array_values(array_unique($items));
    foreach ($items as $it) {
        if (!validateScopeName($it)) return false;
    }
    return implode(',', $items);
}
