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
            (action,target_ip,target_port,comment,actor_user_id,actor_name,actor_ip,user_agent,status,error_msg)
            VALUES (:action,:target_ip,:target_port,:comment,:actor_user_id,:actor_name,:actor_ip,:user_agent,:status,:error_msg)";
    pdo()->prepare($sql)->execute([
        ':action' => $data['action'],
        ':target_ip' => isset($data['ip']) ? $data['ip'] : null,
        ':target_port' => isset($data['port']) ? $data['port'] : null,
        ':comment' => isset($data['comment']) ? $data['comment'] : null,
        ':actor_user_id' => isset($data['uid']) ? (int)$data['uid'] : null,
        ':actor_name' => isset($data['uname']) ? $data['uname'] : null,
        ':actor_ip' => actorIp(),
        ':user_agent' => userAgent(),
        ':status' => $data['status'],
        ':error_msg' => isset($data['error']) ? substr($data['error'], 0, 250) : null,
    ]);
}
