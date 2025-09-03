<?php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/lib.php';

$admin = getCurrentAdmin();
if (!$admin) { echo json_encode(['ok'=>false,'err'=>'관리자 정보를 가져올 수 없습니다.']); exit; }
$uid = $admin['id'];
$uname = $admin['name'];

$comment = isset($_POST['comment']) ? trim((string)$_POST['comment']) : '대시보드에서 일괄 해제';

// entries: [{ ip, target_type, target_value }]
$entriesRaw = isset($_POST['entries']) ? $_POST['entries'] : '';
$ipsRaw = isset($_POST['ips']) ? $_POST['ips'] : '';

$entries = [];
if ($entriesRaw) {
    if (is_array($entriesRaw)) $entries = $entriesRaw; else {
        $decoded = json_decode((string)$entriesRaw, true);
        if (is_array($decoded)) $entries = $decoded;
    }
}
if (empty($entries) && $ipsRaw) {
    $ips = is_array($ipsRaw) ? $ipsRaw : array_filter(array_map('trim', explode(',', (string)$ipsRaw)), 'strlen');
    foreach ($ips as $ip) {
        $entries[] = ['ip' => $ip, 'target_type' => 'all', 'target_value' => ''];
    }
}

if (empty($entries)) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'no entries']); exit; }

$clean = [];
foreach ($entries as $e) {
    $ip = isset($e['ip']) ? trim((string)$e['ip']) : '';
    $tt = isset($e['target_type']) ? trim((string)$e['target_type']) : 'all';
    $tv = isset($e['target_value']) ? trim((string)$e['target_value']) : '';
    if (!validIp($ip)) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'invalid ip: '.$ip]); exit; }
    if ($tt === 'server' || $tt === 'group') {
        if ($tv === '' || !validateScopeName($tv)) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'invalid target_value for '.$tt]); exit; }
    } else { $tt = 'all'; $tv = ''; }
    $clean[] = ['ip'=>$ip,'target_type'=>$tt,'target_value'=>$tv];
}

$ok = true; $err = null; $affected = 0;
try {
    $r = redisClient();
    foreach ($clean as $e) {
        $ip = $e['ip'];
        if ($e['target_type']==='server') {
            $r->srem('fw:black_ips:server:'.$e['target_value'], [$ip]);
            $msg = "unban_ip {$ip} @server={$e['target_value']}";
        } elseif ($e['target_type']==='group') {
            $r->srem('fw:black_ips:group:'.$e['target_value'], [$ip]);
            $msg = "unban_ip {$ip} @group={$e['target_value']}";
        } else {
            $r->srem('fw:black_ips', [$ip]);
            $msg = "unban_ip {$ip}";
        }
        $r->publish(REDIS_CH, $msg);
        $affected++;
        logFirewall([
            'action'=>'unban_ip',
            'ip'=>$ip,
            'comment'=>$comment,
            'target_server'=>$e['target_type']==='server'?$e['target_value']:'',
            'target_group'=>$e['target_type']==='group'?$e['target_value']:'',
            'uid'=>$uid,
            'uname'=>$uname,
            'status'=>'OK',
        ]);
    }
} catch (Exception $e) { $ok=false; $err=$e->getMessage(); }

echo json_encode(['ok'=>$ok,'err'=>$err,'affected'=>$affected]);

