<?php
header('Content-Type: application/json; charset=utf-8');
require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/lib.php';

$admin = getCurrentAdmin();
if (!$admin) { echo json_encode(['ok'=>false,'err'=>'관리자 정보를 가져올 수 없습니다.']); exit; }
$uid = $admin['id'];
$uname = $admin['name'];

$comment = isset($_POST['comment']) ? trim((string)$_POST['comment']) : '대시보드에서 일괄 차단 해제';

// entries: [{ port, target_type, target_value }], port can be single or range string
$entriesRaw = isset($_POST['entries']) ? $_POST['entries'] : '';
$portsRaw = isset($_POST['ports']) ? $_POST['ports'] : '';

$entries = [];
if ($entriesRaw) {
    if (is_array($entriesRaw)) $entries = $entriesRaw; else {
        $decoded = json_decode((string)$entriesRaw, true);
        if (is_array($decoded)) $entries = $decoded;
    }
}
if (empty($entries) && $portsRaw) {
    $ports = is_array($portsRaw) ? $portsRaw : array_filter(array_map('trim', explode(',', (string)$portsRaw)), 'strlen');
    foreach ($ports as $p) $entries[] = ['port'=>$p,'target_type'=>'all','target_value'=>''];
}

if (empty($entries)) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'no entries']); exit; }

$clean = [];
foreach ($entries as $e) {
    $portRaw = isset($e['port']) ? trim((string)$e['port']) : '';
    $tt = isset($e['target_type']) ? trim((string)$e['target_type']) : 'all';
    $tv = isset($e['target_value']) ? trim((string)$e['target_value']) : '';
    if (!validPortOrRange($portRaw)) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'invalid port: '.$portRaw]); exit; }
    if ($tt==='server'||$tt==='group') { if ($tv===''||!validateScopeName($tv)) { http_response_code(400); echo json_encode(['ok'=>false,'err'=>'invalid target_value for '.$tt]); exit; } }
    else { $tt='all'; $tv=''; }
    $clean[] = ['port'=>$portRaw,'target_type'=>$tt,'target_value'=>$tv];
}

$ok=true; $err=null; $affected=0;
try {
    $r = redisClient();
    foreach ($clean as $e) {
        $portRaw = $e['port'];
        if ($e['target_type']==='server') {
            $r->srem('fw:block:ports:server:'.$e['target_value'], [$portRaw]);
            $msg = "unblock_port {$portRaw} @server={$e['target_value']}";
        } elseif ($e['target_type']==='group') {
            $r->srem('fw:block:ports:group:'.$e['target_value'], [$portRaw]);
            $msg = "unblock_port {$portRaw} @group={$e['target_value']}";
        } else {
            $r->srem('fw:block:ports', [$portRaw]);
            $msg = "unblock_port {$portRaw}";
        }
        $r->publish(REDIS_CH, $msg);
        $affected++;
        logFirewall([
            'action'=>'unblock_port',
            'port'=>ctype_digit($portRaw)?(int)$portRaw:null,
            'port_from'=>(strpos($portRaw,'-')!==false)?(int)explode('-', $portRaw, 2)[0]:null,
            'port_to'=>(strpos($portRaw,'-')!==false)?(int)explode('-', $portRaw, 2)[1]:null,
            'comment'=>ctype_digit($portRaw)?$comment:trim($comment===''?'':($comment.' '))."(range: {$portRaw})",
            'target_server'=>$e['target_type']==='server'?$e['target_value']:'',
            'target_group'=>$e['target_type']==='group'?$e['target_value']:'',
            'uid'=>$uid,
            'uname'=>$uname,
            'status'=>'OK',
        ]);
    }
} catch (Exception $e) { $ok=false; $err=$e->getMessage(); }

echo json_encode(['ok'=>$ok,'err'=>$err,'affected'=>$affected]);

