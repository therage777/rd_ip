<?php
require __DIR__ . '/config.php';
echo "len=" . strlen(REDIS_PASS) . "\n";
echo "hex=" . bin2hex(REDIS_PASS) . "\n";
