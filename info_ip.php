<?php
header('Content-Type: text/plain; charset=utf-8');
echo 'REMOTE_ADDR: ' . (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '') . PHP_EOL;
echo 'CF-Connecting-IP: ' . (isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? $_SERVER['HTTP_CF_CONNECTING_IP'] : '') . PHP_EOL;
echo 'X-Forwarded-For: ' . (isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : '') . PHP_EOL;
