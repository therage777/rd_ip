<?php
// 비밀번호 해시 생성 스크립트
// PHP 5.6+ 호환

$password = 'Admin@2024!';
$hash = password_hash($password, PASSWORD_DEFAULT);

echo "비밀번호: " . $password . "\n";
echo "해시: " . $hash . "\n";
echo "\n";
echo "SQL 쿼리:\n";
echo "UPDATE admins SET password = '" . $hash . "' WHERE username = 'admin';\n";
echo "\n";
echo "또는 새로 삽입:\n";
echo "INSERT INTO admins (username, password, name, email, is_active) VALUES ('admin', '" . $hash . "', '시스템 관리자', 'admin@example.com', 1) ON DUPLICATE KEY UPDATE password = '" . $hash . "';\n";