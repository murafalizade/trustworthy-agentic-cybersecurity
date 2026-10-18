<?php
header('Content-Type: application/json');

$dbFile = __DIR__ . '/data/users.db';
$pdo = new PDO('sqlite:' . $dbFile);

$user = $_GET['user'] ?? '';
$pass = $_GET['pass'] ?? '';

// Intentionally vulnerable to SQL injection — this is a deliberately
// unsafe training endpoint for the attacker lab, not production code.
$query = "SELECT username FROM users WHERE username = '$user' AND password = '$pass'";

try {
    $stmt = $pdo->query($query);
    $row = $stmt ? $stmt->fetch(PDO::FETCH_ASSOC) : false;
    echo json_encode($row ? ['status' => 'success', 'user' => $row['username']] : ['status' => 'fail']);
} catch (Exception $e) {
    echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
}
