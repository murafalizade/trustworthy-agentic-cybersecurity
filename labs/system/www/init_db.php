<?php
$dbFile = __DIR__ . '/data/users.db';
if (file_exists($dbFile)) {
    exit(0);
}

$pdo = new PDO('sqlite:' . $dbFile);
$pdo->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)');
$seed = $pdo->prepare('INSERT INTO users (username, password) VALUES (:u, :p)');
foreach ([
    ['admin', 'admin123'],
    ['alice', 'summer2024'],
] as [$u, $p]) {
    $seed->execute(['u' => $u, 'p' => $p]);
}
