<?php
header('Content-Type: application/json');
echo json_encode([
    'service'  => 'lab-target',
    'status'   => 'ok',
    'endpoint' => '/login.php?user=..&pass=..',
    'ua'       => $_SERVER['HTTP_USER_AGENT'] ?? null,
]);
