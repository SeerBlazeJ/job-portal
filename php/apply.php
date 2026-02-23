<?php
require_once 'config.php';
header('Content-Type: application/json');

if (!isAuthenticated()) {
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $result = callRustAPI('/apply', 'POST', $input, getJWTToken());

    if ($result['success']) {
         echo json_encode(['status' => 'success']);
    } else {
         echo json_encode(['status' => 'error', 'message' => 'Failed to submit application.']);
    }
}
?>
