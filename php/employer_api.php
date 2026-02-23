<?php
require_once 'config.php';
header('Content-Type: application/json');

if (!isAuthenticated()) {
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit;
}

$action = $_GET['action'] ?? '';
$token = getJWTToken();

if ($action === 'my_jobs') {
    echo json_encode(callRustAPI('/my-jobs', 'GET', null, $token));
} elseif ($action === 'applicants' && !empty($_GET['job_id'])) {
    $job_id = $_GET['job_id'];
    echo json_encode(callRustAPI('/job-applicants/' . urlencode($job_id), 'GET', null, $token));
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid action']);
}
?>
