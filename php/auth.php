<?php
// auth.php
require_once 'config.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method not allowed', 'status_code' => 405]);
    exit;
}

$mode = $_POST['mode'] ?? '';
$username = trim($_POST['username'] ?? '');
$password = $_POST['password'] ?? '';
$email = trim($_POST['email'] ?? '');

if (empty($mode)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'mode is required', 'status_code' => 400]);
    exit;
}

if (empty($username) || empty($password)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Username and password are required', 'status_code' => 400]);
    exit;
}

if ($mode === 'signup') {
    if (empty($email)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Email is required for signup', 'status_code' => 400]);
        exit;
    }

    $signupData = [
        'uid' => $username,
        'pword' => $password,
        'email' => $email,
        'name' => $username,
    ];

    $result = callRustAPI('/signup', 'POST', $signupData);

    if ($result['success']) {
        echo json_encode([
            'status' => 'success',
            'message' => 'Account created successfully! Please log in.',
            'redirect' => 'login',
            'status_code' => $result['status'],
        ]);
        exit;
    }

    http_response_code($result['status'] ?: 500);
    echo json_encode([
        'status' => 'error',
        'message' => $result['message'],
        'status_code' => $result['status'],
        'backend_data' => $result['data'],
        'backend_raw' => $result['raw'],
    ]);
    exit;
}

if ($mode === 'login') {
    $signinData = [
        'uid' => $username,
        'pword' => $password,
    ];

    $result = callRustAPI('/signin', 'POST', $signinData);

    if ($result['success'] && isset($result['data']['token']) && is_string($result['data']['token'])) {
        setJWTCookie($result['data']['token']);

        echo json_encode([
            'status' => 'success',
            'message' => 'Login successful!',
            'redirect' => 'dashboard.php',
            'status_code' => $result['status'],
        ]);
        exit;
    }

    http_response_code($result['status'] ?: 401);
    echo json_encode([
        'status' => 'error',
        'message' => $result['message'],
        'status_code' => $result['status'],
        'backend_data' => $result['data'],
        'backend_raw' => $result['raw'],
    ]);
    exit;
}

http_response_code(400);
echo json_encode(['status' => 'error', 'message' => 'Invalid authentication mode', 'status_code' => 400]);
