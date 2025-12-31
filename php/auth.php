<?php
// auth.php
require_once 'config.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method not allowed']);
    exit;
}

$mode = $_POST['mode'] ?? '';
$username = trim($_POST['username'] ?? '');
$password = $_POST['password'] ?? '';
$email = trim($_POST['email'] ?? '');

// Validate inputs
if (empty($username) || empty($password)) {
    echo json_encode([
        'status' => 'error',
        'message' => 'Username and password are required'
    ]);
    exit;
}

if ($mode === 'signup') {
    // Signup logic
    if (empty($email)) {
        echo json_encode([
            'status' => 'error',
            'message' => 'Email is required for signup'
        ]);
        exit;
    }

    // Extract name from username (or use email prefix as name)
    $name = $username;

    $signupData = [
        'uid' => $username,
        'pword' => $password,
        'email' => $email,
        'name' => $name
    ];

    $result = callRustAPI('/signup', 'POST', $signupData);

    if ($result['success']) {
        echo json_encode([
            'status' => 'success',
            'message' => 'Account created successfully! Please log in.',
            'redirect' => 'login'
        ]);
    } else {
        echo json_encode([
            'status' => 'error',
            'message' => $result['message']
        ]);
    }

} elseif ($mode === 'login') {
    // Login logic
    $signinData = [
        'uid' => $username,
        'pword' => $password
    ];

    $result = callRustAPI('/signin', 'POST', $signinData);

    if ($result['success'] && isset($result['data']['token'])) {
        $token = $result['data']['token'];

        // Store JWT in secure cookie
        setJWTCookie($token);

        echo json_encode([
            'status' => 'success',
            'message' => 'Login successful!',
            'redirect' => 'dashboard.php'
        ]);
    } else {
        // Handle specific error codes
        if ($result['status'] === 401) {
            echo json_encode([
                'status' => 'error',
                'message' => 'Incorrect username or password',
                'code' => 'UNAUTHORIZED'
            ]);
        } else if ($result['status'] === 500) {
            echo json_encode([
                'status' => 'error',
                'message' => 'An error occurred on the server. Please try again later.',
                'code' => 'SERVER_ERROR'
            ]);
        } else {
            echo json_encode([
                'status' => 'error',
                'message' => $result['message']
            ]);
        }
    }

} else {
    echo json_encode([
        'status' => 'error',
        'message' => 'Invalid authentication mode'
    ]);
}
?>
