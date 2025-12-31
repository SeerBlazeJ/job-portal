<?php
// config.php
session_start();

// Rust server configuration
define('RUST_API_URL', 'http://localhost:3000');
define('JWT_COOKIE_NAME', 'job_portal_token');
define('COOKIE_EXPIRY', 86400); // 24 hours (matching JWT expiration)

// Enable secure cookies in production
define('SECURE_COOKIE', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on');

// Helper function to make API calls to Rust server
function callRustAPI($endpoint, $method = 'GET', $data = null, $token = null) {
    $url = RUST_API_URL . $endpoint;

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);

    $headers = ['Content-Type: application/json'];

    if ($token) {
        $headers[] = 'Authorization: Bearer ' . $token;
    }

    if ($data && ($method === 'POST' || $method === 'PUT')) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    }

    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
        return [
            'success' => false,
            'status' => 500,
            'message' => 'Server connection failed',
            'data' => null
        ];
    }

    $responseData = json_decode($response, true);

    return [
        'success' => $httpCode >= 200 && $httpCode < 300,
        'status' => $httpCode,
        'message' => getMessageFromStatus($httpCode),
        'data' => $responseData
    ];
}

function getMessageFromStatus($httpCode) {
    switch ($httpCode) {
        case 200:
        case 201:
            return 'Success';
        case 401:
            return 'Incorrect username or password';
        case 404:
            return 'User not found';
        case 500:
            return 'An error occurred on the server. Please try again later.';
        default:
            return 'An unexpected error occurred';
    }
}

// Store JWT in secure cookie
function setJWTCookie($token) {
    setcookie(
        JWT_COOKIE_NAME,
        $token,
        [
            'expires' => time() + COOKIE_EXPIRY,
            'path' => '/',
            'secure' => SECURE_COOKIE,
            'httponly' => true,
            'samesite' => 'Strict'
        ]
    );
    $_SESSION['jwt_token'] = $token;
}

// Get JWT from cookie or session
function getJWTToken() {
    if (isset($_COOKIE[JWT_COOKIE_NAME])) {
        return $_COOKIE[JWT_COOKIE_NAME];
    }
    if (isset($_SESSION['jwt_token'])) {
        return $_SESSION['jwt_token'];
    }
    return null;
}

// Clear JWT cookie and session
function clearJWTCookie() {
    setcookie(JWT_COOKIE_NAME, '', time() - 3600, '/', '', SECURE_COOKIE, true);
    unset($_SESSION['jwt_token']);
}

// Check if user is authenticated
function isAuthenticated() {
    $token = getJWTToken();
    if (!$token) {
        return false;
    }

    // Verify token with Rust backend by calling /profile
    $result = callRustAPI('/profile', 'GET', null, $token);

    if ($result['success']) {
        return true;
    }

    // Token invalid, clear it
    clearJWTCookie();
    return false;
}
?>
