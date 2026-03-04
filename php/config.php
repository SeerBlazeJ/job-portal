<?php
// config.php
ob_start(); // Prevent session_start() issues with early output
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Rust server configuration
define('RUST_API_URL', 'http://localhost:3000');
define('JWT_COOKIE_NAME', 'job_portal_token');
define('COOKIE_EXPIRY', 86400); // 24 hours
define('SECURE_COOKIE', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on');

// Cookie policy: Lax is usually safer during development than Strict.
define('JWT_SAMESITE', 'Lax');

// Helper: cookie options (PHP 7.3+)
function jwtCookieOptions(int $expires): array {
    return [
        'expires' => $expires,
        'path' => '/',
        'secure' => SECURE_COOKIE,
        'httponly' => true,
        'samesite' => JWT_SAMESITE,
    ];
}

// Helper function to make API calls to Rust server
function callRustAPI($endpoint, $method = 'GET', $data = null, $token = null) {
    $url = RUST_API_URL . $endpoint;

    $headers = [
        'Content-Type' => 'application/json',
    ];
    if ($token) {
        $headers['Authorization'] = 'Bearer ' . $token;
    }

    $postData = null;
    if ($data !== null && ($method === 'POST' || $method === 'PUT')) {
        $postData = json_encode($data);
    }

    // Build header string for stream context
    $headerStr = '';
    foreach ($headers as $k => $v) {
        $headerStr .= "$k: $v\r\n";
    }

    $contextOptions = [
        'http' => [
            'method' => $method,
            'header' => $headerStr,
            'timeout' => 10,
        ]
    ];

    if ($postData !== null) {
        $contextOptions['http']['content'] = $postData;
    }

    $context = stream_context_create($contextOptions);

    try {
        $response = @file_get_contents($url, false, $context);
        
        // Assume 200 if response is received, otherwise it failed
        $httpCode = ($response !== false) ? 200 : 500;

        if ($response === false) {
            return [
                'success' => false,
                'status' => 500,
                'message' => 'Server connection failed',
                'data' => null,
                'raw' => null,
            ];
        }

        $responseData = json_decode($response, true);

        // Prefer backend-provided message if present
        $msg = getMessageFromStatus($httpCode);
        if (is_array($responseData) && isset($responseData['message']) && is_string($responseData['message'])) {
            $msg = $responseData['message'];
        }

        return [
            'success' => $httpCode >= 200 && $httpCode < 300,
            'status' => $httpCode,
            'message' => $msg,
            'data' => $responseData,
            'raw' => $response,
        ];
    } catch (Exception $e) {
        return [
            'success' => false,
            'status' => 500,
            'message' => 'Server connection failed',
            'data' => null,
            'raw' => null,
        ];
    }
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
    // Keep session copy (optional; useful if cookies are blocked)
    $_SESSION['jwt_token'] = $token;

    // Must be sent before any output
    setcookie(JWT_COOKIE_NAME, $token, jwtCookieOptions(time() + COOKIE_EXPIRY));
}

// Get JWT from cookie or session
function getJWTToken() {
    if (!empty($_COOKIE[JWT_COOKIE_NAME])) {
        return $_COOKIE[JWT_COOKIE_NAME];
    }
    if (!empty($_SESSION['jwt_token'])) {
        return $_SESSION['jwt_token'];
    }
    return null;
}

// Clear JWT cookie and session
function clearJWTCookie() {
    unset($_SESSION['jwt_token']);
    // Expire cookie using the same attributes as setJWTCookie()
    setcookie(JWT_COOKIE_NAME, '', jwtCookieOptions(time() - 3600));
}

// Check if user is authenticated
function isAuthenticated() {
    $token = getJWTToken();
    if (!$token) return false;

    // Verify token with Rust backend by calling /profile
    $result = callRustAPI('/profile', 'GET', null, $token);

    if ($result['success']) return true;

    clearJWTCookie();
    return false;
}
