<?php
// dashboard.php
require_once 'config.php';

// Check authentication
if (!isAuthenticated()) {
    header('Location: signin.php');
    exit;
}

// Get user profile (optional - for future use)
$token = getJWTToken();
// $profile = callRustAPI('/profile', 'GET', null, $token);

// Serve the dashboard HTML
$htmlContent = file_get_contents('../frontend/dashboard.html');

// You can inject user data here when profile endpoint is ready
// For now, just serve static dashboard
echo $htmlContent;
?>
