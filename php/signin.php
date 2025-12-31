<?php
// signin.php
require_once 'config.php';

// If already authenticated, redirect to dashboard
if (isAuthenticated()) {
    header('Location: dashboard.php');
    exit;
}

// Serve the login-signup.html with dynamic PHP rendering
$htmlContent = file_get_contents('../frontend/login-signup.html');

// Update the fetch call in JavaScript to work with PHP
$htmlContent = str_replace(
    '// TODO UNCOMMENT THE BLOCK BELOW WHEN auth.php IS READY',
    '// PHP Integration Active',
    $htmlContent
);

// Uncomment the fetch block
$htmlContent = preg_replace(
    '/\/\*\s*fetchauth\.php.*?\*\//s',
    '',
    $htmlContent
);

// Remove the temporary testing code
$htmlContent = preg_replace(
    '/\/\/ TEMPORARY Just for UI testing.*?\/\/ PHP INTEGRATION ENDS HERE/s',
    '// PHP INTEGRATION ENDS HERE',
    $htmlContent
);

echo $htmlContent;
?>
