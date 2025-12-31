<?php
// logout.php
require_once 'config.php';

// Clear JWT cookie and session
clearJWTCookie();
session_destroy();

// Redirect to signin page
header('Location: signin.php');
exit;
?>
