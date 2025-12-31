<?php
// index.php
require_once 'config.php';

// Redirect to dashboard if authenticated, otherwise to signin
if (isAuthenticated()) {
    header('Location: dashboard.php');
} else {
    header('Location: signin.php');
}
exit;
?>
