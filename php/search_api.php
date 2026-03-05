<?php
// search_api.php
require_once "config.php";
header("Content-Type: application/json");

if (!isAuthenticated()) {
    echo json_encode(["success" => false, "message" => "Unauthorized"]);
    exit();
}

$qs = http_build_query($_GET);
$res = callRustAPI("/global-search?" . $qs, "GET", null, getJWTToken());

echo json_encode($res);
?>
