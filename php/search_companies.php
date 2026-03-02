<?php
// search_companies.php
require_once "config.php";
header("Content-Type: application/json");

$q = $_GET["q"] ?? "";
if (strlen(trim($q)) < 2) {
    echo json_encode(["success" => true, "data" => []]);
    exit();
}

$res = callRustAPI("/search-companies?q=" . urlencode(trim($q)), "GET");
echo json_encode($res);
?>
