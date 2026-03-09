<?php
// employer_api.php
require_once "config.php";
header("Content-Type: application/json");

if (!isAuthenticated()) {
    echo json_encode(["success" => false, "message" => "Unauthorized"]);
    exit();
}

$action = $_GET["action"] ?? "";
$token = getJWTToken();

if ($action === "my_jobs") {
    echo json_encode(callRustAPI("/my-jobs", "GET", null, $token));
} elseif ($action === "applicants" && !empty($_GET["job_id"])) {
    $job_id = $_GET["job_id"];
    echo json_encode(
        callRustAPI(
            "/job-applicants/" . urlencode($job_id),
            "GET",
            null,
            $token,
        ),
    );
} elseif ($action === "my_applications") {
    echo json_encode(callRustAPI("/my-applications", "GET", null, $token));
} elseif ($action === "verify_employee") {
    $input = json_decode(file_get_contents("php://input"), true);
    echo json_encode(callRustAPI("/verify-employee", "POST", $input, $token));
} elseif ($action === "reject_employee") {
    // <--- NEW ACTION ADDED HERE
    $input = json_decode(file_get_contents("php://input"), true);
    echo json_encode(callRustAPI("/reject-employee", "POST", $input, $token));
} elseif ($action === "update_application_status") {
    $input = json_decode(file_get_contents("php://input"), true);
    echo json_encode(
        callRustAPI("/update-application-status", "POST", $input, $token),
    );
} elseif ($action === "delete_job" && !empty($_GET["job_id"])) {
    echo json_encode(
        callRustAPI(
            "/job/" . urlencode($_GET["job_id"]),
            "DELETE",
            null,
            $token,
        ),
    );
} elseif ($action === "delete_company" && !empty($_GET["company_id"])) {
    echo json_encode(
        callRustAPI(
            "/company/" . urlencode($_GET["company_id"]),
            "DELETE",
            null,
            $token,
        ),
    );
} else {
    echo json_encode(["success" => false, "message" => "Invalid action"]);
}
?>
