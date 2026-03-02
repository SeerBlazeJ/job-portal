<?php
// auth.php
require_once "config.php";

header("Content-Type: application/json");

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(["status" => "error", "message" => "Method not allowed"]);
    exit();
}

$mode = $_POST["mode"] ?? "";
$username = trim($_POST["username"] ?? "");
$password = $_POST["password"] ?? "";
$email = trim($_POST["email"] ?? "");

if (empty($mode) || empty($username) || empty($password)) {
    echo json_encode([
        "status" => "error",
        "message" => "Required fields missing",
    ]);
    exit();
}

if ($mode === "signup") {
    $role = $_POST["role"] ?? "seeker";
    $is_finding_job = $role === "seeker";

    $signupData = [
        "uid" => $username,
        "pword" => $password,
        "email" => $email,
        "name" => $username,
        "is_finding_job" => $is_finding_job,
    ];

    $result = callRustAPI("/signup", "POST", $signupData);

    if ($result["success"]) {
        // Automatically Log them in so we get a token to perform the company creation
        $signinData = ["uid" => $username, "pword" => $password];
        $signinRes = callRustAPI("/signin", "POST", $signinData);

        if ($signinRes["success"] && !empty($signinRes["data"]["token"])) {
            $token = $signinRes["data"]["token"];
            setJWTCookie($token); // Lock them in immediately

            // If Employer, orchestrate company attachment
            if (!$is_finding_job) {
                $compAction = $_POST["company_action"] ?? "create";
                $designation = trim($_POST["designation"] ?? "HR");

                if ($compAction === "create") {
                    $compData = [
                        "name" => trim(
                            $_POST["new_company_name"] ?? $username . " Corp",
                        ),
                        "location" => trim(
                            $_POST["new_company_location"] ?? "",
                        ),
                        "website" => trim($_POST["new_company_website"] ?? ""),
                        "designation" => $designation,
                        "description" => null,
                        "logo" => null,
                    ];
                    callRustAPI("/create-company", "POST", $compData, $token);
                } elseif (
                    $compAction === "join" &&
                    !empty($_POST["company_id"])
                ) {
                    $joinData = [
                        "company_id" => $_POST["company_id"],
                        "designation" => $designation,
                    ];
                    callRustAPI("/join-company", "POST", $joinData, $token);
                }
            }

            echo json_encode([
                "status" => "success",
                "message" => "Registration complete!",
                "redirect" => "dashboard.php",
            ]);
            exit();
        }

        echo json_encode(["status" => "success", "redirect" => "login"]);
        exit();
    }

    echo json_encode(["status" => "error", "message" => $result["message"]]);
    exit();
}

if ($mode === "login") {
    $signinData = ["uid" => $username, "pword" => $password];
    $result = callRustAPI("/signin", "POST", $signinData);

    if ($result["success"] && isset($result["data"]["token"])) {
        setJWTCookie($result["data"]["token"]);
        echo json_encode([
            "status" => "success",
            "redirect" => "dashboard.php",
        ]);
        exit();
    }
    echo json_encode(["status" => "error", "message" => $result["message"]]);
    exit();
}
