<?php
// php/chat_api.php
require_once "config.php";
header("Content-Type: application/json");

if (!isAuthenticated()) {
    echo json_encode(["success" => false, "message" => "Unauthorized"]);
    exit();
}

$action = $_GET["action"] ?? "";
$jwt = getJWTToken();

if ($action === "init") {
    $data = json_decode(file_get_contents("php://input"), true);
    $res = callRustAPI(
        "/chat/init",
        "POST",
        ["target_uid" => $data["target_uid"]],
        $jwt,
    );
    echo json_encode($res);
} elseif ($action === "get_sessions") {
    $res = callRustAPI("/chat/sessions", "GET", null, $jwt);
    echo json_encode($res);
} elseif ($action === "get_messages") {
    $sid = $_GET["session_id"] ?? "";
    $res = callRustAPI("/chat/messages/" . urlencode($sid), "GET", null, $jwt);
    echo json_encode($res);
} elseif ($action === "send") {
    $session_id = $_POST["session_id"] ?? "";
    $content = $_POST["content"] ?? "";
    $file_url = null;

    // FIX: Enhanced and strictly validated File Upload handling
    if (isset($_FILES["attachment"])) {
        if ($_FILES["attachment"]["error"] === UPLOAD_ERR_OK) {
            $uploadDir = "uploads/chats/";
            if (!is_dir($uploadDir)) {
                mkdir($uploadDir, 0777, true);
            }

            // Remove spaces/special characters from filename to prevent saving bugs
            $cleanName = preg_replace(
                "/[^a-zA-Z0-9\._-]/",
                "",
                basename($_FILES["attachment"]["name"]),
            );
            $fileName = time() . "_" . $cleanName;
            $targetPath = $uploadDir . $fileName;

            if (
                move_uploaded_file(
                    $_FILES["attachment"]["tmp_name"],
                    $targetPath,
                )
            ) {
                $file_url = $targetPath;
            } else {
                echo json_encode([
                    "success" => false,
                    "message" => "Server error: Failed to save uploaded file.",
                ]);
                exit();
            }
        } else {
            // Give specific feedback instead of failing silently
            $errorCode = $_FILES["attachment"]["error"];
            $errorMsg = "File upload failed (Error Code: $errorCode). ";
            if (
                $errorCode == UPLOAD_ERR_INI_SIZE ||
                $errorCode == UPLOAD_ERR_FORM_SIZE
            ) {
                $errorMsg .= "The file size exceeds the server limit.";
            }
            echo json_encode(["success" => false, "message" => $errorMsg]);
            exit();
        }
    }

    $payload = [
        "session_id" => $session_id,
        "content" => $content,
        "file_url" => $file_url,
    ];

    $res = callRustAPI("/chat/message", "POST", $payload, $jwt);
    echo json_encode(["success" => true, "data" => $res]);
}
?>
