<?php
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
    echo json_encode(
        callRustAPI(
            "/chat/init",
            "POST",
            ["target_uid" => $data["target_uid"]],
            $jwt,
        ),
    );
} elseif ($action === "get_sessions") {
    echo json_encode(callRustAPI("/chat/sessions", "GET", null, $jwt));
} elseif ($action === "get_messages") {
    $sid = $_GET["session_id"] ?? "";
    echo json_encode(
        callRustAPI("/chat/messages/" . urlencode($sid), "GET", null, $jwt),
    );
} elseif ($action === "send") {
    $file_url = null;
    if (
        isset($_FILES["attachment"]) &&
        $_FILES["attachment"]["error"] === UPLOAD_ERR_OK
    ) {
        $uploadDir = "uploads/chats/";
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0777, true);
        }
        $fileName = time() . "_" . basename($_FILES["attachment"]["name"]);
        if (
            move_uploaded_file(
                $_FILES["attachment"]["tmp_name"],
                $uploadDir . $fileName,
            )
        ) {
            $file_url = $uploadDir . $fileName;
        }
    }
    $payload = [
        "session_id" => $_POST["session_id"] ?? "",
        "content" => $_POST["content"] ?? "",
        "file_url" => $file_url,
    ];
    echo json_encode(callRustAPI("/chat/message", "POST", $payload, $jwt));
}
?>
