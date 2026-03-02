<?php
// edit_company.php
require_once "config.php";
if (!isAuthenticated()) {
    header("Location: signin.php");
    exit();
}
if (!isset($_GET["id"]) && $_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: dashboard.php");
    exit();
}

$token = getJWTToken();

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    header("Content-Type: application/json");
    $companyId = $_POST["company_id"];

    $companyData = [
        "name" => trim($_POST["name"] ?? ""),
        "description" => trim($_POST["description"] ?? "") ?: null,
        "website" => trim($_POST["website"] ?? "") ?: null,
        "location" => trim($_POST["location"] ?? "") ?: null,
    ];

    if (isset($_FILES["logo"]) && $_FILES["logo"]["error"] === UPLOAD_ERR_OK) {
        $uploadDir = "uploads/companies/";
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0777, true);
        }
        $ext = pathinfo($_FILES["logo"]["name"], PATHINFO_EXTENSION);
        $filename = "logo_" . time() . "_" . uniqid() . "." . $ext;
        if (
            move_uploaded_file(
                $_FILES["logo"]["tmp_name"],
                $uploadDir . $filename,
            )
        ) {
            $companyData["logo"] = $uploadDir . $filename;
        }
    }

    $result = callRustAPI(
        "/company/" . urlencode($companyId),
        "PUT",
        $companyData,
        $token,
    );

    if ($result["success"]) {
        echo json_encode([
            "status" => "success",
            "message" => "Company updated!",
        ]);
    } else {
        echo json_encode([
            "status" => "error",
            "message" => $result["message"],
        ]);
    }
    exit();
}

// Fetch existing data to populate the form
$targetId = $_GET["id"];
$apiResult = callRustAPI(
    "/company/" . urlencode($targetId),
    "GET",
    null,
    $token,
);

if (!$apiResult["success"] || empty($apiResult["data"]["is_owner"])) {
    die("Unauthorized or company not found.");
}
$company = $apiResult["data"]["company"];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Company</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .btn-secondary { padding: 10px 20px; background: #6c757d; color: white; border-radius: 5px; text-decoration: none; font-weight: 600; display: inline-block; margin-bottom: 20px;}
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; color: #333; font-weight: 600; margin-bottom: 8px; font-size: 14px; }
        .form-group input, .form-group textarea { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 5px; font-size: 14px; font-family: inherit;}
        .form-group textarea { min-height: 120px; resize: vertical; }
        .btn-primary { background: #667eea; color: white; width: 100%; padding: 15px; font-size: 16px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
        .alert { padding: 15px; border-radius: 5px; margin-bottom: 20px; display: none; font-weight: 500;}
        .alert.show { display: block; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .row { display: flex; gap: 20px; }
        .row > div { flex: 1; }
    </style>
</head>
<body>
    <div class="container">
        <h2>✏️ Edit Company: <?php echo htmlspecialchars(
            $company["name"],
        ); ?></h2>
        <a href="company.php?id=<?php echo urlencode(
            $company["id"],
        ); ?>" class="btn-secondary">← Back to Profile</a>

        <div id="alert" class="alert"></div>

        <form id="edit-form" enctype="multipart/form-data">
            <input type="hidden" id="company_id" name="company_id" value="<?php echo htmlspecialchars(
                $company["id"],
            ); ?>">

            <div class="form-group">
                <label>Company Logo (Upload new image to replace)</label>
                <input type="file" id="logo" name="logo" accept="image/*">
            </div>

            <div class="row">
                <div class="form-group">
                    <label>Company Name *</label>
                    <input type="text" id="name" name="name" required value="<?php echo htmlspecialchars(
                        $company["name"],
                    ); ?>">
                </div>
                <div class="form-group">
                    <label>Location</label>
                    <input type="text" id="location" name="location" value="<?php echo htmlspecialchars(
                        $company["location"] ?? "",
                    ); ?>">
                </div>
            </div>

            <div class="form-group">
                <label>Website URL</label>
                <input type="url" id="website" name="website" value="<?php echo htmlspecialchars(
                    $company["website"] ?? "",
                ); ?>">
            </div>

            <div class="form-group">
                <label>About the Company</label>
                <textarea id="description" name="description"><?php echo htmlspecialchars(
                    $company["description"] ?? "",
                ); ?></textarea>
            </div>

            <button type="submit" class="btn-primary" id="submit-btn">Save Changes</button>
        </form>
    </div>

    <script>
        document.getElementById('edit-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('submit-btn');
            const alertBox = document.getElementById('alert');
            const fd = new FormData();

            fd.append('company_id', document.getElementById('company_id').value);
            fd.append('name', document.getElementById('name').value.trim());
            fd.append('location', document.getElementById('location').value.trim());
            fd.append('website', document.getElementById('website').value.trim());
            fd.append('description', document.getElementById('description').value.trim());

            const logoFile = document.getElementById('logo').files[0];
            if (logoFile) fd.append('logo', logoFile);

            btn.disabled = true; btn.textContent = 'Saving...';
            alertBox.className = 'alert';

            try {
                const res = await fetch('edit_company.php', { method: 'POST', body: fd });
                const result = await res.json();

                alertBox.textContent = result.message;
                alertBox.className = `alert alert-${result.status === 'success' ? 'success' : 'error'} show`;

                if (result.status === 'success') {
                    setTimeout(() => {
                        window.location.href = 'company.php?id=' + encodeURIComponent(document.getElementById('company_id').value);
                    }, 1000);
                } else {
                    btn.disabled = false; btn.textContent = 'Save Changes';
                }
            } catch(e) {
                alertBox.textContent = 'Network Error';
                alertBox.className = 'alert alert-error show';
                btn.disabled = false; btn.textContent = 'Save Changes';
            }
        });
    </script>
</body>
</html>
