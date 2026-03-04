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
    <title>Edit Company — JobPortal</title>
    <link rel="stylesheet" href="./css/styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="bg-orbs"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>

    <div class="dash-container">
        
        <header class="dash-header">
            <h1 class="dash-title">✏️ Edit Company</h1>
            <div class="dash-nav">
                <a href="company.php?id=<?php echo urlencode($company["id"]); ?>" class="dash-btn dash-btn-glass">← Back to Profile</a>
            </div>
        </header>

        <div class="profile-wrapper">
            <h2 class="dash-section-title" style="margin-bottom: 2rem;">Updating: <?php echo htmlspecialchars($company["name"]); ?></h2>
            <div id="alert" class="profile-alert"></div>

            <form id="edit-form" enctype="multipart/form-data">
                <input type="hidden" id="company_id" name="company_id" value="<?php echo htmlspecialchars($company["id"]); ?>">

                <div class="form-group" style="margin-bottom: 1.5rem;">
                    <label class="form-label">Company Logo (Upload new image to replace)</label>
                    <input type="file" id="logo" name="logo" accept="image/*" class="form-input">
                </div>

                <div class="form-grid-2">
                    <div class="form-group">
                        <label class="form-label">Company Name *</label>
                        <input type="text" id="name" name="name" required class="form-input" style="padding-left: 1rem;" value="<?php echo htmlspecialchars($company["name"]); ?>">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Location</label>
                        <input type="text" id="location" name="location" class="form-input" style="padding-left: 1rem;" value="<?php echo htmlspecialchars($company["location"] ?? ""); ?>">
                    </div>
                </div>

                <div class="form-group" style="margin-bottom: 1.5rem;">
                    <label class="form-label">Website URL</label>
                    <input type="url" id="website" name="website" class="form-input" style="padding-left: 1rem;" value="<?php echo htmlspecialchars($company["website"] ?? ""); ?>">
                </div>

                <div class="form-group" style="margin-bottom: 2rem;">
                    <label class="form-label">About the Company</label>
                    <textarea id="description" name="description" class="form-input"><?php echo htmlspecialchars($company["description"] ?? ""); ?></textarea>
                </div>

                <button type="submit" class="dash-btn dash-btn-primary" id="submit-btn" style="width: 100%; justify-content: center; font-size: 1rem; padding: 1rem;">💾 Save Changes</button>
            </form>
        </div>
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

            btn.disabled = true; btn.innerHTML = '⏳ Saving...';
            alertBox.classList.remove('show');

            try {
                const res = await fetch('edit_company.php', { method: 'POST', body: fd });
                const result = await res.json();

                alertBox.innerHTML = `<span>${result.status === 'success' ? '✓' : '⚠️'}</span> ${result.message}`;
                alertBox.className = `profile-alert alert-${result.status === 'success' ? 'success' : 'error'} show`;

                if (result.status === 'success') {
                    setTimeout(() => {
                        window.location.href = 'company.php?id=' + encodeURIComponent(document.getElementById('company_id').value);
                    }, 1000);
                } else {
                    btn.disabled = false; btn.innerHTML = '💾 Save Changes';
                }
            } catch(e) {
                alertBox.innerHTML = `<span>⚠️</span> Network Error`;
                alertBox.className = 'profile-alert alert-error show';
                btn.disabled = false; btn.innerHTML = '💾 Save Changes';
            }
        });
    </script>
</body>
</html>