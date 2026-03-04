<?php
// create_company.php
require_once "config.php";

// Ensure the user is signed in
if (!isAuthenticated()) {
    header("Location: signin.php");
    exit();
}

// Handle the form submission
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    header("Content-Type: application/json");

    $companyData = [
        "name" => trim($_POST["name"] ?? ""),
        "description" => trim($_POST["description"] ?? "") ?: null,
        "website" => trim($_POST["website"] ?? "") ?: null,
        "location" => trim($_POST["location"] ?? "") ?: null,
        "designation" => trim($_POST["designation"] ?? "Founder"), // Required for works_for relation
    ];

    if (empty($companyData["name"])) {
        echo json_encode([
            "status" => "error",
            "message" => "Company name is required.",
        ]);
        exit();
    }

    // Handle Logo Upload via PHP
    $uploadDir = "uploads/companies/";
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    if (isset($_FILES["logo"]) && $_FILES["logo"]["error"] === UPLOAD_ERR_OK) {
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
    } else {
        $companyData["logo"] = null;
    }

    // Send the processed data to the Rust backend
    $token = getJWTToken();
    $result = callRustAPI("/create-company", "POST", $companyData, $token);

    if ($result["success"]) {
        echo json_encode([
            "status" => "success",
            "message" => "Company created successfully!",
        ]);
    } else {
        echo json_encode([
            "status" => "error",
            "message" => $result["message"],
        ]);
    }
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Company — JobPortal</title>
    <link rel="stylesheet" href="./css/styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="bg-orbs"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>

    <div class="dash-container">
        <header class="dash-header">
            <h1 class="dash-title">🏢 Create Company</h1>
            <div class="dash-nav">
                <a href="dashboard.php" class="dash-btn dash-btn-glass">← Back to Dashboard</a>
            </div>
        </header>

        <div class="profile-wrapper">
            <h2 class="dash-section-title" style="margin-bottom: 2rem;">Register a New Company Profile</h2>
            <div id="alert" class="profile-alert"></div>

            <form id="company-form" enctype="multipart/form-data">
                
                <div class="form-group" style="margin-bottom: 1.5rem;">
                    <label class="form-label" for="logo">Company Logo (Image)</label>
                    <input type="file" id="logo" name="logo" accept="image/*" class="form-input">
                </div>

                <div class="form-grid-2">
                    <div class="form-group">
                        <label class="form-label" for="name">Company Name *</label>
                        <input type="text" id="name" name="name" required placeholder="e.g., Acme Corp" class="form-input" style="padding-left: 1rem;">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="designation">Your Role/Designation *</label>
                        <input type="text" id="designation" name="designation" required placeholder="e.g., Founder & CEO" class="form-input" style="padding-left: 1rem;">
                    </div>
                </div>

                <div class="form-grid-2">
                    <div class="form-group">
                        <label class="form-label" for="location">Headquarters / Location</label>
                        <input type="text" id="location" name="location" placeholder="e.g., San Francisco, CA" class="form-input" style="padding-left: 1rem;">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="website">Website URL</label>
                        <input type="url" id="website" name="website" placeholder="e.g., https://acmecorp.com" class="form-input" style="padding-left: 1rem;">
                    </div>
                </div>

                <div class="form-group" style="margin-bottom: 2rem;">
                    <label class="form-label" for="description">About the Company</label>
                    <textarea id="description" name="description" placeholder="What does your company do?" class="form-input"></textarea>
                </div>

                <button type="submit" class="dash-btn dash-btn-primary" id="submit-btn" style="width: 100%; justify-content: center; font-size: 1rem; padding: 1rem;">🚀 Register Company</button>
            </form>
        </div>
    </div>

    <script>
        document.getElementById('company-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('submit-btn');
            const alertBox = document.getElementById('alert');

            // Build multipart/form-data payload
            const fd = new FormData();
            fd.append('name', document.getElementById('name').value.trim());
            fd.append('location', document.getElementById('location').value.trim());
            fd.append('website', document.getElementById('website').value.trim());
            fd.append('description', document.getElementById('description').value.trim());
            fd.append('designation', document.getElementById('designation').value.trim());

            const logoFile = document.getElementById('logo').files[0];
            if (logoFile) fd.append('logo', logoFile);

            btn.disabled = true;
            btn.innerHTML = '⏳ Registering...';
            alertBox.classList.remove('show'); // hide previous alerts

            try {
                const res = await fetch('create_company.php', {
                    method: 'POST',
                    body: fd
                });

                const result = await res.json();

                alertBox.innerHTML = `<span>${result.status === 'success' ? '✓' : '⚠️'}</span> ${result.message}`;
                alertBox.className = `profile-alert alert-${result.status === 'success' ? 'success' : 'error'} show`;

                if (result.status === 'success') {
                    setTimeout(() => window.location.href = 'dashboard.php', 1500);
                } else {
                    btn.disabled = false;
                    btn.innerHTML = '🚀 Register Company';
                }
            } catch(error) {
                alertBox.innerHTML = `<span>⚠️</span> A network error occurred while submitting the form.`;
                alertBox.className = `profile-alert alert-error show`;
                btn.disabled = false;
                btn.innerHTML = '🚀 Register Company';
            }
        });
    </script>
</body>
</html>