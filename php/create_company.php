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
    <title>Create Company - Job Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; }

        .header { background: white; padding: 20px 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .header h1 { color: #333; font-size: 28px; }
        .btn-secondary { padding: 10px 20px; background: #6c757d; color: white; border-radius: 5px; text-decoration: none; font-weight: 600; transition: background 0.3s;}
        .btn-secondary:hover { background: #5a6268; }

        .form-container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .form-container h2 { margin-bottom: 25px; color: #333; }

        .form-group { margin-bottom: 25px; }
        .form-group label { display: block; color: #333; font-weight: 600; margin-bottom: 8px; font-size: 14px; }
        .form-group input, .form-group textarea { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 5px; font-size: 14px; font-family: inherit; transition: border-color 0.3s;}
        .form-group input:focus, .form-group textarea:focus { border-color: #667eea; outline: none; }
        .form-group textarea { min-height: 120px; resize: vertical; }

        .row { display: flex; gap: 20px; }
        .row > div { flex: 1; }

        .btn-primary { background: #667eea; color: white; width: 100%; padding: 15px; font-size: 16px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; transition: background 0.3s;}
        .btn-primary:hover { background: #5568d3; }
        .btn-primary:disabled { background: #ccc; cursor: not-allowed; }

        .alert { padding: 15px; border-radius: 5px; margin-bottom: 20px; display: none; font-weight: 500;}
        .alert.show { display: block; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏢 Create Company</h1>
            <a href="dashboard.php" class="btn-secondary">← Back to Dashboard</a>
        </div>

        <div class="form-container">
            <h2>Register a New Company Profile</h2>
            <div id="alert" class="alert"></div>

            <form id="company-form" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="logo">Company Logo (Image)</label>
                    <input type="file" id="logo" name="logo" accept="image/*">
                </div>

                <div class="row">
                    <div class="form-group">
                        <label for="name">Company Name *</label>
                        <input type="text" id="name" name="name" required placeholder="e.g., Acme Corp">
                    </div>
                    <div class="form-group">
                        <label for="designation">Your Role/Designation *</label>
                        <input type="text" id="designation" name="designation" required placeholder="e.g., Founder & CEO">
                    </div>
                </div>

                <div class="row">
                    <div class="form-group">
                        <label for="location">Headquarters / Location</label>
                        <input type="text" id="location" name="location" placeholder="e.g., San Francisco, CA">
                    </div>
                    <div class="form-group">
                        <label for="website">Website URL</label>
                        <input type="url" id="website" name="website" placeholder="e.g., https://acmecorp.com">
                    </div>
                </div>

                <div class="form-group">
                    <label for="description">About the Company</label>
                    <textarea id="description" name="description" placeholder="What does your company do?"></textarea>
                </div>

                <button type="submit" class="btn-primary" id="submit-btn">Register Company</button>
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
            btn.textContent = 'Registering...';
            alertBox.className = 'alert'; // hide previous alerts

            try {
                const res = await fetch('create_company.php', {
                    method: 'POST',
                    body: fd
                });

                const result = await res.json();

                alertBox.textContent = result.message;
                alertBox.className = `alert alert-${result.status === 'success' ? 'success' : 'error'} show`;

                if (result.status === 'success') {
                    // Redirect to dashboard after successful creation
                    setTimeout(() => window.location.href = 'dashboard.php', 1500);
                } else {
                    btn.disabled = false;
                    btn.textContent = 'Register Company';
                }
            } catch(error) {
                alertBox.textContent = 'A network error occurred while submitting the form.';
                alertBox.className = `alert alert-error show`;
                btn.disabled = false;
                btn.textContent = 'Register Company';
            }
        });
    </script>
</body>
</html>
