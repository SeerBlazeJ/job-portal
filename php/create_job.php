<?php
// create_job.php
require_once "config.php";

// Check authentication
if (!isAuthenticated()) {
    header("Location: signin.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    header("Content-Type: application/json");

    $eduLevelMap = [
        1 => "HighSchool",
        2 => "Diploma",
        3 => "Bachelors",
        4 => "Masters",
        5 => "PhD",
    ];

    $expYears =
        isset($_POST["min_exp_years"]) && $_POST["min_exp_years"] !== ""
            ? (int) $_POST["min_exp_years"]
            : 0;
    $expMonths =
        isset($_POST["min_exp_months"]) && $_POST["min_exp_months"] !== ""
            ? (int) $_POST["min_exp_months"]
            : 0;
    $totalExpMonths = $expYears * 12 + $expMonths;
    $minExperience = $totalExpMonths > 0 ? $totalExpMonths : null;

    $jobData = [
        "title" => trim($_POST["title"] ?? ""),
        "company_name" => trim($_POST["company_name"] ?? ""),
        "company_id" => trim($_POST["company_id"] ?? ""),
        "min_experience" => $minExperience,
        "description" => trim($_POST["description"] ?? ""),
        "location" => trim($_POST["location"] ?? ""),
        "datetime_due" => $_POST["datetime_due"] ?? "",
        "min_ed_lvl" => $eduLevelMap[$_POST["min_ed_lvl"] ?? 3] ?? "Bachelors",
        "salary_range_start" => !empty($_POST["salary_range_start"])
            ? (int) $_POST["salary_range_start"]
            : null,
        "salary_range_end" => !empty($_POST["salary_range_end"])
            ? (int) $_POST["salary_range_end"]
            : null,
    ];

    if (!empty($_POST["skills_required"])) {
        $jobData["skills_required"] = json_decode(
            $_POST["skills_required"],
            true,
        );
    }
    if (!empty($_POST["majors_accepted"])) {
        $jobData["majors_accepted"] = json_decode(
            $_POST["majors_accepted"],
            true,
        );
    }

    $uploadDir = "uploads/jobs/";
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    $photos = [];
    if (isset($_FILES["photos"])) {
        $fileCount = is_array($_FILES["photos"]["name"])
            ? count($_FILES["photos"]["name"])
            : 0;
        for ($i = 0; $i < $fileCount; $i++) {
            if ($_FILES["photos"]["error"][$i] === UPLOAD_ERR_OK) {
                $ext = pathinfo(
                    $_FILES["photos"]["name"][$i],
                    PATHINFO_EXTENSION,
                );
                $filename = "job_" . time() . "_" . uniqid() . "." . $ext;
                if (
                    move_uploaded_file(
                        $_FILES["photos"]["tmp_name"][$i],
                        $uploadDir . $filename,
                    )
                ) {
                    $photos[] = $uploadDir . $filename;
                }
            }
        }
    }
    if (!empty($photos)) {
        $jobData["photos"] = $photos;
    }

    $token = getJWTToken();
    $result = callRustAPI("/create-job", "POST", $jobData, $token);

    if ($result["success"]) {
        echo json_encode([
            "status" => "success",
            "message" => "Job post created successfully!",
            "data" => $result["data"],
        ]);
    } else {
        echo json_encode([
            "status" => "error",
            "message" => $result["message"],
        ]);
    }
    exit();
}

$token = getJWTToken();
$profileResult = callRustAPI("/profile", "GET", null, $token);

if (!$profileResult["success"]) {
    clearJWTCookie();
    header("Location: signin.php");
    exit();
}

$companies = $profileResult["data"]["working_at"] ?? [];
$verifiedCompanies = array_filter($companies, function ($c) {
    return !empty($c["is_verified"]);
});
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Create Job Post - Job Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; }
        .header { background: white; padding: 20px 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .btn { padding: 10px 20px; border-radius: 5px; text-decoration: none; font-weight: 600; font-size: 14px; cursor: pointer; border: none; transition: all 0.3s; }
        .btn-secondary { background: #6c757d; color: white; }
        .form-container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .form-group { margin-bottom: 25px; }
        .form-group label { display: block; color: #333; font-weight: 600; margin-bottom: 8px; font-size: 14px; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 5px; font-size: 14px; }
        .form-group textarea { min-height: 120px; resize: vertical; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .exp-inputs { display: flex; gap: 10px; }
        .btn-primary { background: #667eea; color: white; width: 100%; padding: 15px; font-size: 16px; }
        .btn-primary:disabled { background: #ccc; cursor: not-allowed; }
        .alert { padding: 15px; border-radius: 5px; margin-bottom: 20px; display: none; }
        .alert.show { display: block; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .helper-text { font-size: 12px; color: #666; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📝 Create Job Post</h1>
            <div class="nav-links"><a href="dashboard.php" class="btn btn-secondary">← Back to Dashboard</a></div>
        </div>

        <div class="form-container">
            <div id="alert" class="alert"></div>

            <form id="job-form" enctype="multipart/form-data">
                <div class="form-group"><label>Job Photos</label><input type="file" id="photos" name="photos[]" accept="image/*" multiple></div>
                <div class="form-group"><label>Job Title *</label><input type="text" id="title" required placeholder="e.g., Senior Software Engineer"></div>

                <div class="form-row">
                    <div class="form-group">
                        <label>Company *</label>
                        <?php if (empty($verifiedCompanies)): ?>
                            <p style="color: #dc3545; font-size: 13px; font-weight: bold; margin-bottom: 5px;">
                                ⚠️ You must be a verified employee to post jobs.
                            </p>
                            <select id="company_select" disabled required>
                                <option value="">No verified companies</option>
                            </select>
                        <?php else: ?>
                            <select id="company_select" required>
                                <option value="">-- Select Company --</option>
                                <?php foreach ($verifiedCompanies as $comp): ?>
                                    <option value="<?php echo htmlspecialchars(
                                        $comp["company_id"],
                                    ); ?>" data-name="<?php echo htmlspecialchars(
    $comp["company_name"],
); ?>">
                                        <?php echo htmlspecialchars(
                                            $comp["company_name"],
                                        ); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        <?php endif; ?>
                    </div>
                    <div class="form-group">
                        <label>Minimum Experience</label>
                        <div class="exp-inputs">
                            <input type="number" id="min_exp_years" placeholder="Years" min="0">
                            <input type="number" id="min_exp_months" placeholder="Months" min="0" max="11">
                        </div>
                    </div>
                </div>

                <div class="form-group"><label>Job Description *</label><textarea id="description" required></textarea></div>

                <div class="form-row">
                    <div class="form-group"><label>Location *</label><input type="text" id="location" required></div>
                    <div class="form-group">
                        <label>Minimum Education Level *</label>
                        <select id="min_ed_lvl" required>
                            <option value="">Select education level</option>
                            <option value="1">High School</option>
                            <option value="2">Diploma</option>
                            <option value="3" selected>Bachelor's Degree</option>
                            <option value="4">Master's Degree</option>
                            <option value="5">PhD/Doctorate</option>
                        </select>
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-group"><label>Salary Range Start ($)</label><input type="number" id="salary_start" min="0"></div>
                    <div class="form-group"><label>Salary Range End ($)</label><input type="number" id="salary_end" min="0"></div>
                </div>

                <div class="form-group"><label>Application Deadline *</label><input type="datetime-local" id="datetime_due" required></div>

                <button type="submit" class="btn btn-primary" id="submit-btn" <?php echo empty(
                    $verifiedCompanies
                )
                    ? "disabled"
                    : ""; ?>>Create Job Post</button>
            </form>
        </div>
    </div>

    <script>
        document.getElementById('job-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = document.getElementById('submit-btn');

            const compSelect = document.getElementById('company_select');
            const selectedComp = compSelect.options[compSelect.selectedIndex];

            const formData = new FormData();
            formData.append('title', document.getElementById('title').value.trim());
            formData.append('company_id', selectedComp.value);
            formData.append('company_name', selectedComp.getAttribute('data-name'));

            if (document.getElementById('min_exp_years').value !== "") {
                formData.append('min_exp_years', document.getElementById('min_exp_years').value);
            }
            if (document.getElementById('min_exp_months').value !== "") {
                formData.append('min_exp_months', document.getElementById('min_exp_months').value);
            }

            formData.append('description', document.getElementById('description').value.trim());
            formData.append('location', document.getElementById('location').value.trim());
            formData.append('min_ed_lvl', document.getElementById('min_ed_lvl').value);

            if (document.getElementById('salary_start').value) formData.append('salary_range_start', document.getElementById('salary_start').value);
            if (document.getElementById('salary_end').value) formData.append('salary_range_end', document.getElementById('salary_end').value);

            formData.append('datetime_due', new Date(document.getElementById('datetime_due').value).toISOString());

            const photosInput = document.getElementById('photos');
            for(let i = 0; i < photosInput.files.length; i++) { formData.append('photos[]', photosInput.files[i]); }

            submitBtn.disabled = true; submitBtn.textContent = 'Creating...';

            try {
                const response = await fetch('create_job.php', { method: 'POST', body: formData });
                const result = await response.json();

                if (result.status === 'success') {
                    showAlert('Job post created successfully! Redirecting...', 'success');
                    setTimeout(() => window.location.href = 'dashboard.php', 2000);
                } else {
                    showAlert(result.message, 'error');
                    submitBtn.disabled = false; submitBtn.textContent = 'Create Job Post';
                }
            } catch (error) {
                showAlert('Network Error', 'error');
                submitBtn.disabled = false; submitBtn.textContent = 'Create Job Post';
            }
        });

        function showAlert(message, type) {
            const alert = document.getElementById('alert');
            alert.textContent = message; alert.className = `alert alert-${type} show`;
            setTimeout(() => { alert.classList.remove('show'); }, 5000);
        }
    </script>
</body>
</html>
