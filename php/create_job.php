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

    // FIX: Properly split comma-separated strings into arrays
    $skills_raw = $_POST["skills_required"] ?? "";
    if (!empty(trim($skills_raw))) {
        $jobData["skills_required"] = array_values(
            array_filter(array_map("trim", explode(",", $skills_raw))),
        );
    }

    $majors_raw = $_POST["majors_accepted"] ?? "";
    if (!empty(trim($majors_raw))) {
        $jobData["majors_accepted"] = array_values(
            array_filter(array_map("trim", explode(",", $majors_raw))),
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
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Job Post — JobPortal</title>
    <link rel="stylesheet" href="./css/styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>

    <div class="bg-orbs">
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
        <div class="orb orb-3"></div>
    </div>

    <div class="dash-container">

        <header class="dash-header">
            <h1 class="dash-title">📝 Create Job Post</h1>
            <div class="dash-nav">
                <a href="dashboard.php" class="dash-btn dash-btn-glass">← Back to Dashboard</a>
            </div>
        </header>

        <div class="profile-wrapper">
            <div id="alert" class="profile-alert"></div>

            <form id="job-form" enctype="multipart/form-data">

                <div class="form-group" style="margin-bottom: 1.25rem;">
                    <label class="form-label">Job Photos</label>
                    <input type="file" id="photos" name="photos[]" accept="image/*" multiple class="form-input">
                </div>

                <div class="form-group" style="margin-bottom: 1.25rem;">
                    <label class="form-label">Job Title *</label>
                    <input type="text" id="title" class="form-input" required placeholder="e.g., Senior Software Engineer" style="padding-left: 1rem;">
                </div>

                <div class="form-grid-2">
                    <div class="form-group">
                        <label class="form-label">Company *</label>
                        <?php if (empty($verifiedCompanies)): ?>
                            <div class="warning-box">
                                ⚠️ You must be a verified employee to post jobs.
                            </div>
                            <select id="company_select" class="form-input" disabled required style="padding-left: 1rem;">
                                <option value="">No verified companies</option>
                            </select>
                        <?php else: ?>
                            <select id="company_select" class="form-input" required style="padding-left: 1rem;">
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
                        <label class="form-label">Minimum Experience</label>
                        <div style="display: flex; gap: 1rem;">
                            <input type="number" id="min_exp_years" class="form-input" placeholder="Years" min="0" style="flex: 1; padding-left: 1rem;">
                            <input type="number" id="min_exp_months" class="form-input" placeholder="Months" min="0" max="11" style="flex: 1; padding-left: 1rem;">
                        </div>
                    </div>
                </div>

                <div class="form-group" style="margin-bottom: 1.25rem;">
                    <label class="form-label">Job Description *</label>
                    <textarea id="description" class="form-input" required placeholder="Describe the role, responsibilities, and perks..."></textarea>
                </div>

                <div class="form-grid-2" style="margin-bottom: 1.25rem;">
                    <div class="form-group">
                        <label class="form-label">Skills Required (Comma separated)</label>
                        <input type="text" id="skills_required" class="form-input" placeholder="e.g. Rust, Python, React" style="padding-left: 1rem;">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Majors Accepted (Comma separated)</label>
                        <input type="text" id="majors_accepted" class="form-input" placeholder="e.g. Computer Science, IT" style="padding-left: 1rem;">
                    </div>
                </div>

                <div class="form-grid-2">
                    <div class="form-group">
                        <label class="form-label">Location *</label>
                        <input type="text" id="location" class="form-input" required placeholder="e.g., Remote or New York, NY" style="padding-left: 1rem;">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Minimum Education Level *</label>
                        <select id="min_ed_lvl" class="form-input" required style="padding-left: 1rem;">
                            <option value="">Select education level</option>
                            <option value="1">High School</option>
                            <option value="2">Diploma</option>
                            <option value="3" selected>Bachelor's Degree</option>
                            <option value="4">Master's Degree</option>
                            <option value="5">PhD/Doctorate</option>
                        </select>
                    </div>
                </div>

                <div class="form-grid-2">
                    <div class="form-group">
                        <label class="form-label">Salary Range Start ($)</label>
                        <input type="number" id="salary_start" class="form-input" min="0" placeholder="e.g., 60000" style="padding-left: 1rem;">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Salary Range End ($)</label>
                        <input type="number" id="salary_end" class="form-input" min="0" placeholder="e.g., 120000" style="padding-left: 1rem;">
                    </div>
                </div>

                <div class="form-group" style="margin-bottom: 2rem;">
                    <label class="form-label">Application Deadline *</label>
                    <input type="datetime-local" id="datetime_due" class="form-input" required style="padding-left: 1rem;">
                </div>

                <button type="submit" class="dash-btn dash-btn-primary" id="submit-btn" style="width: 100%; justify-content: center; font-size: 1rem; padding: 1rem;" <?php echo empty(
                    $verifiedCompanies
                )
                    ? "disabled"
                    : ""; ?>>
                    🚀 Create Job Post
                </button>
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

            // Append the new skills and majors fields
            formData.append('skills_required', document.getElementById('skills_required').value.trim());
            formData.append('majors_accepted', document.getElementById('majors_accepted').value.trim());

            formData.append('location', document.getElementById('location').value.trim());
            formData.append('min_ed_lvl', document.getElementById('min_ed_lvl').value);

            if (document.getElementById('salary_start').value) formData.append('salary_range_start', document.getElementById('salary_start').value);
            if (document.getElementById('salary_end').value) formData.append('salary_range_end', document.getElementById('salary_end').value);

            formData.append('datetime_due', new Date(document.getElementById('datetime_due').value).toISOString());

            const photosInput = document.getElementById('photos');
            for(let i = 0; i < photosInput.files.length; i++) { formData.append('photos[]', photosInput.files[i]); }

            submitBtn.disabled = true; submitBtn.innerHTML = '⏳ Creating...';

            try {
                const response = await fetch('create_job.php', { method: 'POST', body: formData });
                const result = await response.json();

                if (result.status === 'success') {
                    showAlert('Job post created successfully! Redirecting...', 'success');
                    setTimeout(() => window.location.href = 'dashboard.php', 2000);
                } else {
                    showAlert(result.message, 'error');
                    submitBtn.disabled = false; submitBtn.innerHTML = '🚀 Create Job Post';
                }
            } catch (error) {
                showAlert('Network Error', 'error');
                submitBtn.disabled = false; submitBtn.innerHTML = '🚀 Create Job Post';
            }
        });

        function showAlert(message, type) {
            const alertBox = document.getElementById('alert');
            alertBox.innerHTML = `<span>${type === 'success' ? '✓' : '⚠️'}</span> ${message}`;
            alertBox.className = `profile-alert alert-${type} show`;
            setTimeout(() => { alertBox.classList.remove('show'); }, 5000);
        }
    </script>
</body>
</html>
