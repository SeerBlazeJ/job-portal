<?php
// edit_job.php
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

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    header("Content-Type: application/json");
    $jobId = $_POST["job_id"];

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
        "min_experience" => $minExperience,
        "description" => trim($_POST["description"] ?? ""),
        "location" => trim($_POST["location"] ?? ""),
        "min_ed_lvl" => isset($_POST["min_ed_lvl"])
            ? (int) $_POST["min_ed_lvl"]
            : 3,
        "salary_range_start" => !empty($_POST["salary_range_start"])
            ? (int) $_POST["salary_range_start"]
            : null,
        "salary_range_end" => !empty($_POST["salary_range_end"])
            ? (int) $_POST["salary_range_end"]
            : null,
    ];

    // Only attach company_id if it's not empty, allowing Rust to safely parse it as a RecordId
    $compId = trim($_POST["company_id"] ?? "");
    if ($compId !== "") {
        $jobData["company_id"] = $compId;
    }

    $photos = [];
    if (isset($_FILES["photos"])) {
        $uploadDir = "uploads/jobs/";
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0777, true);
        }
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

    $result = callRustAPI("/job/" . urlencode($jobId), "PUT", $jobData, $token);

    if ($result["success"]) {
        echo json_encode([
            "status" => "success",
            "message" => "Job updated successfully!",
        ]);
    } else {
        echo json_encode([
            "status" => "error",
            "message" => $result["message"],
        ]);
    }
    exit();
}

$targetId = $_GET["id"];
$apiResult = callRustAPI("/job/" . urlencode($targetId), "GET", null, $token);
if (!$apiResult["success"]) {
    die("Unauthorized or job not found.");
}
$job = $apiResult["data"];

// SECURITY: Ensure the person viewing this edit page actually owns the job post
$profileResult = callRustAPI("/profile", "GET", null, $token);
if ($job["employer_id"] !== $profileResult["data"]["id"]) {
    die("You do not have permission to edit this job.");
}

$jobMinExp = $job["min_experience"] ?? null;
$expYears = $jobMinExp !== null ? floor($jobMinExp / 12) : "";
$expMonths = $jobMinExp !== null ? $jobMinExp % 12 : "";

$companies = $profileResult["data"]["working_at"] ?? [];
$verifiedCompanies = array_filter($companies, function ($c) {
    return !empty($c["is_verified"]);
});
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Edit Job Post — JobPortal</title>
    <link rel="stylesheet" href="./css/styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="bg-orbs"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>

    <div class="dash-container">
        
        <header class="dash-header">
            <h1 class="dash-title">✏️ Edit Job Post</h1>
            <div class="dash-nav">
                <a href="profile.php" class="dash-btn dash-btn-glass">← Back to Profile</a>
            </div>
        </header>

        <div class="profile-wrapper">
            <h2 class="dash-section-title" style="margin-bottom: 2rem;">Updating: <?php echo htmlspecialchars($job["title"]); ?></h2>
            <div id="alert" class="profile-alert"></div>

            <form id="job-form" enctype="multipart/form-data">
                <input type="hidden" id="job_id" value="<?php echo htmlspecialchars($job["id"]); ?>">

                <div class="form-group" style="margin-bottom: 1.5rem;">
                    <label class="form-label">Job Title *</label>
                    <input type="text" id="title" class="form-input" style="padding-left: 1rem;" required value="<?php echo htmlspecialchars($job["title"]); ?>">
                </div>

                <div class="form-grid-2">
                    <div class="form-group">
                        <label class="form-label">Company *</label>
                        <?php if (empty($verifiedCompanies)): ?>
                            <div class="warning-box">⚠️ Verification Required.</div>
                            <select id="company_select" class="form-input" style="padding-left: 1rem;" disabled required><option value="">No verified companies</option></select>
                        <?php else: ?>
                            <select id="company_select" class="form-input" style="padding-left: 1rem;" required>
                                <option value="">-- Select Company --</option>
                                <?php foreach ($verifiedCompanies as $comp): ?>
                                    <option value="<?php echo htmlspecialchars($comp["company_id"]); ?>" data-name="<?php echo htmlspecialchars($comp["company_name"]); ?>" <?php echo ($job["company_id"] ?? "") === $comp["company_id"] ? "selected" : ""; ?>>
                                        <?php echo htmlspecialchars($comp["company_name"]); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        <?php endif; ?>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Minimum Experience</label>
                        <div style="display: flex; gap: 1rem;">
                            <input type="number" id="min_exp_years" class="form-input" style="padding-left: 1rem; flex: 1;" placeholder="Years" min="0" value="<?php echo htmlspecialchars($expYears); ?>">
                            <input type="number" id="min_exp_months" class="form-input" style="padding-left: 1rem; flex: 1;" placeholder="Months" min="0" max="11" value="<?php echo htmlspecialchars($expMonths); ?>">
                        </div>
                    </div>
                </div>

                <div class="form-group" style="margin-bottom: 1.5rem;">
                    <label class="form-label">Job Description *</label>
                    <textarea id="description" class="form-input" required><?php echo htmlspecialchars($job["description"]); ?></textarea>
                </div>

                <div class="form-grid-2">
                    <div class="form-group">
                        <label class="form-label">Location *</label>
                        <input type="text" id="location" class="form-input" style="padding-left: 1rem;" required value="<?php echo htmlspecialchars($job["location"]); ?>">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Minimum Education Level *</label>
                        <?php $currentLvl = is_numeric($job["min_ed_lvl"]) ? $job["min_ed_lvl"] : 3; ?>
                        <select id="min_ed_lvl" class="form-input" style="padding-left: 1rem;" required>
                            <option value="1" <?php echo $currentLvl == 1 ? "selected" : ""; ?>>High School</option>
                            <option value="2" <?php echo $currentLvl == 2 ? "selected" : ""; ?>>Diploma</option>
                            <option value="3" <?php echo $currentLvl == 3 ? "selected" : ""; ?>>Bachelor's Degree</option>
                            <option value="4" <?php echo $currentLvl == 4 ? "selected" : ""; ?>>Master's Degree</option>
                            <option value="5" <?php echo $currentLvl == 5 ? "selected" : ""; ?>>PhD/Doctorate</option>
                        </select>
                    </div>
                </div>

                <div class="form-grid-2">
                    <div class="form-group">
                        <label class="form-label">Salary Range Start ($)</label>
                        <input type="number" id="salary_start" class="form-input" style="padding-left: 1rem;" value="<?php echo htmlspecialchars($job["salary_range_start"] ?? ""); ?>">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Salary Range End ($)</label>
                        <input type="number" id="salary_end" class="form-input" style="padding-left: 1rem;" value="<?php echo htmlspecialchars($job["salary_range_end"] ?? ""); ?>">
                    </div>
                </div>

                <div class="form-group" style="margin-bottom: 2rem;">
                    <label class="form-label">Add Additional Photos</label>
                    <input type="file" id="photos" name="photos[]" accept="image/*" multiple class="form-input">
                </div>

                <button type="submit" class="dash-btn dash-btn-primary" id="submit-btn" style="width: 100%; justify-content: center; font-size: 1rem; padding: 1rem;" <?php echo empty($verifiedCompanies) ? "disabled" : ""; ?>>
                    💾 Save Changes
                </button>
            </form>
        </div>
    </div>

    <script>
        document.getElementById('job-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('submit-btn');
            const alertBox = document.getElementById('alert');

            const compSelect = document.getElementById('company_select');
            const selectedComp = compSelect.options[compSelect.selectedIndex];

            const fd = new FormData();
            fd.append('job_id', document.getElementById('job_id').value);
            fd.append('title', document.getElementById('title').value.trim());
            fd.append('company_id', selectedComp.value);
            fd.append('company_name', selectedComp.getAttribute('data-name'));

            if (document.getElementById('min_exp_years').value !== "") {
                fd.append('min_exp_years', document.getElementById('min_exp_years').value);
            }
            if (document.getElementById('min_exp_months').value !== "") {
                fd.append('min_exp_months', document.getElementById('min_exp_months').value);
            }

            fd.append('description', document.getElementById('description').value.trim());
            fd.append('location', document.getElementById('location').value.trim());
            fd.append('min_ed_lvl', document.getElementById('min_ed_lvl').value);

            if (document.getElementById('salary_start').value) fd.append('salary_range_start', document.getElementById('salary_start').value);
            if (document.getElementById('salary_end').value) fd.append('salary_range_end', document.getElementById('salary_end').value);

            const photosInput = document.getElementById('photos');
            for(let i = 0; i < photosInput.files.length; i++) { fd.append('photos[]', photosInput.files[i]); }

            btn.disabled = true; btn.innerHTML = '⏳ Saving...';
            alertBox.classList.remove('show');

            try {
                const res = await fetch('edit_job.php', { method: 'POST', body: fd });
                const result = await res.json();

                alertBox.innerHTML = `<span>${result.status === 'success' ? '✓' : '⚠️'}</span> ${result.message}`;
                alertBox.className = `profile-alert alert-${result.status === 'success' ? 'success' : 'error'} show`;

                if (result.status === 'success') {
                    setTimeout(() => window.location.href = 'profile.php', 1000);
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