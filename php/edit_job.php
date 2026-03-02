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

// Handle Form Submission
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    header("Content-Type: application/json");
    $jobId = $_POST["job_id"];

    $eduLevelMap = [
        1 => "HighSchool",
        2 => "Diploma",
        3 => "Bachelors",
        4 => "Masters",
        5 => "PhD",
    ];

    $jobData = [
        "title" => trim($_POST["title"] ?? ""),
        "description" => trim($_POST["description"] ?? ""),
        "location" => trim($_POST["location"] ?? ""),
        // "min_ed_lvl" => $eduLevelMap[$_POST["min_ed_lvl"] ?? 3] ?? "Bachelors",
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

// Fetch Job Data to pre-fill the form
$targetId = $_GET["id"];
$apiResult = callRustAPI("/job/" . urlencode($targetId), "GET", null, $token);

if (!$apiResult["success"]) {
    die("Unauthorized or job not found. <br><a href='profile.php'>Go Back</a>");
}
$job = $apiResult["data"];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Job Post</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .btn-secondary { padding: 10px 20px; background: #6c757d; color: white; border-radius: 5px; text-decoration: none; font-weight: 600; display: inline-block; margin-bottom: 20px;}
        .form-group { margin-bottom: 25px; }
        .form-group label { display: block; color: #333; font-weight: 600; margin-bottom: 8px; font-size: 14px; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 5px; font-size: 14px; font-family: inherit;}
        .form-group textarea { min-height: 120px; resize: vertical; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .btn-primary { background: #667eea; color: white; width: 100%; padding: 15px; font-size: 16px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
        .alert { padding: 15px; border-radius: 5px; margin-bottom: 20px; display: none; font-weight: 500;}
        .alert.show { display: block; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="container">
        <h2>✏️ Edit Job: <?php echo htmlspecialchars($job["title"]); ?></h2>
        <a href="profile.php" class="btn-secondary">← Back to Profile</a>

        <div id="alert" class="alert"></div>

        <form id="job-form" enctype="multipart/form-data">
            <input type="hidden" id="job_id" name="job_id" value="<?php echo htmlspecialchars(
                $job["id"],
            ); ?>">

            <div class="form-group">
                <label>Job Title *</label>
                <input type="text" id="title" required value="<?php echo htmlspecialchars(
                    $job["title"],
                ); ?>">
            </div>

            <div class="form-group">
                <label>Job Description *</label>
                <textarea id="description" required><?php echo htmlspecialchars(
                    $job["description"],
                ); ?></textarea>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label>Location *</label>
                    <input type="text" id="location" required value="<?php echo htmlspecialchars(
                        $job["location"],
                    ); ?>">
                </div>
                <div class="form-group">
                    <label>Minimum Education Level *</label>
                    <?php $currentLvl = is_numeric($job["min_ed_lvl"])
                        ? $job["min_ed_lvl"]
                        : 3; ?>
                    <select id="min_ed_lvl" required>
                        <option value="1" <?php echo $currentLvl == 1
                            ? "selected"
                            : ""; ?>>High School</option>
                        <option value="2" <?php echo $currentLvl == 2
                            ? "selected"
                            : ""; ?>>Diploma</option>
                        <option value="3" <?php echo $currentLvl == 3
                            ? "selected"
                            : ""; ?>>Bachelor's Degree</option>
                        <option value="4" <?php echo $currentLvl == 4
                            ? "selected"
                            : ""; ?>>Master's Degree</option>
                        <option value="5" <?php echo $currentLvl == 5
                            ? "selected"
                            : ""; ?>>PhD/Doctorate</option>
                    </select>
                </div>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label>Salary Range Start ($)</label>
                    <input type="number" id="salary_start" value="<?php echo htmlspecialchars(
                        $job["salary_range_start"] ?? "",
                    ); ?>">
                </div>
                <div class="form-group">
                    <label>Salary Range End ($)</label>
                    <input type="number" id="salary_end" value="<?php echo htmlspecialchars(
                        $job["salary_range_end"] ?? "",
                    ); ?>">
                </div>
            </div>

            <div class="form-group">
                <label>Add Additional Photos (Uploads will merge with existing)</label>
                <input type="file" id="photos" name="photos[]" accept="image/*" multiple>
            </div>

            <button type="submit" class="btn-primary" id="submit-btn">Save Changes</button>
        </form>
    </div>

    <script>
        document.getElementById('job-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('submit-btn');
            const alertBox = document.getElementById('alert');

            const fd = new FormData();
            fd.append('job_id', document.getElementById('job_id').value);
            fd.append('title', document.getElementById('title').value.trim());
            fd.append('description', document.getElementById('description').value.trim());
            fd.append('location', document.getElementById('location').value.trim());
            fd.append('min_ed_lvl', document.getElementById('min_ed_lvl').value);

            if (document.getElementById('salary_start').value) fd.append('salary_range_start', document.getElementById('salary_start').value);
            if (document.getElementById('salary_end').value) fd.append('salary_range_end', document.getElementById('salary_end').value);

            const photosInput = document.getElementById('photos');
            if (photosInput.files.length > 0) {
                for(let i = 0; i < photosInput.files.length; i++) {
                    fd.append('photos[]', photosInput.files[i]);
                }
            }

            btn.disabled = true; btn.textContent = 'Saving...';
            alertBox.className = 'alert';

            try {
                const res = await fetch('edit_job.php', { method: 'POST', body: fd });
                const result = await res.json();

                alertBox.textContent = result.message;
                alertBox.className = `alert alert-${result.status === 'success' ? 'success' : 'error'} show`;

                if (result.status === 'success') {
                    setTimeout(() => window.location.href = 'profile.php', 1000);
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
