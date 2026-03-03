<?php
// job_details.php
require_once "config.php";

if (!isAuthenticated()) {
    header("Location: signin.php");
    exit();
}

if (!isset($_GET["id"]) || empty($_GET["id"])) {
    die("Job ID not provided. <a href='dashboard.php'>Return to Dashboard</a>");
}

$jobId = $_GET["id"];
$token = getJWTToken();

// Fetch Profile to see if they are a job seeker
$profileResult = callRustAPI("/profile", "GET", null, $token);
$isSeeker = $profileResult["data"]["is_finding_job"] ?? false;

// Fetch Job
$apiResult = callRustAPI("/job/" . urlencode($jobId), "GET", null, $token);

if (!$apiResult["success"]) {
    die(
        "Failed to load job details. It may have been deleted. <br><br><a href='dashboard.php'>Return to Dashboard</a>"
    );
}

$job = $apiResult["data"];
$hasApplied = $job["has_applied"] ?? false;

function formatExp($months)
{
    if ($months === null || $months === "") {
        return "No prior experience required";
    }
    $years = floor($months / 12);
    $rem_months = $months % 12;
    $parts = [];
    if ($years > 0) {
        $parts[] = "{$years} Years";
    }
    if ($rem_months > 0) {
        $parts[] = "{$rem_months} Months";
    }
    return implode(" ", $parts);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($job["title"]); ?> - Job Details</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; }
        .btn-back { display: inline-block; background: #6c757d; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; margin-bottom: 20px; font-weight: 600; transition: background 0.3s;}
        .btn-back:hover { background: #5a6268; }
        .job-card { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); margin-bottom: 30px; }
        .header-section { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #eee; padding-bottom: 25px; margin-bottom: 25px; flex-wrap: wrap; gap: 20px;}
        .job-info h1 { color: #333; font-size: 32px; margin-bottom: 8px; }
        .employer-link { font-size: 18px; color: #0c5460; font-weight: bold; text-decoration: none; }
        .employer-link:hover { text-decoration: underline; }
        .meta { color: #666; font-size: 15px; margin-top: 10px; display: flex; gap: 15px; flex-wrap: wrap; }
        .meta-item { background: #f8f9fa; padding: 6px 12px; border-radius: 20px; border: 1px solid #e0e0e0; font-weight: 500;}
        .btn-apply { background: #28a745; color: white; border: none; padding: 15px 30px; border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: bold; transition: background 0.3s;}
        .btn-apply:hover:not(:disabled) { background: #218838; }
        .btn-apply:disabled { background: #6c757d; cursor: not-allowed; }
        .section { margin-bottom: 30px; }
        .section h3 { color: #667eea; margin-bottom: 15px; font-size: 20px; border-bottom: 2px solid #f0f0f0; padding-bottom: 5px; display: inline-block;}
        .section p { color: #444; line-height: 1.7; white-space: pre-wrap; }
        .skills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
        .skill-tag { background: #764ba2; color: white; padding: 6px 15px; border-radius: 15px; font-size: 13px; }
        .photo-gallery { display: flex; gap: 15px; overflow-x: auto; padding-bottom: 10px; }
        .photo-gallery img { width: 250px; height: 180px; object-fit: cover; border-radius: 8px; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="container">
        <a href="dashboard.php" class="btn-back">← Back to Dashboard</a>

        <div class="job-card">
            <div class="header-section">
                <div class="job-info">
                    <h1><?php echo htmlspecialchars($job["title"]); ?></h1>
                    <div>
                        🏢
                        <?php if (!empty($job["company_id"])): ?>
                            <a href="company.php?id=<?php echo urlencode(
                                $job["company_id"],
                            ); ?>" class="employer-link">
                                <?php echo htmlspecialchars(
                                    $job["company_name"],
                                ); ?>
                            </a>
                        <?php else: ?>
                            <strong><?php echo htmlspecialchars(
                                $job["company_name"] ?: $job["employer_name"],
                            ); ?></strong>
                        <?php endif; ?>
                    </div>

                    <div class="meta">
                        <?php if (!empty($job["location"])): ?>
                            <span class="meta-item">📍 <?php echo htmlspecialchars(
                                $job["location"],
                            ); ?></span>
                        <?php endif; ?>
                        <?php if (isset($job["salary_range_start"])): ?>
                            <span class="meta-item">💰 $<?php echo number_format(
                                $job["salary_range_start"],
                            ); ?> - $<?php echo number_format(
     $job["salary_range_end"],
 ); ?></span>
                        <?php endif; ?>
                        <span class="meta-item">🎓 Min. Education: <?php echo htmlspecialchars(
                            $job["min_ed_lvl"],
                        ); ?></span>
                    </div>
                </div>

                <div>
                    <?php if ($isSeeker): ?>
                        <?php if ($hasApplied): ?>
                            <button class="btn-apply" disabled>✓ Application Submitted</button>
                        <?php else: ?>
                            <button class="btn-apply" id="apply-btn" onclick="applyForJob('<?php echo htmlspecialchars(
                                $job["id"],
                            ); ?>', '<?php echo htmlspecialchars(
    $job["employer_id"],
); ?>')">Apply Now</button>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>

            <div class="section">
                <h3>About the Role</h3>
                <p><?php echo htmlspecialchars($job["description"]); ?></p>
            </div>

            <div class="section">
                <h3>Requirements</h3>
                <div style="margin-bottom: 15px;">
                    <strong>Minimum Experience:</strong> <?php echo formatExp(
                        $job["min_experience"],
                    ); ?>
                </div>

                <?php if (!empty($job["skills_required"])): ?>
                    <div style="margin-bottom: 10px;"><strong>Skills Needed:</strong></div>
                    <div class="skills">
                        <?php foreach ($job["skills_required"] as $skill): ?>
                            <span class="skill-tag"><?php echo htmlspecialchars(
                                $skill,
                            ); ?></span>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>

            <?php if (!empty($job["photos"])): ?>
            <div class="section">
                <h3>Gallery</h3>
                <div class="photo-gallery">
                    <?php foreach ($job["photos"] as $photo): ?>
                        <a href="<?php echo htmlspecialchars(
                            $photo,
                        ); ?>" target="_blank">
                            <img src="<?php echo htmlspecialchars(
                                $photo,
                            ); ?>" alt="Job Image">
                        </a>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endif; ?>

        </div>
    </div>

    <script>
        async function applyForJob(jobId, employerId) {
            const btn = document.getElementById('apply-btn');
            btn.disabled = true;
            btn.textContent = 'Submitting...';

            try {
                const res = await fetch('apply.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ job_id: jobId, employer_id: employerId })
                });
                const data = await res.json();

                if (data.status === 'success') {
                    btn.textContent = '✓ Application Submitted';
                } else {
                    alert('Failed to apply: ' + data.message);
                    btn.disabled = false;
                    btn.textContent = 'Apply Now';
                }
            } catch (e) {
                alert('Error applying. Please try again later.');
                btn.disabled = false;
                btn.textContent = 'Apply Now';
            }
        }
    </script>
</body>
</html>
