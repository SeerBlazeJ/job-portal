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
    <title><?php echo htmlspecialchars($job["title"]); ?> — Job Details</title>
    <link rel="stylesheet" href="./css/styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="bg-orbs"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>

    <div class="dash-container">
        <header class="dash-header">
            <h1 class="dash-title">Job Details</h1>
            <div class="dash-nav">
                <a href="dashboard.php" class="dash-btn dash-btn-glass">← Back to Dashboard</a>
            </div>
        </header>

        <div class="profile-wrapper">
            <div class="details-header">
                <div>
                    <h1 class="details-title"><?php echo htmlspecialchars($job["title"]); ?></h1>
                    <div style="font-size: 1.1rem; margin-bottom: 1rem;">
                        🏢
                        <?php if (!empty($job["company_id"])): ?>
                            <a href="company.php?id=<?php echo urlencode($job["company_id"]); ?>" style="color: var(--cyan-400); font-weight: bold; text-decoration: none;">
                                <?php echo htmlspecialchars($job["company_name"]); ?>
                            </a>
                        <?php else: ?>
                            <strong style="color: var(--text-primary);"><?php echo htmlspecialchars($job["company_name"] ?: $job["employer_name"]); ?></strong>
                        <?php endif; ?>
                    </div>

                    <div class="card-tags">
                        <?php if (!empty($job["location"])): ?>
                            <span class="dash-badge badge-location">📍 <?php echo htmlspecialchars($job["location"]); ?></span>
                        <?php endif; ?>
                        <?php if (isset($job["salary_range_start"])): ?>
                            <span class="dash-badge badge-salary">💰 $<?php echo number_format($job["salary_range_start"]); ?> - $<?php echo number_format($job["salary_range_end"]); ?></span>
                        <?php endif; ?>
                        <span class="dash-badge badge-role">🎓 Min. Education: <?php echo htmlspecialchars($job["min_ed_lvl"]); ?></span>
                    </div>
                </div>

                <div>
                    <?php if ($isSeeker): ?>
                        <?php if ($hasApplied): ?>
                            <button class="dash-btn dash-btn-glass" disabled style="color: var(--emerald-400); border-color: rgba(16,185,129,0.3); background: rgba(16,185,129,0.1);">✓ Application Submitted</button>
                        <?php else: ?>
                            <button class="dash-btn dash-btn-primary" id="apply-btn" onclick="applyForJob('<?php echo htmlspecialchars($job["id"]); ?>', '<?php echo htmlspecialchars($job["employer_id"]); ?>')">🚀 Apply Now</button>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>

            <div class="profile-section">
                <h3>📝 About the Role</h3>
                <div style="background: rgba(99,102,241,0.02); padding: 1.5rem; border-radius: var(--r-md); border: 1px solid rgba(99,102,241,0.08);">
                    <p style="color: var(--text-main); line-height: 1.7; white-space: pre-wrap;"><?php echo htmlspecialchars($job["description"]); ?></p>
                </div>
            </div>

            <div class="profile-section">
                <h3>⚙️ Requirements</h3>
                <div class="dynamic-list-item">
                    <div style="margin-bottom: 1rem; font-size: 0.95rem; color: var(--text-secondary);">
                        <strong style="color: var(--text-primary);">Minimum Experience:</strong> <?php echo formatExp($job["min_experience"]); ?>
                    </div>

                    <?php if (!empty($job["skills_required"])): ?>
                        <div style="margin-bottom: 0.5rem; font-size: 0.95rem; color: var(--text-primary);"><strong>Skills Needed:</strong></div>
                        <div class="card-tags">
                            <?php foreach ($job["skills_required"] as $skill): ?>
                                <span class="dash-badge badge-skill"><?php echo htmlspecialchars($skill); ?></span>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <?php if (!empty($job["photos"])): ?>
            <div class="profile-section">
                <h3>🖼️ Gallery</h3>
                <div class="job-gallery">
                    <?php foreach ($job["photos"] as $photo): ?>
                        <a href="<?php echo htmlspecialchars($photo); ?>" target="_blank">
                            <img src="<?php echo htmlspecialchars($photo); ?>" alt="Job Image">
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
            btn.innerHTML = '⏳ Submitting...';

            try {
                const res = await fetch('apply.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ job_id: jobId, employer_id: employerId })
                });
                const data = await res.json();

                if (data.status === 'success') {
                    btn.innerHTML = '✓ Application Submitted';
                    btn.className = 'dash-btn dash-btn-glass';
                    btn.style.color = 'var(--emerald-400)';
                    btn.style.borderColor = 'rgba(16,185,129,0.3)';
                    btn.style.background = 'rgba(16,185,129,0.1)';
                } else {
                    alert('Failed to apply: ' + data.message);
                    btn.disabled = false;
                    btn.innerHTML = '🚀 Apply Now';
                }
            } catch (e) {
                alert('Error applying. Please try again later.');
                btn.disabled = false;
                btn.innerHTML = '🚀 Apply Now';
            }
        }
    </script>
</body>
</html>