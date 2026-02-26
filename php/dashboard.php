<?php
// dashboard.php
require_once "config.php";

if (!isAuthenticated()) {
    header("Location: signin.php");
    exit();
}

$token = getJWTToken();
$profileResult = callRustAPI("/profile", "GET", null, $token);

if (!$profileResult["success"]) {
    clearJWTCookie();
    header("Location: signin.php");
    exit();
}

$userProfile = $profileResult["data"];
$uid = $userProfile["uid"];
$userName = $userProfile["name"];

$apiResult = callRustAPI("/get-jobs", "POST", null, $token);

$dashboardData = [];
$dashboardMode = "none";

if ($apiResult["success"]) {
    $dashboardMode = $apiResult["data"]["mode"] ?? "none";
    $dashboardData = $apiResult["data"]["payload"] ?? [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Job Portal - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; padding: 20px 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .header h1 { color: #333; font-size: 28px; }
        .header .user-info { display: flex; align-items: center; gap: 20px; }
        .header .username { color: #667eea; font-weight: 600; }
        .logout-btn { background: #dc3545; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 14px; font-weight: 600; transition: background 0.3s; }
        .logout-btn:hover { background: #c82333; }
        .jobs-section { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .jobs-section h2 { color: #333; margin-bottom: 20px; font-size: 24px; }
        .jobs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }
        .job-card { border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; transition: transform 0.2s, box-shadow 0.2s; background: #fafafa; }
        .job-card:hover { transform: translateY(-5px); box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15); }
        .job-card h3 { color: #667eea; margin-bottom: 10px; font-size: 20px; }
        .job-card .employer { color: #666; font-size: 14px; margin-bottom: 10px; font-weight: 600; }
        .job-card .description { color: #555; margin-bottom: 15px; line-height: 1.6; font-size: 14px; }
        .job-card .details { display: flex; flex-direction: column; gap: 8px; margin-bottom: 15px; }
        .job-card .detail-item { font-size: 13px; color: #666; }
        .job-card .detail-item strong { color: #333; }
        .job-card .skills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 15px; }
        .skill-tag { background: #667eea; color: white; padding: 5px 12px; border-radius: 15px; font-size: 12px; }
        .no-jobs { text-align: center; padding: 60px 20px; color: #666; }
        .no-jobs h3 { font-size: 22px; margin-bottom: 10px; }
        .salary { color: #28a745; font-weight: 600; }
        .location { color: #17a2b8; }
        .btn-create-job { background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 14px; font-weight: 600; text-decoration: none; transition: background 0.3s; display: inline-block; }
        .btn-create-job:hover { background: #218838; }
        .candidate-card { border: 1px solid #e0e0e0; border-left: 5px solid #667eea; border-radius: 8px; padding: 20px; background: #fff; transition: transform 0.2s; }
        .candidate-card:hover { transform: translateY(-5px); box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1); }
        .candidate-card h3 { color: #333; font-size: 1.2rem; margin-bottom: 5px; }
        .candidate-card .email { color: #666; font-size: 0.9rem; margin-bottom: 15px; display: block; }
        .section-badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; margin-bottom: 10px; }
        .badge-candidate { background: #e2e8f0; color: #4a5568; }
        .badge-job { background: #c6f6d5; color: #276749; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Job Portal Dashboard</h1>
            <div class="user-info">
                <span class="username">Welcome, <?php echo htmlspecialchars(
                    $userName,
                ); ?>!</span>
                <a href="profile.php" class="btn-create-job">👤 Profile</a>
                <?php if ($dashboardMode === "candidates"): ?>
                <a href="create_job.php" class="btn-create-job">+ Create Job</a>
                <?php endif; ?>
                <form action="logout.php" method="POST" style="margin: 0;">
                    <button type="submit" class="logout-btn">Logout</button>
                </form>
            </div>
        </div>

        <div class="jobs-section">
            <h2>
                <?php if ($dashboardMode === "jobs"): ?>
                    📋 Recommended Jobs For You
                <?php elseif ($dashboardMode === "candidates"): ?>
                    👥 Available Candidates
                <?php else: ?>
                    Dashboard
                <?php endif; ?>
            </h2>

            <?php if (empty($dashboardData)): ?>
                <div class="no-jobs">
                    <h3>No data found</h3>
                    <p>Check back later!</p>
                </div>
            <?php else: ?>
                <div class="jobs-grid">
                    <?php if ($dashboardMode === "jobs"): ?>
                        <?php foreach ($dashboardData as $job): ?>
                            <div class="job-card">
                                <h3><?php echo htmlspecialchars(
                                    $job["title"],
                                ); ?></h3>
                                <div class="employer">
                                    🏢 <a href="user_details.php?id=<?php echo urlencode(
                                        $job["employer_id"] ?? "",
                                    ); ?>" style="text-decoration: none; color: #666; transition: color 0.2s;" onmouseover="this.style.color='#667eea'" onmouseout="this.style.color='#666'">
                                        <?php echo htmlspecialchars(
                                            $job["employer_name"],
                                        ); ?>
                                    </a>
                                </div>
                                <div class="description"><?php echo htmlspecialchars(
                                    $job["description"],
                                ); ?></div>

                                <?php if (!empty($job["photos"])): ?>
                                    <div style="display: flex; gap: 10px; margin-bottom: 15px; overflow-x: auto;">
                                        <?php foreach (
                                            $job["photos"]
                                            as $photo
                                        ): ?>
                                            <img src="<?php echo htmlspecialchars(
                                                $photo,
                                            ); ?>" style="width: 100px; height: 75px; object-fit: cover; border-radius: 5px; border: 1px solid #ddd;">
                                        <?php endforeach; ?>
                                    </div>
                                <?php endif; ?>

                                <div class="details">
                                    <?php if (!empty($job["location"])): ?>
                                        <div class="detail-item location">📍 <?php echo htmlspecialchars(
                                            $job["location"],
                                        ); ?></div>
                                    <?php endif; ?>
                                    <?php if (
                                        isset($job["salary_range_start"])
                                    ): ?>
                                        <div class="detail-item salary">💰 $<?php echo number_format(
                                            $job["salary_range_start"],
                                        ); ?>+</div>
                                    <?php endif; ?>
                                </div>

                                <?php if (!empty($job["skills_required"])): ?>
                                    <div class="skills">
                                        <?php foreach (
                                            $job["skills_required"]
                                            as $skill
                                        ): ?>
                                            <span class="skill-tag"><?php echo htmlspecialchars(
                                                $skill,
                                            ); ?></span>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endif; ?>

                                <div style="margin-top: 20px; text-align: right;">
                                    <?php if (
                                        isset($job["has_applied"]) &&
                                        $job["has_applied"]
                                    ): ?>
                                        <button class="btn-create-job" style="background:#28a745; width:100%; text-align:center; border:none; cursor:default;" disabled>
                                            Applied ✅
                                        </button>
                                    <?php else: ?>
                                        <button class="btn-create-job" style="background:#667eea; width:100%; text-align:center; border:none;" onclick="applyForJob('<?php echo htmlspecialchars(
                                            $job["id"],
                                        ); ?>', '<?php echo htmlspecialchars(
    $job["employer_id"],
); ?>', this)">
                                            Apply Now
                                        </button>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>

                    <?php elseif ($dashboardMode === "candidates"): ?>
                        <?php foreach ($dashboardData as $candidate): ?>
                            <div class="candidate-card">
                                <span class="section-badge badge-candidate">Job Seeker</span>

                                <div style="display: flex; gap: 15px; margin-bottom: 15px; align-items:center;">
                                    <?php if (
                                        !empty($candidate["profile_picture"])
                                    ): ?>
                                        <img src="<?php echo htmlspecialchars(
                                            $candidate["profile_picture"],
                                        ); ?>" style="width: 60px; height: 60px; border-radius: 50%; object-fit: cover; border: 2px solid #667eea;">
                                    <?php else: ?>
                                        <div style="width: 60px; height: 60px; border-radius: 50%; background: #e0e0e0; display: flex; align-items: center; justify-content: center; font-size: 25px;">👤</div>
                                    <?php endif; ?>

                                    <div>
                                        <h3 style="margin-bottom:0;">
                                            <a href="user_details.php?id=<?php echo urlencode(
                                                $candidate["id"],
                                            ); ?>" style="text-decoration: none; color: #333;">
                                                <?php echo htmlspecialchars(
                                                    $candidate["name"],
                                                ); ?>
                                            </a>
                                        </h3>
                                        <span class="email" style="margin-bottom:0;">📧 <?php echo htmlspecialchars(
                                            $candidate["email"],
                                        ); ?></span>
                                    </div>
                                </div>

                                <?php if (
                                    !empty($candidate["current_work"])
                                ): ?>
                                    <div style="margin-bottom: 15px; font-size: 0.9rem;">
                                        <strong style="color: #4a5568;">💼 Current Role:</strong><br>
                                        <span style="color: #666;">
                                            <?php echo htmlspecialchars(
                                                $candidate["current_work"][
                                                    "worked_as"
                                                ],
                                            ); ?>
                                            at <?php echo htmlspecialchars(
                                                $candidate["current_work"][
                                                    "company"
                                                ],
                                            ); ?>
                                        </span>
                                    </div>
                                <?php endif; ?>

                                <?php if (!empty($candidate["education"])): ?>
                                    <div class="details">
                                        <div class="detail-item">
                                            <strong>🎓 Education:</strong>
                                            <?php echo count(
                                                $candidate["education"],
                                            ) . " qualifications listed"; ?>
                                        </div>
                                    </div>
                                <?php endif; ?>

                                <?php if (!empty($candidate["skills"])): ?>
                                    <div class="skills">
                                        <?php foreach (
                                            $candidate["skills"]
                                            as $skill
                                        ): ?>
                                            <span class="skill-tag" style="background: #764ba2;"><?php echo htmlspecialchars(
                                                $skill,
                                            ); ?></span>
                                        <?php endforeach; ?>
                                    </div>
                                <?php else: ?>
                                    <p style="font-size:12px; color:#888; margin-top:10px;">No specific skills listed.</p>
                                <?php endif; ?>

                                <div style="margin-top: 15px;">
                                    <a href="mailto:<?php echo htmlspecialchars(
                                        $candidate["email"],
                                    ); ?>" class="btn-create-job" style="font-size: 12px; padding: 5px 10px;">Contact</a>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        async function applyForJob(jobId, employerId, btnElement) {
            btnElement.disabled = true;
            btnElement.textContent = 'Submitting Application...';

            try {
                const res = await fetch('apply.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ job_id: jobId, employer_id: employerId })
                });
                const data = await res.json();

                if (data.status === 'success') {
                    btnElement.textContent = 'Applied ✅';
                    btnElement.style.background = '#28a745';
                    btnElement.style.cursor = 'default';
                } else {
                    alert('Failed to apply: ' + data.message);
                    btnElement.disabled = false;
                    btnElement.textContent = 'Apply Now';
                }
            } catch (e) {
                alert('Error applying. Please try again later.');
                btnElement.disabled = false;
                btnElement.textContent = 'Apply Now';
            }
        }
    </script>
</body>
</html>
