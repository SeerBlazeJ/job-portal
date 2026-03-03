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
        .header { background: white; padding: 20px 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; flex-wrap: wrap; gap: 15px;}
        .header h1 { color: #333; font-size: 28px; }
        .header .user-info { display: flex; align-items: center; gap: 15px; flex-wrap: wrap;}
        .header .username { color: #667eea; font-weight: 600; }
        .logout-btn { background: #dc3545; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 14px; font-weight: 600; transition: background 0.3s; }
        .logout-btn:hover { background: #c82333; }
        .jobs-section { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .jobs-section h2 { color: #333; margin-bottom: 20px; font-size: 24px; }
        .jobs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }

        /* Updated Job Card Styles */
        .job-card { border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; transition: transform 0.2s, box-shadow 0.2s, border-color 0.2s; background: #fafafa; cursor: pointer; }
        .job-card:hover { transform: translateY(-3px); box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1); border-color: #667eea; }
        .job-card h3 { color: #667eea; margin-bottom: 10px; font-size: 20px; }
        .job-card .employer { color: #666; font-size: 14px; margin-bottom: 15px; font-weight: 600; }
        .job-card .details { display: flex; flex-direction: row; gap: 15px; flex-wrap: wrap; }
        .job-card .detail-item { font-size: 13px; color: #666; background: white; padding: 5px 12px; border-radius: 15px; border: 1px solid #ddd; }

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
        .skills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 15px; }
        .skill-tag { background: #667eea; color: white; padding: 5px 12px; border-radius: 15px; font-size: 12px; }
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

                <?php if (!$userProfile["is_finding_job"]): ?>
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
                            <div class="job-card" onclick="window.location.href='job_details.php?id=<?php echo urlencode(
                                $job["id"],
                            ); ?>'">
                                <h3><?php echo htmlspecialchars(
                                    $job["title"],
                                ); ?></h3>
                                <div class="employer">
                                    🏢 <?php echo htmlspecialchars(
                                        $job["company_name"] ?:
                                        $job["employer_name"],
                                    ); ?>
                                </div>

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

                                <?php $workAt =
                                    $candidate["working_at"] ?? []; ?>
                                <?php if (!empty($workAt)): ?>
                                    <?php foreach ($workAt as $comp): ?>
                                        <div style="margin-bottom: 10px; font-size: 0.9rem; border-left: 3px solid #28a745; padding-left: 10px;">
                                            <strong style="color: #28a745;">🏢 Affiliation:</strong><br>
                                            <span style="color: #333; font-weight: 600;">
                                                <?php echo htmlspecialchars(
                                                    $comp["designation"],
                                                ); ?>
                                            </span>
                                            at
                                            <a href="company.php?id=<?php echo urlencode(
                                                $comp["company_id"],
                                            ); ?>" style="color: #0c5460; font-weight: bold; text-decoration: underline;">
                                                <?php echo htmlspecialchars(
                                                    $comp["company_name"],
                                                ); ?>
                                            </a>
                                            <?php if ($comp["is_verified"]): ?>
                                                <span style="color: #28a745; font-size: 10px; margin-left: 5px;">(✓ Verified)</span>
                                            <?php endif; ?>
                                        </div>
                                    <?php endforeach; ?>
                                <?php elseif (
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

                                <?php if (!empty($candidate["about_user"])): ?>
                                    <p style="color: #666; font-size: 0.85rem; margin-bottom: 15px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; font-style: italic;">
                                        "<?php echo htmlspecialchars(
                                            $candidate["about_user"],
                                        ); ?>"
                                    </p>
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
</body>
</html>
