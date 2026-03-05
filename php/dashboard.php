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
    <title>JobPortal — Dashboard</title>
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
            <h1 class="dash-title">
                <svg width="28" height="28" viewBox="0 0 32 32" fill="none" style="color:var(--indigo-400);filter:drop-shadow(0 0 10px rgba(99,102,241,0.6));">
                    <path d="M16 4L4 10V22L16 28L28 22V10L16 4Z" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M16 16L4 10M16 16V28M16 16L28 10" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                JobPortal
            </h1>

            <div class="dash-nav">
                <form action="search.php" method="GET" style="margin-right: auto; margin-left: 2rem;">
                        <input type="text" name="q" class="search-header-input" placeholder="Search jobs, companies, users...">
                    </form>
                <span class="dash-welcome">Welcome, <strong><?php echo htmlspecialchars(
                    $userName,
                ); ?></strong></span>

                <a href="profile.php" class="dash-btn dash-btn-glass">👤 Profile</a>

                <?php if (!$userProfile["is_finding_job"]): ?>
                    <a href="create_job.php" class="dash-btn dash-btn-primary">+ Create Job</a>
                <?php endif; ?>

                <form action="logout.php" method="POST" style="margin: 0;">
                    <button type="submit" class="dash-btn dash-btn-danger">Logout</button>
                </form>
            </div>
        </header>

        <main>
            <h2 class="dash-section-title">
                <?php if ($dashboardMode === "jobs"): ?>
                    ✨ Recommended For You
                <?php elseif ($dashboardMode === "candidates"): ?>
                    👥 Available Candidates
                <?php else: ?>
                    Dashboard
                <?php endif; ?>
            </h2>

            <?php if (empty($dashboardData)): ?>
                <div class="dash-empty">
                    <h3>No matches found yet</h3>
                    <p>We're looking for the best fit. Check back later!</p>
                </div>
            <?php else: ?>
                <div class="dash-grid">

                    <?php if ($dashboardMode === "jobs"): ?>
                        <?php foreach ($dashboardData as $job): ?>
                            <div class="dash-card dash-card-job" onclick="window.location.href='job_details.php?id=<?php echo urlencode(
                                $job["id"],
                            ); ?>'">
                                <h3 class="card-title"><?php echo htmlspecialchars(
                                    $job["title"],
                                ); ?></h3>
                                <div class="card-subtitle">
                                    🏢 <?php echo htmlspecialchars(
                                        $job["company_name"] ?:
                                        $job["employer_name"],
                                    ); ?>
                                </div>

                                <div class="card-tags">
                                    <?php if (!empty($job["location"])): ?>
                                        <span class="dash-badge badge-location">📍 <?php echo htmlspecialchars(
                                            $job["location"],
                                        ); ?></span>
                                    <?php endif; ?>

                                    <?php if (
                                        isset($job["salary_range_start"])
                                    ): ?>
                                        <span class="dash-badge badge-salary">💰 $<?php echo number_format(
                                            $job["salary_range_start"],
                                        ); ?>+</span>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>

                    <?php elseif ($dashboardMode === "candidates"): ?>
                        <?php foreach ($dashboardData as $candidate): ?>
                            <div class="dash-card">
                                <span class="dash-badge badge-role">Job Seeker</span>

                                <div class="candidate-header">
                                    <?php if (
                                        !empty($candidate["profile_picture"])
                                    ): ?>
                                        <img src="<?php echo htmlspecialchars(
                                            $candidate["profile_picture"],
                                        ); ?>" class="candidate-avatar" alt="Avatar">
                                    <?php else: ?>
                                        <div class="candidate-avatar">👤</div>
                                    <?php endif; ?>

                                    <div>
                                        <h3 class="card-title">
                                            <a href="user_details.php?id=<?php echo urlencode(
                                                $candidate["id"],
                                            ); ?>">
                                                <?php echo htmlspecialchars(
                                                    $candidate["name"],
                                                ); ?>
                                            </a>
                                        </h3>
                                        <span class="candidate-email">📧 <?php echo htmlspecialchars(
                                            $candidate["email"],
                                        ); ?></span>
                                    </div>
                                </div>

                                <?php $workAt =
                                    $candidate["working_at"] ?? []; ?>
                                <?php if (!empty($workAt)): ?>
                                    <?php foreach ($workAt as $comp): ?>
                                        <div class="candidate-block" style="border-left-color: var(--emerald-400);">
                                            <span class="candidate-block-title">🏢 Affiliation</span>
                                            <span class="candidate-block-value">
                                                <strong><?php echo htmlspecialchars(
                                                    $comp["designation"],
                                                ); ?></strong> at
                                                <a href="company.php?id=<?php echo urlencode(
                                                    $comp["company_id"],
                                                ); ?>"><?php echo htmlspecialchars(
    $comp["company_name"],
); ?></a>
                                                <?php if (
                                                    $comp["is_verified"]
                                                ): ?>
                                                    <span class="candidate-verified">✓ Verified</span>
                                                <?php endif; ?>
                                            </span>
                                        </div>
                                    <?php endforeach; ?>
                                <?php elseif (
                                    !empty($candidate["current_work"])
                                ): ?>
                                    <div class="candidate-block">
                                        <span class="candidate-block-title">💼 Current Role</span>
                                        <span class="candidate-block-value">
                                            <?php echo htmlspecialchars(
                                                $candidate["current_work"][
                                                    "worked_as"
                                                ],
                                            ); ?> at
                                            <strong><?php echo htmlspecialchars(
                                                $candidate["current_work"][
                                                    "company"
                                                ],
                                            ); ?></strong>
                                        </span>
                                    </div>
                                <?php endif; ?>

                                <?php if (!empty($candidate["about_user"])): ?>
                                    <p class="candidate-about">"<?php echo htmlspecialchars(
                                        $candidate["about_user"],
                                    ); ?>"</p>
                                <?php endif; ?>

                                <?php if (!empty($candidate["skills"])): ?>
                                    <div class="card-tags">
                                        <?php foreach (
                                            $candidate["skills"]
                                            as $skill
                                        ): ?>
                                            <span class="dash-badge badge-skill"><?php echo htmlspecialchars(
                                                $skill,
                                            ); ?></span>
                                        <?php endforeach; ?>
                                    </div>
                                <?php else: ?>
                                    <p class="candidate-about" style="margin-bottom:0; font-style:normal;">No skills listed.</p>
                                <?php endif; ?>

                                <div class="candidate-footer">
                                    <span class="candidate-edu">
                                        <?php if (
                                            !empty($candidate["education"])
                                        ): ?>
                                            🎓 <?php echo count(
                                                $candidate["education"],
                                            ) . " qualifications"; ?>
                                        <?php endif; ?>
                                    </span>
                                    <a href="mailto:<?php echo htmlspecialchars(
                                        $candidate["email"],
                                    ); ?>" class="dash-btn dash-btn-primary" style="padding: 0.4rem 1rem;">Contact</a>
                                </div>

                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>

                </div>
            <?php endif; ?>
        </main>
    </div>
</body>
</html>
