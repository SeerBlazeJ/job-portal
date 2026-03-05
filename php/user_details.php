<?php
// user_details.php
require_once "config.php";

if (!isAuthenticated()) {
    header("Location: signin.php");
    exit();
}

if (!isset($_GET["id"]) || empty($_GET["id"])) {
    die(
        "User ID not provided. <a href='dashboard.php'>Return to Dashboard</a>"
    );
}

function formatExp($months)
{
    if ($months === null || $months === "") {
        return "N/A";
    }
    $months = (int) $months;
    $years = floor($months / 12);
    $rem_months = $months % 12;
    $parts = [];
    if ($years > 0) {
        $parts[] = "{$years}y";
    }
    if ($rem_months > 0) {
        $parts[] = "{$rem_months}m";
    }
    return empty($parts) ? "0m" : implode(" ", $parts);
}

$targetId = $_GET["id"];
$token = getJWTToken();

$apiResult = callRustAPI(
    "/user-profile/" . urlencode($targetId),
    "GET",
    null,
    $token,
);

if (!$apiResult["success"]) {
    die(
        "Failed to load user profile. Check if the user exists. <br><br><a href='dashboard.php'>Return to Dashboard</a>"
    );
}

$profile = $apiResult["data"];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($profile["name"]); ?> — Profile</title>
    <link rel="stylesheet" href="./css/styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="bg-orbs"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>

    <div class="dash-container">
        <header class="dash-header">
            <h1 class="dash-title">Candidate Profile</h1>
            <div class="dash-nav">
                <a href="dashboard.php" class="dash-btn dash-btn-glass">← Back to Dashboard</a>
            </div>
        </header>

        <div class="profile-wrapper">
            <div class="details-header" style="align-items: center;">
                <div style="display: flex; gap: 1.5rem; align-items:center;">
                    <?php if (!empty($profile["profile_picture"])): ?>
                        <img src="<?php echo htmlspecialchars(
                            $profile["profile_picture"],
                        ); ?>" style="width: 90px; height: 90px; border-radius: 50%; object-fit: cover; border: 3px solid var(--indigo-500); background: rgba(99,102,241,0.1);">
                    <?php else: ?>
                        <div style="width: 90px; height: 90px; border-radius: 50%; background: rgba(99,102,241,0.1); border: 1px solid rgba(99,102,241,0.3); display: flex; align-items: center; justify-content: center; font-size: 2.5rem;">👤</div>
                    <?php endif; ?>

                    <div>
                        <h1 class="details-title" style="font-size: 1.8rem; margin-bottom: 0.2rem;"><?php echo htmlspecialchars(
                            $profile["name"],
                        ); ?></h1>
                        <div style="color: var(--text-muted); font-size: 0.95rem; font-weight: 500;">📧 <?php echo htmlspecialchars(
                            $profile["email"],
                        ); ?></div>
                    </div>
                </div>

                <div class="dash-card">
                                    <script>
                                    async function startChat(targetUid, targetName) {
                                        const res = await fetch('chat_api.php?action=init', {
                                            method: 'POST',
                                            headers: { 'Content-Type': 'application/json' },
                                            body: JSON.stringify({ target_uid: targetUid })
                                        });
                                        const data = await res.json();
                                        if(data.success) {
                                            window.location.href = `chat.php?session=${data.data}&name=${encodeURIComponent(targetName || '')}`;
                                        } else {
                                            alert('Could not start chat: ' + data.message);
                                        }
                                    }
                                    </script>

                                    <button onclick="startChat('<?php echo htmlspecialchars(
                                        $profile["uid"],
                                    ); ?>', '<?php echo addslashes(
    htmlspecialchars($profile["name"]),
); ?>')" class="dash-btn dash-btn-primary" style="margin-top: 1rem;">
                                        💬 Message User
                                    </button>
                                </div>

                <div style="text-align: right; display: flex; flex-direction: column; gap: 0.8rem; align-items: flex-end;">
                    <?php if ($profile["is_finding_job"]): ?>
                        <span class="dash-badge badge-role">🔍 Job Seeker</span>
                    <?php else: ?>
                        <span class="dash-badge badge-salary" style="color: var(--amber-400); border-color: rgba(245,158,11,0.3); background: rgba(245,158,11,0.1);">📢 Employer</span>
                    <?php endif; ?>

                    <?php if (!empty($profile["resume"])): ?>
                        <a href="<?php echo htmlspecialchars(
                            $profile["resume"],
                        ); ?>" download class="dash-btn dash-btn-glass" style="color: var(--emerald-400); border-color: rgba(16,185,129,0.3);">📄 View Resume</a>
                    <?php endif; ?>
                </div>
            </div>

            <?php if (!empty($profile["working_at"])): ?>
                <div class="dynamic-list-item" style="border-left-color: var(--emerald-500); background: rgba(16,185,129,0.05); margin-bottom: 2rem;">
                    <h4 style="margin: 0 0 10px; color: var(--emerald-400);">🏢 Company Affiliations</h4>
                    <?php foreach ($profile["working_at"] as $comp): ?>
                        <div style="font-size: 0.9rem; color: var(--text-main); display: flex; align-items: center; flex-wrap: wrap; margin-bottom: 8px;">
                            <strong><?php echo htmlspecialchars(
                                $comp["designation"],
                            ); ?></strong>
                            &nbsp;at&nbsp;
                            <a href="company.php?id=<?php echo urlencode(
                                $comp["company_id"],
                            ); ?>" style="color: var(--cyan-400); font-weight: bold; text-decoration: none;">
                                <?php echo htmlspecialchars(
                                    $comp["company_name"],
                                ); ?>
                            </a>
                            <?php if ($comp["is_verified"]): ?>
                                <span class="dash-badge badge-salary" style="margin-left: 10px; padding: 0.1rem 0.5rem; font-size: 0.7rem;">✓ Verified</span>
                            <?php else: ?>
                                <span class="dash-badge" style="margin-left: 10px; padding: 0.1rem 0.5rem; font-size: 0.7rem; background: rgba(245,158,11,0.1); color: var(--amber-400); border: 1px solid rgba(245,158,11,0.3);">⏳ Pending</span>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <?php if (!empty($profile["about_user"])): ?>
            <div class="profile-section">
                <h3>📝 About</h3>
                <div style="background: rgba(99,102,241,0.02); padding: 1.5rem; border-radius: var(--r-md); border: 1px solid rgba(99,102,241,0.08);">
                    <p style="color: var(--text-main); line-height: 1.6;"><?php echo nl2br(
                        htmlspecialchars($profile["about_user"]),
                    ); ?></p>
                </div>
            </div>
            <?php endif; ?>

            <div class="profile-section">
                <h3>💼 Work Experience</h3>
                <?php if (!empty($profile["current_work"])): ?>
                    <div class="dynamic-list-item" style="border-left-color: var(--emerald-500);">
                        <div style="margin-bottom: 0.5rem;"><span class="dash-badge badge-salary">Current Role</span></div>
                        <div class="info-value" style="margin-bottom: 0.3rem;"><strong style="color: var(--text-muted);">Title:</strong> <?php echo htmlspecialchars(
                            $profile["current_work"]["worked_as"],
                        ); ?></div>
                        <div class="info-value" style="margin-bottom: 0.3rem;"><strong style="color: var(--text-muted);">Company:</strong> <?php echo htmlspecialchars(
                            $profile["current_work"]["company"],
                        ); ?></div>
                        <div class="info-value"><strong style="color: var(--text-muted);">Duration:</strong> <?php echo formatExp(
                            $profile["current_work"]["exp"],
                        ); ?></div>
                    </div>
                <?php endif; ?>

                <?php if (!empty($profile["previous_experience"])): ?>
                    <?php foreach ($profile["previous_experience"] as $exp): ?>
                        <div class="dynamic-list-item">
                            <div class="info-value" style="margin-bottom: 0.3rem;"><strong style="color: var(--text-muted);">Title:</strong> <?php echo htmlspecialchars(
                                $exp["worked_as"],
                            ); ?></div>
                            <div class="info-value" style="margin-bottom: 0.3rem;"><strong style="color: var(--text-muted);">Company:</strong> <?php echo htmlspecialchars(
                                $exp["company"],
                            ); ?></div>
                            <div class="info-value"><strong style="color: var(--text-muted);">Duration:</strong> <?php echo formatExp(
                                $exp["exp"],
                            ); ?></div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>

                <?php if (
                    empty($profile["current_work"]) &&
                    empty($profile["previous_experience"])
                ): ?>
                    <p class="dash-empty">No work experience listed.</p>
                <?php endif; ?>
            </div>

            <div class="profile-section">
                <h3>🎯 Skills</h3>
                <?php if (!empty($profile["skills"])): ?>
                    <div class="card-tags">
                        <?php foreach ($profile["skills"] as $skill): ?>
                            <span class="dash-badge badge-skill"><?php echo htmlspecialchars(
                                $skill,
                            ); ?></span>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <p class="dash-empty">No specific skills listed.</p>
                <?php endif; ?>
            </div>

            <div class="profile-section">
                <h3>🎓 Education</h3>
                <?php if (!empty($profile["education"])): ?>
                    <?php foreach ($profile["education"] as $edu): ?>
                        <div class="dynamic-list-item" style="border-left-color: var(--cyan-400);">
                            <div class="info-value" style="margin-bottom: 0.3rem;"><strong style="color: var(--text-muted);">Institution:</strong> <?php echo htmlspecialchars(
                                $edu["edu_institution"] ?? "N/A",
                            ); ?></div>
                            <div class="info-value" style="margin-bottom: 0.3rem;"><strong style="color: var(--text-muted);">Major:</strong> <?php echo htmlspecialchars(
                                $edu["major"],
                            ); ?></div>
                            <div class="info-value"><strong style="color: var(--text-muted);">Level:</strong> <span class="dash-badge badge-location" style="font-size: 0.7rem; padding: 0.1rem 0.5rem; margin-left: 0.3rem;"><?php echo htmlspecialchars(
                                $edu["education"],
                            ); ?></span></div>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <p class="dash-empty">No education history provided.</p>
                <?php endif; ?>
            </div>

            <div style="margin-top: 2rem; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 2rem; text-align: center;">
                <a href="mailto:<?php echo htmlspecialchars(
                    $profile["email"],
                ); ?>" class="dash-btn dash-btn-primary" style="padding: 1rem 2.5rem; font-size: 1rem;">✉️ Email <?php echo htmlspecialchars(
    $profile["name"],
); ?></a>
            </div>
        </div>
    </div>
</body>
</html>
