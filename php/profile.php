<?php
// profile.php
require_once "config.php";

if (!isAuthenticated()) {
    header("Location: signin.php");
    exit();
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

$token = getJWTToken();

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    header("Content-Type: application/json");
    $updateData = [];

    if (isset($_POST["name"]) && !empty(trim($_POST["name"]))) {
        $updateData["name"] = trim($_POST["name"]);
    }
    if (isset($_POST["email"]) && !empty(trim($_POST["email"]))) {
        $updateData["email"] = trim($_POST["email"]);
    }
    if (isset($_POST["is_finding_job"])) {
        $updateData["is_finding_job"] = $_POST["is_finding_job"] === "1";
    }
    if (isset($_POST["about_user"])) {
        $updateData["about_user"] = trim($_POST["about_user"]);
    }
    if (!empty($_POST["skills"])) {
        $updateData["skills"] = array_values(
            array_filter(json_decode($_POST["skills"], true)),
        );
    }
    if (!empty($_POST["education"])) {
        $updateData["education"] = json_decode($_POST["education"], true);
    }

    if (!empty($_POST["current_work"])) {
        $cw = json_decode($_POST["current_work"], true);
        $updateData["current_work"] = [
            "worked_as" => trim($cw["worked_as"]),
            "company" => trim($cw["company"]),
            "exp" => (int) $cw["exp_y"] * 12 + (int) $cw["exp_m"],
        ];
    }

    if (!empty($_POST["previous_experience"])) {
        $pe = json_decode($_POST["previous_experience"], true);
        $expData = [];
        foreach ($pe as $work) {
            $expData[] = [
                "worked_as" => trim($work["worked_as"]),
                "company" => trim($work["company"]),
                "exp" => (int) $work["exp_y"] * 12 + (int) $work["exp_m"],
            ];
        }
        $updateData["previous_experience"] = $expData;
    }

    $uploadDir = "uploads/";
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    if (
        isset($_FILES["profile_picture"]) &&
        $_FILES["profile_picture"]["error"] === UPLOAD_ERR_OK
    ) {
        $ext = pathinfo($_FILES["profile_picture"]["name"], PATHINFO_EXTENSION);
        $filename = "pfp_" . time() . "_" . uniqid() . "." . $ext;
        if (
            move_uploaded_file(
                $_FILES["profile_picture"]["tmp_name"],
                $uploadDir . $filename,
            )
        ) {
            $updateData["profile_picture"] = $uploadDir . $filename;
        }
    }

    if (
        isset($_FILES["resume"]) &&
        $_FILES["resume"]["error"] === UPLOAD_ERR_OK
    ) {
        $ext = pathinfo($_FILES["resume"]["name"], PATHINFO_EXTENSION);
        $filename = "resume_" . time() . "_" . uniqid() . "." . $ext;
        if (
            move_uploaded_file(
                $_FILES["resume"]["tmp_name"],
                $uploadDir . $filename,
            )
        ) {
            $updateData["resume"] = $uploadDir . $filename;
        }
    }

    if (empty($updateData)) {
        echo json_encode([
            "status" => "error",
            "message" => "No fields to update",
        ]);
        exit();
    }

    $result = callRustAPI("/update-profile", "POST", $updateData, $token);
    if ($result["success"]) {
        echo json_encode([
            "status" => "success",
            "message" => "Profile updated successfully!",
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

$profileResult = callRustAPI("/profile", "GET", null, $token);
if (!$profileResult["success"]) {
    clearJWTCookie();
    header("Location: signin.php");
    exit();
}
$profile = $profileResult["data"];

if (isset($profile["current_work"]) && is_array($profile["current_work"])) {
    $totalMonths = (int) ($profile["current_work"]["exp"] ?? 0);
    $profile["current_work"]["exp_y"] = floor($totalMonths / 12);
    $profile["current_work"]["exp_m"] = $totalMonths % 12;
}

if (
    isset($profile["previous_experience"]) &&
    is_array($profile["previous_experience"])
) {
    foreach ($profile["previous_experience"] as &$exp) {
        $totalMonths = (int) ($exp["exp"] ?? 0);
        $exp["exp_y"] = floor($totalMonths / 12);
        $exp["exp_m"] = $totalMonths % 12;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Profile - Job Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; }
        .header { background: white; padding: 20px 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .header h1 { color: #333; font-size: 28px; }
        .header .nav-links { display: flex; gap: 15px; align-items: center; }
        .btn { padding: 10px 20px; border-radius: 5px; text-decoration: none; font-weight: 600; font-size: 14px; cursor: pointer; border: none; transition: all 0.3s; display: inline-block; }
        .btn-secondary { background: #6c757d; color: white; }
        .profile-container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .profile-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #f0f0f0; }
        .btn-edit { background: #667eea; color: white; }
        .btn-cancel { background: #6c757d; color: white; }
        .profile-section { margin-bottom: 30px; }
        .profile-section h3 { color: #667eea; font-size: 18px; margin-bottom: 15px; display: flex; align-items: center; gap: 10px; }
        .info-grid { display: grid; grid-template-columns: 200px 1fr; gap: 15px; align-items: start; }
        .info-label { font-weight: 600; color: #555; }
        .info-value { color: #333; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; color: #333; font-weight: 600; margin-bottom: 8px; font-size: 14px; }
        .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 5px; font-size: 14px; font-family: inherit; }
        .form-group textarea { min-height: 100px; resize: vertical; }
        .toggle-switch-container { display: flex; align-items: center; gap: 15px; margin-top: 5px; }
        .switch { position: relative; display: inline-block; width: 60px; height: 30px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px; }
        .slider:before { position: absolute; content: ""; height: 22px; width: 22px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }
        input:checked + .slider { background-color: #667eea; }
        input:checked + .slider:before { transform: translateX(30px); }
        .toggle-label { font-size: 14px; color: #999; font-weight: 600; cursor: pointer; }
        .toggle-label.active { color: #333; }
        .skills-container { display: flex; flex-wrap: wrap; gap: 8px; }
        .skill-tag { background: #667eea; color: white; padding: 8px 15px; border-radius: 20px; font-size: 14px; display: flex; align-items: center; gap: 8px; }
        .skill-tag-remove { cursor: pointer; font-weight: bold; font-size: 18px; }
        .tags-display { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; min-height: 40px; padding: 10px; border: 2px dashed #e0e0e0; border-radius: 5px; }
        .education-item { background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 4px solid #667eea; }
        .education-form-item { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 15px; border: 2px solid #e0e0e0; position: relative; }
        .education-form-item .remove-btn { position: absolute; top: 10px; right: 10px; background: #dc3545; color: white; border: none; width: 30px; height: 30px; border-radius: 50%; cursor: pointer; font-size: 18px; font-weight: bold; }
        .btn-add { background: #28a745; color: white; padding: 10px 20px; margin-top: 10px; border: none; border-radius: 5px; cursor: pointer;}
        .alert { padding: 15px; border-radius: 5px; margin-bottom: 20px; display: none; }
        .alert.show { display: block; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .btn-primary { background: #667eea; color: white; width: 100%; padding: 15px; font-size: 16px; margin-top: 20px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; text-align: center; }
        .edit-mode { display: none; }
        .view-mode { display: block; }
        .helper-text { font-size: 12px; color: #666; margin-top: 5px; }
        .status-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; font-size: 13px; font-weight: 600; }
        .status-active { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status-poster { background: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
        .empty-state { color: #999; font-style: italic; }
        .edu-level-badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; background: #667eea; color: white; }
        .profile-tabs { display: flex; border-bottom: 2px solid #e0e0e0; margin-bottom: 20px; overflow-x: auto; }
        .profile-tab { padding: 12px 25px; cursor: pointer; font-weight: bold; color: #666; border-bottom: 3px solid transparent; transition: all 0.3s; white-space: nowrap; }
        .profile-tab:hover { color: #667eea; }
        .profile-tab.active { color: #667eea; border-bottom-color: #667eea; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .posted-job-card { background: #f8f9fa; border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; margin-bottom: 15px; }
        .applicant-card { background: white; border: 1px solid #ddd; border-left: 4px solid #667eea; border-radius: 6px; padding: 15px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>👤 My Profile</h1>
            <div class="nav-links">
                <a href="dashboard.php" class="btn btn-secondary">← Back to Dashboard</a>
            </div>
        </div>

        <div class="profile-container">
            <div class="profile-header">
                <h2>Manage Account</h2>
                <div class="nav-links">
                    <button id="edit-btn" class="btn btn-edit view-mode">✏️ Edit Profile</button>
                    <button id="cancel-btn" class="btn btn-cancel edit-mode">✖ Cancel</button>
                </div>
            </div>

            <div class="profile-tabs view-mode">
                <div class="profile-tab active" onclick="switchTab('profile')">Profile Info</div>
                <?php if (!$profile["is_finding_job"]): ?>
                    <div class="profile-tab" id="tab-companies" onclick="switchTab('companies')">My Companies</div>
                    <div class="profile-tab" id="tab-my-jobs" onclick="switchTab('jobs')">My Posted Jobs</div>
                <?php else: ?>
                    <div class="profile-tab" id="tab-my-apps" onclick="switchTab('apps')">My Applications</div>
                <?php endif; ?>
            </div>

            <div id="alert" class="alert"></div>

            <div id="view-mode" class="view-mode tab-content active">

                <?php if (!empty($profile["working_at"])): ?>
                    <div style="background: #f0fdf4; border: 1px solid #c3e6cb; padding: 15px; border-radius: 8px; margin-bottom: 30px;">
                        <h4 style="margin: 0 0 10px; color: #155724;">🏢 Company Affiliations</h4>
                        <?php foreach ($profile["working_at"] as $comp): ?>
                            <div style="font-size: 14px; color: #155724; display: flex; align-items: center; flex-wrap: wrap; margin-bottom: 8px;">
                                <strong><?php echo htmlspecialchars(
                                    $comp["designation"],
                                ); ?></strong>
                                &nbsp;at&nbsp;
                                <a href="company.php?id=<?php echo urlencode(
                                    $comp["company_id"],
                                ); ?>" style="color: #0c5460; font-weight: bold; text-decoration: underline;">
                                    <?php echo htmlspecialchars(
                                        $comp["company_name"],
                                    ); ?>
                                </a>
                                <?php if ($comp["is_verified"]): ?>
                                    <span style="color: #28a745; font-size: 11px; margin-left: 10px; border: 1px solid #28a745; padding: 2px 5px; border-radius: 4px; background: white;">✓ Verified</span>
                                <?php else: ?>
                                    <span style="color: #856404; font-size: 11px; margin-left: 10px; border: 1px solid #ffeeba; padding: 2px 5px; border-radius: 4px; background: #fff3cd;">⏳ Pending Verification</span>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

                <div style="text-align: center; margin-bottom: 30px;">
                    <?php if (!empty($profile["profile_picture"])): ?>
                        <img src="<?php echo htmlspecialchars(
                            $profile["profile_picture"],
                        ); ?>" style="width: 120px; height: 120px; border-radius: 50%; object-fit: cover; border: 4px solid #667eea; margin-bottom: 15px;">
                    <?php else: ?>
                        <div style="width: 120px; height: 120px; border-radius: 50%; background: #e0e0e0; display: flex; align-items: center; justify-content: center; margin: 0 auto 15px; font-size: 40px;">👤</div>
                    <?php endif; ?>

                    <?php if (!empty($profile["resume"])): ?>
                        <div><a href="<?php echo htmlspecialchars(
                            $profile["resume"],
                        ); ?>" download class="btn" style="background: #28a745; color: white;">📄 Download Current Resume</a></div>
                    <?php endif; ?>
                </div>

                <div class="profile-section">
                    <h3>📋 Basic Information</h3>
                    <div class="info-grid">
                        <div class="info-label">Username:</div>
                        <div class="info-value"><?php echo htmlspecialchars(
                            $profile["uid"],
                        ); ?></div>
                        <div class="info-label">Name:</div>
                        <div class="info-value"><?php echo htmlspecialchars(
                            $profile["name"],
                        ); ?></div>
                        <div class="info-label">Email:</div>
                        <div class="info-value"><?php echo htmlspecialchars(
                            $profile["email"],
                        ); ?></div>
                        <div class="info-label">Account Role:</div>
                        <div class="info-value">
                            <?php if ($profile["is_finding_job"]): ?>
                                <span class="status-badge status-active">🔍 Job Seeker</span>
                            <?php else: ?>
                                <span class="status-badge status-poster">📢 Job Poster</span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>

                <?php if (!empty($profile["about_user"])): ?>
                <div class="profile-section">
                    <h3>📝 About Me</h3>
                    <p style="color: #555; line-height: 1.6;"><?php echo nl2br(
                        htmlspecialchars($profile["about_user"]),
                    ); ?></p>
                </div>
                <?php endif; ?>

                <div class="profile-section">
                    <h3>🎯 Skills</h3>
                    <?php if (!empty($profile["skills"])): ?>
                        <div class="skills-container">
                            <?php foreach ($profile["skills"] as $skill): ?>
                                <span class="skill-tag"><?php echo htmlspecialchars(
                                    $skill,
                                ); ?></span>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <p class="empty-state">No skills added yet</p>
                    <?php endif; ?>
                </div>

                <div class="profile-section">
                    <h3>💼 Work Experience</h3>
                    <?php if (!empty($profile["current_work"])): ?>
                        <div class="education-item" style="border-left-color: #28a745;">
                            <div>
                                <span class="edu-level-badge" style="background: #28a745;">Current Role</span>
                                <strong style="margin-left: 10px;"><?php echo htmlspecialchars(
                                    $profile["current_work"]["worked_as"],
                                ); ?></strong>
                            </div>
                            <div style="margin-top: 8px;">
                                🏢 <?php echo htmlspecialchars(
                                    $profile["current_work"]["company"],
                                ); ?>
                                • ⏱️ <?php echo formatExp(
                                    $profile["current_work"]["exp"],
                                ); ?>
                            </div>
                        </div>
                    <?php endif; ?>

                    <?php if (!empty($profile["previous_experience"])): ?>
                        <?php foreach (
                            $profile["previous_experience"]
                            as $exp
                        ): ?>
                            <div class="education-item">
                                <div>
                                    <strong style="margin-left: 10px;"><?php echo htmlspecialchars(
                                        $exp["worked_as"],
                                    ); ?></strong>
                                </div>
                                <div style="margin-top: 8px;">
                                    🏢 <?php echo htmlspecialchars(
                                        $exp["company"],
                                    ); ?>
                                    • ⏱️ <?php echo formatExp($exp["exp"]); ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>

                    <?php if (
                        empty($profile["current_work"]) &&
                        empty($profile["previous_experience"])
                    ): ?>
                        <p class="empty-state">No work experience records added yet</p>
                    <?php endif; ?>
                </div>

                <div class="profile-section">
                    <h3>🎓 Education</h3>
                    <?php if (!empty($profile["education"])): ?>
                        <?php foreach ($profile["education"] as $edu): ?>
                            <div class="education-item">
                                <div>
                                    <span class="edu-level-badge"><?php echo htmlspecialchars(
                                        $edu["education"],
                                    ); ?></span>
                                    <strong style="margin-left: 10px;"><?php echo htmlspecialchars(
                                        $edu["major"],
                                    ); ?></strong>
                                </div>
                                <div style="margin-top: 8px;">
                                    📍 <?php echo htmlspecialchars(
                                        $edu["edu_institution"],
                                    ); ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p class="empty-state">No education records added yet</p>
                    <?php endif; ?>
                </div>
            </div>

            <div id="content-companies" class="view-mode tab-content">
                <div class="profile-section">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                        <h3 style="margin: 0;">🏢 My Affiliated Companies</h3>
                        <a href="create_company.php" class="btn btn-primary" style="width: auto; margin: 0; padding: 10px 20px;">➕ Register New Company</a>
                    </div>

                    <?php if (!empty($profile["working_at"])): ?>
                        <?php foreach ($profile["working_at"] as $comp): ?>
                            <div class="posted-job-card" style="display: flex; gap: 20px; align-items: center;">
                                <div style="width: 60px; height: 60px; border-radius: 8px; background: #e0e0e0; display: flex; align-items: center; justify-content: center; font-size: 24px;">🏢</div>
                                <div style="flex: 1;">
                                    <h3 style="margin: 0 0 5px;">
                                        <a href="company.php?id=<?php echo urlencode(
                                            $comp["company_id"],
                                        ); ?>" style="text-decoration: none; color: #333;">
                                            <?php echo htmlspecialchars(
                                                $comp["company_name"],
                                            ); ?>
                                        </a>
                                    </h3>
                                    <div style="color: #666; font-size: 14px;">
                                        <strong>Role:</strong> <?php echo htmlspecialchars(
                                            $comp["designation"],
                                        ); ?>
                                        <?php if ($comp["is_verified"]): ?>
                                            <span style="color: #28a745; font-size: 11px; margin-left: 10px; border: 1px solid #28a745; padding: 2px 5px; border-radius: 4px; background: #f0fdf4;">✓ Verified</span>
                                        <?php else: ?>
                                            <span style="color: #856404; font-size: 11px; margin-left: 10px; border: 1px solid #ffeeba; padding: 2px 5px; border-radius: 4px; background: #fff3cd;">⏳ Pending Verification</span>
                                        <?php endif; ?>
                                    </div>
                                </div>

                                <div style="display:flex; gap: 5px; flex-wrap: wrap; justify-content: flex-end;">
                                    <a href="company.php?id=<?php echo urlencode(
                                        $comp["company_id"],
                                    ); ?>" class="btn btn-secondary">View Profile</a>
                                    <?php if (
                                        isset($comp["is_owner"]) &&
                                        $comp["is_owner"]
                                    ): ?>
                                        <a href="edit_company.php?id=<?php echo urlencode(
                                            $comp["company_id"],
                                        ); ?>" class="btn btn-secondary" style="background:#17a2b8; text-decoration:none;">Edit</a>
                                        <button onclick="deleteCompany('<?php echo htmlspecialchars(
                                            $comp["company_id"],
                                        ); ?>')" class="btn btn-secondary" style="background:#dc3545; border:none; cursor:pointer;">Delete</button>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="empty-state" style="text-align: center; padding: 40px 20px; background: #f8f9fa; border-radius: 8px; border: 1px dashed #ddd;">
                            <div style="font-size: 40px; margin-bottom: 10px;">🏢</div>
                            <p>You are not currently affiliated with any company.</p>
                            <p style="font-size: 13px; color: #888; margin-top: 5px;">Register your company to start posting jobs and managing employees.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <div id="content-jobs" class="view-mode tab-content">
                <div id="my-jobs-list">
                    <p>Loading your job posts...</p>
                </div>
            </div>

            <div id="content-apps" class="view-mode tab-content">
                <div class="profile-section">
                    <h3 style="margin-bottom: 20px;">📝 My Job Applications</h3>
                    <div id="my-apps-list">
                        <p>Loading your applications...</p>
                    </div>
                </div>
            </div>

            <div id="edit-mode" class="edit-mode">
                <div class="profile-section" style="background: #f8f9fa; border: 1px solid #e0e0e0; padding: 20px; border-radius: 8px;">
                    <h3>🏢 Company Affiliations</h3>
                    <?php if (!empty($profile["working_at"])): ?>
                        <?php foreach ($profile["working_at"] as $comp): ?>
                            <p style="font-size: 14px; margin-bottom: 5px;">You are affiliated with <strong><?php echo htmlspecialchars(
                                $comp["company_name"],
                            ); ?></strong>.</p>
                            <a href="company.php?id=<?php echo urlencode(
                                $comp["company_id"],
                            ); ?>" class="btn btn-secondary" style="display:inline-block; background:#6c757d; text-decoration:none; padding:5px 10px; font-size:12px; margin-bottom:15px;">View Company Page</a><br>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p style="color: #666; font-size: 14px; margin-bottom: 10px;">You are not currently linked to any company.</p>
                        <p style="font-size: 12px; color: #888;">If you are an employer, you can search and join your company, or create a new one from your dashboard.</p>
                        <a href="dashboard.php" class="btn btn-secondary" style="display:inline-block; background:#17a2b8; text-decoration:none;">Back to Dashboard</a>
                    <?php endif; ?>
                </div>

                <form id="profile-form">
                    <div class="profile-section">
                        <h3>📋 Basic Information & Files</h3>

                        <div class="form-group">
                            <label for="profile_picture">Profile Picture (Image)</label>
                            <input type="file" id="profile_picture" name="profile_picture" accept="image/*">
                        </div>
                        <div class="form-group">
                            <label for="resume">Resume (PDF/Word)</label>
                            <input type="file" id="resume" name="resume" accept=".pdf,.doc,.docx">
                        </div>

                        <div class="form-group">
                            <label for="name">Name *</label>
                            <input type="text" id="name" name="name" value="<?php echo htmlspecialchars(
                                $profile["name"],
                            ); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="email">Email *</label>
                            <input type="email" id="email" name="email" value="<?php echo htmlspecialchars(
                                $profile["email"],
                            ); ?>" required>
                        </div>
                        <div class="form-group">
                            <label for="about_user">About Me (Brief Bio)</label>
                            <textarea id="about_user" name="about_user" placeholder="Tell us a little about yourself..."><?php echo htmlspecialchars(
                                $profile["about_user"] ?? "",
                            ); ?></textarea>
                        </div>
                        <div class="form-group">
                            <label>Primary Role</label>
                            <div class="toggle-switch-container">
                                <span class="toggle-label <?php echo !$profile[
                                    "is_finding_job"
                                ]
                                    ? "active"
                                    : ""; ?>" id="label-poster">Job Poster</span>
                                <label class="switch">
                                    <input type="checkbox" id="is_finding_job" name="is_finding_job" <?php echo $profile[
                                        "is_finding_job"
                                    ]
                                        ? "checked"
                                        : ""; ?> onchange="updateToggleLabels()">
                                    <span class="slider round"></span>
                                </label>
                                <span class="toggle-label <?php echo $profile[
                                    "is_finding_job"
                                ]
                                    ? "active"
                                    : ""; ?>" id="label-seeker">Job Seeker</span>
                            </div>
                        </div>
                    </div>

                    <div class="profile-section">
                        <h3>🎯 Skills</h3>
                        <div class="form-group">
                            <label for="skills_input">Add Skills</label>
                            <input type="text" id="skills_input" placeholder="Type a skill and press Enter">
                            <div class="helper-text">Press Enter after typing each skill</div>
                            <div id="skills_tags" class="tags-display"></div>
                        </div>
                    </div>

                    <div class="profile-section">
                        <h3>💼 Current Work</h3>
                        <div id="current-work-container"></div>
                    </div>

                    <div class="profile-section">
                        <h3>🕰️ Previous Experience</h3>
                        <div id="previous-experience-container"></div>
                        <button type="button" class="btn btn-add" id="add-experience-btn">➕ Add Experience Record</button>
                    </div>

                    <div class="profile-section">
                        <h3>🎓 Education</h3>
                        <div id="education-container"></div>
                        <button type="button" class="btn btn-add" id="add-education-btn">➕ Add Education Record</button>
                    </div>

                    <button type="submit" class="btn btn-primary" id="save-btn">💾 Save Changes</button>
                </form>
            </div>
        </div>
    </div>

    <script>
        const viewMode = document.getElementById('view-mode');
        const editMode = document.getElementById('edit-mode');
        const editBtn = document.getElementById('edit-btn');
        const cancelBtn = document.getElementById('cancel-btn');
        const profileForm = document.getElementById('profile-form');
        const saveBtn = document.getElementById('save-btn');
        const alert = document.getElementById('alert');

        let skills = <?php echo json_encode($profile["skills"] ?? []); ?>;
        let educationRecords = <?php echo json_encode(
            $profile["education"] ?? [],
        ); ?>;
        let currentWork = <?php echo json_encode(
            $profile["current_work"] ?? null,
        ); ?>;
        let previousExperience = <?php echo json_encode(
            $profile["previous_experience"] ?? [],
        ); ?>;

        const eduLevels = [
            { value: 'SecondarySchool', label: 'Secondary School' },
            { value: 'HighSchool', label: 'High School' },
            { value: 'Diploma', label: 'Diploma' },
            { value: 'Bachelors', label: "Bachelor's Degree" },
            { value: 'Masters', label: "Master's Degree" },
            { value: 'PhD', label: 'PhD/Doctorate' }
        ];

        function switchTab(tab) {
            document.querySelectorAll('.profile-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            if (tab === 'profile') {
                document.querySelector('.profile-tab:nth-child(1)').classList.add('active');
                document.getElementById('view-mode').classList.add('active');
            } else if (tab === 'companies') {
                document.getElementById('tab-companies').classList.add('active');
                document.getElementById('content-companies').classList.add('active');
            } else if (tab === 'jobs') {
                document.getElementById('tab-my-jobs').classList.add('active');
                document.getElementById('content-jobs').classList.add('active');
                loadMyJobs();
            } else if (tab === 'apps') {
                document.getElementById('tab-my-apps').classList.add('active');
                document.getElementById('content-apps').classList.add('active');
                loadMyApplications();
            }
        }

        async function loadMyJobs() {
            const container = document.getElementById('my-jobs-list');
            try {
                const res = await fetch('employer_api.php?action=my_jobs');
                const text = await res.text();
                const result = JSON.parse(text);

                if (result.success && result.data) {
                    if (result.data.length === 0) {
                        container.innerHTML = '<p class="empty-state">You haven\'t posted any jobs yet.</p>';
                        return;
                    }

                    let html = '';
                    result.data.forEach(job => {
                        const companyLink = job.company_id
                            ? `<a href="company.php?id=${encodeURIComponent(job.company_id)}" style="color: #0c5460; font-weight: bold; text-decoration: underline;">${job.company_name}</a>`
                            : (job.company_name || 'Your Company');

                        html += `
                            <div class="posted-job-card">
                                <div style="display:flex; justify-content:space-between; align-items:center;">
                                    <h3 style="color:#333; margin:0;">${job.title}</h3>
                                    <div>
                                        <a href="edit_job.php?id=${encodeURIComponent(job.id)}" class="btn btn-secondary" style="background:#17a2b8; padding: 6px 12px; font-size:12px; text-decoration:none;">Edit</a>
                                        <button onclick="deleteJob('${job.id}')" class="btn btn-secondary" style="background:#dc3545; padding: 6px 12px; font-size:12px; margin-right:10px; border:none; cursor:pointer;">Delete</button>
                                        <button class="btn btn-secondary" style="padding: 6px 12px; font-size:12px;" onclick="toggleApplicants('${job.id}', this)">View Applicants</button>
                                    </div>
                                </div>
                                <p style="color:#666; font-size:14px; margin-top:8px;">🏢 ${companyLink} | 📍 ${job.location} | 💰 $${job.salary_range_start} - $${job.salary_range_end}</p>
                                <div id="applicants-${job.id}" style="display:none; margin-top: 20px; border-top: 2px dashed #e0e0e0; padding-top: 20px;">
                                    <p>Loading applicants...</p>
                                </div>
                            </div>
                        `;
                    });
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<p class="empty-state">Failed to load jobs.</p>';
                }
            } catch (e) {
                container.innerHTML = '<p class="empty-state">Error loading jobs. Session may have expired.</p>';
            }
        }

        async function deleteJob(jobId) {
            if (!confirm("Are you sure you want to permanently delete this job post?")) return;
            try {
                const res = await fetch(`employer_api.php?action=delete_job&job_id=${encodeURIComponent(jobId)}`);
                const text = await res.text();
                const result = JSON.parse(text);

                if (result.success || result.status === 'success') {
                    loadMyJobs();
                } else {
                    alert('Failed to delete job: ' + (result.message || 'Unknown Error'));
                }
            } catch(e) { alert('Error securely reaching server to delete job.'); }
        }

        async function deleteCompany(companyId) {
            if (!confirm("WARNING: Are you sure you want to permanently delete this company? This cannot be undone.")) return;
            try {
                const res = await fetch(`employer_api.php?action=delete_company&company_id=${encodeURIComponent(companyId)}`);
                const text = await res.text();
                const result = JSON.parse(text);

                if (result.success || result.status === 'success') {
                    alert("Company deleted.");
                    window.location.reload();
                } else {
                    alert('Failed to delete company: ' + (result.message || 'Unknown Error'));
                }
            } catch(e) { alert('Error securely reaching server to delete company.'); }
        }

        async function toggleApplicants(jobId, btn) {
            const container = document.getElementById(`applicants-${jobId}`);

            if (container.style.display === 'block') {
                container.style.display = 'none';
                btn.textContent = 'View Applicants';
                btn.classList.replace('btn-cancel', 'btn-secondary');
                return;
            }

            container.style.display = 'block';
            btn.textContent = 'Hide Applicants';
            btn.classList.replace('btn-secondary', 'btn-cancel');
            container.innerHTML = '<p>Loading applicants...</p>';

            try {
                const res = await fetch('employer_api.php?action=applicants&job_id=' + encodeURIComponent(jobId));
                const text = await res.text();
                const result = JSON.parse(text);

                if (result.success && result.data) {
                    if (result.data.length === 0) {
                        container.innerHTML = '<p class="empty-state" style="margin:0;">No one has applied to this position yet.</p>';
                        return;
                    }

                    let html = `<h4 style="margin-bottom: 10px; color:#667eea;">${result.data.length} Applicant(s)</h4>`;
                    result.data.forEach(app => {
                        const dateObj = new Date(app.datetime_applied);
                        const prettyDate = isNaN(dateObj.getTime()) ? 'Recently' : dateObj.toLocaleDateString();

                        const statusSelect = `
                            <select onchange="updateAppStatus('${jobId}', '${app.user.id}', this.value)" style="padding: 4px; font-size: 12px; border-radius: 4px; font-weight: bold; border: 1px solid #ccc;">
                                <option value="Pending" ${app.status.toLowerCase() === 'pending' ? 'selected' : ''}>Pending</option>
                                <option value="Accepted" ${app.status.toLowerCase() === 'accepted' ? 'selected' : ''}>Accepted</option>
                                <option value="Rejected" ${app.status.toLowerCase() === 'rejected' ? 'selected' : ''}>Rejected</option>
                            </select>
                        `;

                        html += `
                            <div class="applicant-card">
                                <div style="display:flex; justify-content:space-between; align-items:center;">
                                    <strong style="font-size: 16px;">${app.user.name}</strong>
                                    ${statusSelect}
                                </div>
                                <div style="font-size:14px; color:#555; margin-top:8px;">
                                    📧 <a href="mailto:${app.user.email}" style="color:#667eea; text-decoration:none;">${app.user.email}</a>
                                    <br>🕒 Applied on ${prettyDate}
                                </div>
                                <div style="margin-top:12px;">
                                    <a href="user_details.php?id=${encodeURIComponent(app.user.id)}" target="_blank" class="btn" style="background:#667eea; color:white; padding:8px 15px; font-size:13px; display:inline-block; text-align:center; text-decoration:none;">View Full Profile ↗</a>
                                </div>
                            </div>
                        `;
                    });
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<p class="empty-state">Failed to load applicants.</p>';
                }
            } catch (e) {
                container.innerHTML = '<p class="empty-state">Error parsing applicant data.</p>';
            }
        }

        async function updateAppStatus(jobId, applicantId, status) {
            try {
                const res = await fetch('employer_api.php?action=update_application_status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ job_id: jobId, applicant_id: applicantId, status: status })
                });
                const result = await res.json();
                if (!result.success && result.status !== 'success') {
                    alert('Failed to update status');
                }
            } catch(e) {
                alert('Error updating status');
            }
        }

        async function loadMyApplications() {
            const container = document.getElementById('my-apps-list');
            try {
                const res = await fetch('employer_api.php?action=my_applications');
                const text = await res.text();
                const result = JSON.parse(text);

                if (result.success && result.data) {
                    if (result.data.length === 0) {
                        container.innerHTML = '<p class="empty-state">You have not applied to any jobs yet.</p>';
                        return;
                    }

                    let html = '';
                    result.data.forEach(app => {
                        let statusColor = app.status.toLowerCase() === 'accepted' ? '#28a745' : (app.status.toLowerCase() === 'rejected' ? '#dc3545' : '#856404');
                        let statusBg = app.status.toLowerCase() === 'accepted' ? '#d4edda' : (app.status.toLowerCase() === 'rejected' ? '#f8d7da' : '#fff3cd');

                        const dateObj = new Date(app.datetime_applied);
                        const prettyDate = isNaN(dateObj.getTime()) ? 'Recently' : dateObj.toLocaleDateString();

                        const companyLink = app.job.company_id
                            ? `<a href="company.php?id=${encodeURIComponent(app.job.company_id)}" style="color: #0c5460; font-weight: bold; text-decoration: underline;">${app.job.company_name}</a>`
                            : (app.job.company_name || app.job.employer_name);

                        html += `
                            <div class="posted-job-card" style="border-left: 4px solid ${statusColor};">
                                <div style="display:flex; justify-content:space-between; align-items:center;">
                                    <h3 style="color:#333; margin:0;">${app.job.title}</h3>
                                    <span style="font-size:12px; font-weight:bold; background:${statusBg}; color:${statusColor}; padding:5px 12px; border-radius:15px;">${app.status.toUpperCase()}</span>
                                </div>
                                <div style="color:#666; font-size:14px; margin-top:8px;">
                                    🏢 ${companyLink} | 📍 ${app.job.location}
                                </div>
                                <div style="color:#888; font-size:12px; margin-top:10px;">
                                    Applied on: ${prettyDate}
                                </div>
                            </div>
                        `;
                    });
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<p class="empty-state">Failed to load applications.</p>';
                }
            } catch (e) {
                container.innerHTML = '<p class="empty-state">Error loading applications.</p>';
            }
        }

        function updateToggleLabels() {
            const checkbox = document.getElementById('is_finding_job');
            document.getElementById('label-seeker').classList.toggle('active', checkbox.checked);
            document.getElementById('label-poster').classList.toggle('active', !checkbox.checked);
        }

        const skillsInput = document.getElementById('skills_input');
        const skillsTagsContainer = document.getElementById('skills_tags');

        skillsInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const skill = skillsInput.value.trim();
                if (skill && !skills.includes(skill)) {
                    skills.push(skill);
                    renderSkills();
                    skillsInput.value = '';
                }
            }
        });

        function renderSkills() {
            skillsTagsContainer.innerHTML = '';
            skills.forEach((skill, index) => {
                const tag = document.createElement('div');
                tag.className = 'skill-tag';
                tag.innerHTML = `${skill} <span class="skill-tag-remove" onclick="removeSkill(${index})">×</span>`;
                skillsTagsContainer.appendChild(tag);
            });
        }

        function removeSkill(index) {
            skills.splice(index, 1);
            renderSkills();
        }

        function renderCurrentWork() {
            const container = document.getElementById('current-work-container');
            const hasWork = currentWork !== null;
            const workedAs = hasWork ? currentWork.worked_as || '' : '';
            const company = hasWork ? currentWork.company || '' : '';

            const years = hasWork ? currentWork.exp_y || 0 : 0;
            const months = hasWork ? currentWork.exp_m || 0 : 0;

            container.innerHTML = `
                <div class="form-group" style="margin-bottom: 10px;">
                    <label style="display:inline-flex; align-items:center; cursor:pointer;">
                        <input type="checkbox" id="has_current_work" ${hasWork ? 'checked' : ''} onchange="toggleCurrentWorkFields()" style="width:auto; margin-right:8px;">
                        I am currently employed
                    </label>
                </div>
                <div id="current-work-fields" style="display: ${hasWork ? 'block' : 'none'};" class="education-form-item">
                    <div class="form-group">
                        <label>Job Title (Worked As) *</label>
                        <input type="text" id="cw_worked_as" value="${workedAs}" placeholder="e.g., Software Engineer">
                    </div>
                    <div class="form-group">
                        <label>Company *</label>
                        <input type="text" id="cw_company" value="${company}" placeholder="e.g., Google">
                    </div>
                    <div class="form-group">
                        <label>Duration of Experience *</label>
                        <div style="display: flex; gap: 10px;">
                            <input type="number" id="cw_exp_y" min="0" value="${years}" placeholder="Years" style="flex: 1;">
                            <input type="number" id="cw_exp_m" min="0" max="11" value="${months}" placeholder="Months" style="flex: 1;">
                        </div>
                    </div>
                </div>
            `;
        }

        window.toggleCurrentWorkFields = function() {
            const checked = document.getElementById('has_current_work').checked;
            document.getElementById('current-work-fields').style.display = checked ? 'block' : 'none';
        };

        const prevExpContainer = document.getElementById('previous-experience-container');
        function renderPreviousExperience() {
            prevExpContainer.innerHTML = '';
            if (previousExperience.length === 0) {
                prevExpContainer.innerHTML = '<p class="empty-state">No previous experience added.</p>';
                return;
            }
            previousExperience.forEach((exp, index) => {
                const years = exp.exp_y || 0;
                const months = exp.exp_m || 0;

                const item = document.createElement('div');
                item.className = 'education-form-item';
                item.innerHTML = `
                    <button type="button" class="remove-btn" onclick="removeExperience(${index})">×</button>
                    <div class="form-group">
                        <label>Job Title (Worked As) *</label>
                        <input type="text" class="exp-worked-as" value="${exp.worked_as || ''}" required>
                    </div>
                    <div class="form-group">
                        <label>Company *</label>
                        <input type="text" class="exp-company" value="${exp.company || ''}" required>
                    </div>
                    <div class="form-group">
                        <label>Duration of Experience *</label>
                        <div style="display: flex; gap: 10px;">
                            <input type="number" class="exp-y" min="0" value="${years}" placeholder="Years" required style="flex: 1;">
                            <input type="number" class="exp-m" min="0" max="11" value="${months}" placeholder="Months" required style="flex: 1;">
                        </div>
                    </div>
                `;
                prevExpContainer.appendChild(item);
            });
        }

        function removeExperience(index) {
            previousExperience.splice(index, 1);
            renderPreviousExperience();
        }

        document.getElementById('add-experience-btn').addEventListener('click', () => {
            previousExperience.push({ worked_as: '', company: '', exp_y: 0, exp_m: 0 });
            renderPreviousExperience();
        });

        const educationContainer = document.getElementById('education-container');
        function renderEducation() {
            educationContainer.innerHTML = '';
            if (educationRecords.length === 0) {
                educationContainer.innerHTML = '<p class="empty-state">No education records.</p>';
                return;
            }
            educationRecords.forEach((edu, index) => {
                let currentEduValue = edu.education;
                if (typeof currentEduValue === 'number' && eduLevels[currentEduValue]) {
                    currentEduValue = eduLevels[currentEduValue].value;
                }
                const eduItem = document.createElement('div');
                eduItem.className = 'education-form-item';
                eduItem.innerHTML = `
                    <button type="button" class="remove-btn" onclick="removeEducation(${index})">×</button>
                    <div class="form-group">
                        <label>Education Level *</label>
                        <select class="edu-level" required>
                            ${eduLevels.map(level => `<option value="${level.value}" ${currentEduValue === level.value ? 'selected' : ''}>${level.label}</option>`).join('')}
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Major/Field of Study *</label>
                        <input type="text" class="edu-major" value="${edu.major || ''}" required>
                    </div>
                    <div class="form-group">
                        <label>Institution Name *</label>
                        <input type="text" class="edu-institution" value="${edu.edu_institution || ''}" required>
                    </div>
                `;
                educationContainer.appendChild(eduItem);
            });
        }

        function removeEducation(index) {
            educationRecords.splice(index, 1);
            renderEducation();
        }

        document.getElementById('add-education-btn').addEventListener('click', () => {
            educationRecords.push({ education: 'Bachelors', major: '', edu_institution: '' });
            renderEducation();
        });

        editBtn.addEventListener('click', () => {
            viewMode.style.display = 'none';
            editMode.style.display = 'block';
            editBtn.style.display = 'none';
            cancelBtn.style.display = 'inline-block';
            clearAlert();
        });

        cancelBtn.addEventListener('click', () => {
            editMode.style.display = 'none';
            viewMode.style.display = 'block';
            cancelBtn.style.display = 'none';
            editBtn.style.display = 'inline-block';

            profileForm.reset();
            skills = <?php echo json_encode($profile["skills"] ?? []); ?>;
            educationRecords = <?php echo json_encode(
                $profile["education"] ?? [],
            ); ?>;
            currentWork = <?php echo json_encode(
                $profile["current_work"] ?? null,
            ); ?>;
            previousExperience = <?php echo json_encode(
                $profile["previous_experience"] ?? [],
            ); ?>;

            renderSkills();
            renderEducation();
            renderCurrentWork();
            renderPreviousExperience();
            updateToggleLabels();
            clearAlert();
        });

        renderSkills();
        renderEducation();
        renderCurrentWork();
        renderPreviousExperience();
        updateToggleLabels();

        profileForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            let cwData = null;
            if (document.getElementById('has_current_work').checked) {
                cwData = {
                    worked_as: document.getElementById('cw_worked_as').value.trim(),
                    company: document.getElementById('cw_company').value.trim(),
                    exp_y: parseInt(document.getElementById('cw_exp_y').value || 0),
                    exp_m: parseInt(document.getElementById('cw_exp_m').value || 0)
                };
            }

            const updatedExperience = [];
            prevExpContainer.querySelectorAll('.education-form-item').forEach(item => {
                const workedAs = item.querySelector('.exp-worked-as').value.trim();
                const company = item.querySelector('.exp-company').value.trim();

                if (workedAs && company) {
                    updatedExperience.push({
                        worked_as: workedAs,
                        company: company,
                        exp_y: parseInt(item.querySelector('.exp-y').value || 0),
                        exp_m: parseInt(item.querySelector('.exp-m').value || 0)
                    });
                }
            });

            const updatedEducation = [];
            educationContainer.querySelectorAll('.education-form-item').forEach(item => {
                const level = item.querySelector('.edu-level').value;
                const major = item.querySelector('.edu-major').value.trim();
                const institution = item.querySelector('.edu-institution').value.trim();
                if (level && major && institution) updatedEducation.push({ education: level, major: major, edu_institution: institution });
            });

            const fd = new FormData();
            fd.append('name', document.getElementById('name').value.trim());
            fd.append('email', document.getElementById('email').value.trim());
            fd.append('is_finding_job', document.getElementById('is_finding_job').checked ? '1' : '0');
            fd.append('about_user', document.getElementById('about_user').value.trim());

            if (skills.length > 0) fd.append('skills', JSON.stringify(skills));
            if (updatedEducation.length > 0) fd.append('education', JSON.stringify(updatedEducation));
            if (cwData) fd.append('current_work', JSON.stringify(cwData));
            if (updatedExperience.length > 0) fd.append('previous_experience', JSON.stringify(updatedExperience));

            const pfpFile = document.getElementById('profile_picture').files[0];
            if (pfpFile) fd.append('profile_picture', pfpFile);

            const resumeFile = document.getElementById('resume').files[0];
            if (resumeFile) fd.append('resume', resumeFile);

            saveBtn.disabled = true;
            saveBtn.textContent = '💾 Saving...';

            try {
                const response = await fetch('profile.php', {
                    method: 'POST',
                    body: fd
                });

                const text = await response.text();
                const result = JSON.parse(text);

                if (result.status === 'success') {
                    showAlert('Profile updated successfully! Reloading...', 'success');
                    setTimeout(() => window.location.reload(), 1500);
                } else {
                    showAlert(result.message, 'error');
                    saveBtn.disabled = false;
                    saveBtn.textContent = '💾 Save Changes';
                }
            } catch (error) {
                showAlert('Failed to parse update request properly.', 'error');
                saveBtn.disabled = false;
                saveBtn.textContent = '💾 Save Changes';
            }
        });

        function showAlert(message, type) {
            alert.textContent = message;
            alert.className = `alert alert-${type} show`;
            setTimeout(() => alert.classList.remove('show'), 5000);
        }
        function clearAlert() { alert.classList.remove('show'); }

        window.removeSkill = removeSkill;
        window.removeEducation = removeEducation;
        window.removeExperience = removeExperience;
        window.updateToggleLabels = updateToggleLabels;
    </script>
</body>
</html>
