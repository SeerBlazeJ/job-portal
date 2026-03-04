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
    <title>My Profile — JobPortal</title>
    <link rel="stylesheet" href="./css/styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
       
    </style>
</head>
<body>

    <div class="bg-orbs">
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
        <div class="orb orb-3"></div>
    </div>

    <div class="dash-container profile-page-container">
        
        <header class="dash-header">
            <h1 class="dash-title">👤 My Profile</h1>
            <div class="dash-nav">
                <a href="dashboard.php" class="dash-btn dash-btn-glass">← Back to Dashboard</a>
            </div>
        </header>

        <div class="profile-wrapper">
            
            <div class="profile-top-bar">
                <h2>Manage Account</h2>
                <div>
                    <button id="edit-btn" class="dash-btn dash-btn-primary view-mode">✏️ Edit Profile</button>
                    <button id="cancel-btn" class="dash-btn dash-btn-danger edit-mode">✖ Cancel</button>
                </div>
            </div>

            <div class="profile-tabs-nav view-mode">
                <button class="profile-tab active" onclick="switchTab('profile')">Profile Info</button>
                <?php if (!$profile["is_finding_job"]): ?>
                    <button class="profile-tab" id="tab-companies" onclick="switchTab('companies')">My Companies</button>
                    <button class="profile-tab" id="tab-my-jobs" onclick="switchTab('jobs')">My Posted Jobs</button>
                <?php else: ?>
                    <button class="profile-tab" id="tab-my-apps" onclick="switchTab('apps')">My Applications</button>
                <?php endif; ?>
            </div>

            <div id="alert" class="profile-alert"></div>

            <div id="view-mode" class="view-mode tab-content active">

                <?php if (!empty($profile["working_at"])): ?>
                    <div class="dynamic-list-item" style="border-left-color: var(--emerald-500); background: rgba(16,185,129,0.05);">
                        <h4 style="margin: 0 0 10px; color: var(--emerald-400);">🏢 Company Affiliations</h4>
                        <?php foreach ($profile["working_at"] as $comp): ?>
                            <div style="font-size: 0.9rem; color: var(--text-main); display: flex; align-items: center; flex-wrap: wrap; margin-bottom: 8px;">
                                <strong><?php echo htmlspecialchars($comp["designation"]); ?></strong>
                                &nbsp;at&nbsp;
                                <a href="company.php?id=<?php echo urlencode($comp["company_id"]); ?>" style="color: var(--cyan-400); font-weight: bold; text-decoration: none;">
                                    <?php echo htmlspecialchars($comp["company_name"]); ?>
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

                <div style="text-align: center; margin-bottom: 2.5rem;">
                    <?php if (!empty($profile["profile_picture"])): ?>
                        <img src="<?php echo htmlspecialchars($profile["profile_picture"]); ?>" class="profile-avatar-display">
                    <?php else: ?>
                        <div class="profile-avatar-display">👤</div>
                    <?php endif; ?>

                    <?php if (!empty($profile["resume"])): ?>
                        <div style="margin-top: 1rem;">
                            <a href="<?php echo htmlspecialchars($profile["resume"]); ?>" download class="dash-btn badge-salary">📄 Download Resume</a>
                        </div>
                    <?php endif; ?>
                </div>

                <div class="profile-section">
                    <h3>📋 Basic Information</h3>
                    <div class="info-grid">
                        <div class="info-label">Username</div>
                        <div class="info-value"><?php echo htmlspecialchars($profile["uid"]); ?></div>
                        <div class="info-label">Name</div>
                        <div class="info-value"><?php echo htmlspecialchars($profile["name"]); ?></div>
                        <div class="info-label">Email</div>
                        <div class="info-value"><?php echo htmlspecialchars($profile["email"]); ?></div>
                        <div class="info-label">Account Role</div>
                        <div class="info-value">
                            <?php if ($profile["is_finding_job"]): ?>
                                <span class="dash-badge badge-role">🔍 Job Seeker</span>
                            <?php else: ?>
                                <span class="dash-badge badge-salary" style="color: var(--amber-400); border-color: rgba(245,158,11,0.3); background: rgba(245,158,11,0.1);">📢 Job Poster</span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>

                <?php if (!empty($profile["about_user"])): ?>
                <div class="profile-section">
                    <h3>📝 About Me</h3>
                    <div style="background: rgba(99,102,241,0.02); padding: 1.5rem; border-radius: var(--r-md); border: 1px solid rgba(99,102,241,0.08);">
                        <p style="color: var(--text-main); line-height: 1.6;"><?php echo nl2br(htmlspecialchars($profile["about_user"])); ?></p>
                    </div>
                </div>
                <?php endif; ?>

                <div class="profile-section">
                    <h3>🎯 Skills</h3>
                    <?php if (!empty($profile["skills"])): ?>
                        <div class="card-tags">
                            <?php foreach ($profile["skills"] as $skill): ?>
                                <span class="dash-badge badge-skill"><?php echo htmlspecialchars($skill); ?></span>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <p class="dash-empty">No skills added yet</p>
                    <?php endif; ?>
                </div>

                <div class="profile-section">
                    <h3>💼 Work Experience</h3>
                    <?php if (!empty($profile["current_work"])): ?>
                        <div class="dynamic-list-item" style="border-left-color: var(--emerald-500);">
                            <div>
                                <span class="dash-badge badge-salary" style="margin-bottom: 0.5rem;">Current Role</span>
                                <strong style="margin-left: 10px; font-size: 1.1rem; color: var(--text-primary);"><?php echo htmlspecialchars($profile["current_work"]["worked_as"]); ?></strong>
                            </div>
                            <div style="margin-top: 8px; color: var(--text-secondary); font-size: 0.9rem;">
                                🏢 <?php echo htmlspecialchars($profile["current_work"]["company"]); ?>
                                &nbsp;•&nbsp; ⏱️ <?php echo formatExp($profile["current_work"]["exp"]); ?>
                            </div>
                        </div>
                    <?php endif; ?>

                    <?php if (!empty($profile["previous_experience"])): ?>
                        <?php foreach ($profile["previous_experience"] as $exp): ?>
                            <div class="dynamic-list-item">
                                <strong style="font-size: 1.1rem; color: var(--text-primary);"><?php echo htmlspecialchars($exp["worked_as"]); ?></strong>
                                <div style="margin-top: 8px; color: var(--text-secondary); font-size: 0.9rem;">
                                    🏢 <?php echo htmlspecialchars($exp["company"]); ?>
                                    &nbsp;•&nbsp; ⏱️ <?php echo formatExp($exp["exp"]); ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>

                    <?php if (empty($profile["current_work"]) && empty($profile["previous_experience"])): ?>
                        <div class="dash-empty">
                            <p>No work experience records added yet</p>
                        </div>
                    <?php endif; ?>
                </div>

                <div class="profile-section">
                    <h3>🎓 Education</h3>
                    <?php if (!empty($profile["education"])): ?>
                        <?php foreach ($profile["education"] as $edu): ?>
                            <div class="dynamic-list-item" style="border-left-color: var(--cyan-400);">
                                <div>
                                    <span class="dash-badge badge-location" style="margin-bottom: 0.5rem;"><?php echo htmlspecialchars($edu["education"]); ?></span>
                                    <strong style="margin-left: 10px; font-size: 1.1rem; color: var(--text-primary);"><?php echo htmlspecialchars($edu["major"]); ?></strong>
                                </div>
                                <div style="margin-top: 8px; color: var(--text-secondary); font-size: 0.9rem;">
                                    📍 <?php echo htmlspecialchars($edu["edu_institution"]); ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="dash-empty">
                            <p>No education records added yet</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <div id="content-companies" class="view-mode tab-content">
                <div class="profile-section">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                        <h3 style="margin: 0;">🏢 My Affiliated Companies</h3>
                        <a href="create_company.php" class="dash-btn dash-btn-primary">➕ Register New Company</a>
                    </div>

                    <?php if (!empty($profile["working_at"])): ?>
                        <?php foreach ($profile["working_at"] as $comp): ?>
                            <div class="dash-card" style="flex-direction: row; align-items: center; gap: 1.5rem; margin-bottom: 1rem;">
                                <div style="width: 50px; height: 50px; border-radius: var(--r-sm); background: rgba(99,102,241,0.1); display: flex; align-items: center; justify-content: center; font-size: 20px;">🏢</div>
                                <div style="flex: 1;">
                                    <h3 class="card-title" style="margin-bottom: 0.2rem;">
                                        <a href="company.php?id=<?php echo urlencode($comp["company_id"]); ?>"><?php echo htmlspecialchars($comp["company_name"]); ?></a>
                                    </h3>
                                    <div style="color: var(--text-secondary); font-size: 0.85rem;">
                                        <strong>Role:</strong> <?php echo htmlspecialchars($comp["designation"]); ?>
                                        <?php if ($comp["is_verified"]): ?>
                                            <span class="dash-badge badge-salary" style="padding: 0.1rem 0.4rem; font-size: 0.65rem; margin-left: 0.5rem;">✓ Verified</span>
                                        <?php else: ?>
                                            <span class="dash-badge" style="padding: 0.1rem 0.4rem; font-size: 0.65rem; margin-left: 0.5rem; background: rgba(245,158,11,0.1); color: var(--amber-400); border: 1px solid rgba(245,158,11,0.3);">⏳ Pending</span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <div style="display:flex; gap: 0.5rem;">
                                    <a href="company.php?id=<?php echo urlencode($comp["company_id"]); ?>" class="dash-btn dash-btn-glass">View</a>
                                    <?php if (isset($comp["is_owner"]) && $comp["is_owner"]): ?>
                                        <a href="edit_company.php?id=<?php echo urlencode($comp["company_id"]); ?>" class="dash-btn dash-btn-glass" style="color: var(--cyan-400);">Edit</a>
                                        <button onclick="deleteCompany('<?php echo htmlspecialchars($comp["company_id"]); ?>')" class="dash-btn dash-btn-danger">Delete</button>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="dash-empty">
                            <div style="font-size: 2.5rem; margin-bottom: 1rem;">🏢</div>
                            <h3>No Affiliations</h3>
                            <p>Register your company to start posting jobs and managing employees.</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <div id="content-jobs" class="view-mode tab-content">
                <div id="my-jobs-list">
                    <p style="color: var(--text-muted);">Loading your job posts...</p>
                </div>
            </div>

            <div id="content-apps" class="view-mode tab-content">
                <div class="profile-section">
                    <h3 style="margin-bottom: 1.5rem;">📝 My Job Applications</h3>
                    <div id="my-apps-list">
                        <p style="color: var(--text-muted);">Loading your applications...</p>
                    </div>
                </div>
            </div>

            <div id="edit-mode" class="edit-mode">
                
                <div class="profile-section" style="background: rgba(99,102,241,0.02); border: 1px solid rgba(99,102,241,0.1); padding: 1.5rem; border-radius: var(--r-md);">
                    <h3 style="margin-bottom: 0.5rem;">🏢 Company Affiliations</h3>
                    <?php if (!empty($profile["working_at"])): ?>
                        <?php foreach ($profile["working_at"] as $comp): ?>
                            <p style="font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 0.5rem;">You are affiliated with <strong style="color: var(--text-primary);"><?php echo htmlspecialchars($comp["company_name"]); ?></strong>.</p>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem;">You are not currently linked to any company.</p>
                    <?php endif; ?>
                </div>

                <form id="profile-form" enctype="multipart/form-data">
                    
                    <div class="profile-section">
                        <h3>📋 Basic Information & Files</h3>

                        <div class="form-group" style="margin-bottom: 1.25rem;">
                            <label class="form-label" for="profile_picture">Profile Picture (Image)</label>
                            <input type="file" id="profile_picture" name="profile_picture" accept="image/*" class="form-input">
                        </div>
                        <div class="form-group" style="margin-bottom: 1.25rem;">
                            <label class="form-label" for="resume">Resume (PDF/Word)</label>
                            <input type="file" id="resume" name="resume" accept=".pdf,.doc,.docx" class="form-input">
                        </div>

                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.25rem;">
                            <div class="form-group">
                                <label class="form-label" for="name">Name *</label>
                                <input type="text" id="name" name="name" class="form-input" value="<?php echo htmlspecialchars($profile["name"]); ?>" required style="padding-left: 1rem;">
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="email">Email *</label>
                                <input type="email" id="email" name="email" class="form-input" value="<?php echo htmlspecialchars($profile["email"]); ?>" required style="padding-left: 1rem;">
                            </div>
                        </div>

                        <div class="form-group" style="margin-bottom: 1.25rem;">
                            <label class="form-label" for="about_user">About Me (Brief Bio)</label>
                            <textarea id="about_user" name="about_user" class="form-input" placeholder="Tell us a little about yourself..."><?php echo htmlspecialchars($profile["about_user"] ?? ""); ?></textarea>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Primary Role</label>
                            <div class="toggle-switch-container">
                                <span class="toggle-label <?php echo !$profile["is_finding_job"] ? "active" : ""; ?>" id="label-poster">Job Poster</span>
                                <label class="theme-switch">
                                    <input type="checkbox" id="is_finding_job" name="is_finding_job" <?php echo $profile["is_finding_job"] ? "checked" : ""; ?> onchange="updateToggleLabels()">
                                    <span class="theme-slider"></span>
                                </label>
                                <span class="toggle-label <?php echo $profile["is_finding_job"] ? "active" : ""; ?>" id="label-seeker">Job Seeker</span>
                            </div>
                        </div>
                    </div>

                    <div class="profile-section">
                        <h3>🎯 Skills</h3>
                        <div class="form-group">
                            <label class="form-label" for="skills_input">Add Skills</label>
                            <input type="text" id="skills_input" class="form-input" placeholder="Type a skill and press Enter" style="padding-left: 1rem;">
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
                        <button type="button" class="dash-btn dash-btn-glass" id="add-experience-btn">➕ Add Experience Record</button>
                    </div>

                    <div class="profile-section">
                        <h3>🎓 Education</h3>
                        <div id="education-container"></div>
                        <button type="button" class="dash-btn dash-btn-glass" id="add-education-btn">➕ Add Education Record</button>
                    </div>

                    <div style="margin-top: 3rem; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 2rem;">
                        <button type="submit" class="dash-btn dash-btn-primary" id="save-btn" style="width: 100%; justify-content: center; font-size: 1rem; padding: 1rem;">💾 Save Changes</button>
                    </div>
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
        const alertBox = document.getElementById('alert');

        let skills = <?php echo json_encode($profile["skills"] ?? []); ?>;
        let educationRecords = <?php echo json_encode($profile["education"] ?? []); ?>;
        let currentWork = <?php echo json_encode($profile["current_work"] ?? null); ?>;
        let previousExperience = <?php echo json_encode($profile["previous_experience"] ?? []); ?>;

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
                        container.innerHTML = '<div class="dash-empty"><p>You haven\'t posted any jobs yet.</p></div>';
                        return;
                    }

                    let html = '';
                    result.data.forEach(job => {
                        const companyLink = job.company_id
                            ? `<a href="company.php?id=${encodeURIComponent(job.company_id)}" style="color: var(--cyan-400); font-weight: bold; text-decoration: none;">${job.company_name}</a>`
                            : (job.company_name || 'Your Company');

                        html += `
                            <div class="dash-card" style="margin-bottom: 1.5rem;">
                                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap: wrap; gap: 1rem;">
                                    <h3 class="card-title" style="margin:0;">${job.title}</h3>
                                    <div style="display: flex; gap: 0.5rem;">
                                        <a href="edit_job.php?id=${encodeURIComponent(job.id)}" class="dash-btn dash-btn-glass" style="color: var(--cyan-400);">Edit</a>
                                        <button onclick="deleteJob('${job.id}')" class="dash-btn dash-btn-danger">Delete</button>
                                        <button class="dash-btn dash-btn-primary" onclick="toggleApplicants('${job.id}', this)">View Applicants</button>
                                    </div>
                                </div>
                                <p style="color: var(--text-secondary); font-size: 0.85rem; margin-top: 0.5rem;">🏢 ${companyLink} &nbsp;|&nbsp; 📍 ${job.location} &nbsp;|&nbsp; <span style="color:var(--emerald-400); font-family:'JetBrains Mono',monospace;">💰 $${job.salary_range_start} - $${job.salary_range_end}</span></p>
                                <div id="applicants-${job.id}" style="display:none; margin-top: 1.5rem; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 1.5rem;">
                                    <p style="color:var(--text-muted); font-size:0.85rem;">Loading applicants...</p>
                                </div>
                            </div>
                        `;
                    });
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div class="dash-empty"><p>Failed to load jobs.</p></div>';
                }
            } catch (e) {
                container.innerHTML = '<div class="dash-empty"><p>Error loading jobs. Session may have expired.</p></div>';
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
                btn.classList.replace('dash-btn-glass', 'dash-btn-primary');
                return;
            }

            container.style.display = 'block';
            btn.textContent = 'Hide Applicants';
            btn.classList.replace('dash-btn-primary', 'dash-btn-glass');
            container.innerHTML = '<p style="color:var(--text-muted); font-size:0.85rem;">Loading applicants...</p>';

            try {
                const res = await fetch('employer_api.php?action=applicants&job_id=' + encodeURIComponent(jobId));
                const text = await res.text();
                const result = JSON.parse(text);

                if (result.success && result.data) {
                    if (result.data.length === 0) {
                        container.innerHTML = '<p style="color:var(--text-muted); font-size:0.85rem; font-style:italic;">No one has applied to this position yet.</p>';
                        return;
                    }

                    let html = `<h4 style="margin-bottom: 1rem; color: var(--indigo-400);">${result.data.length} Applicant(s)</h4>`;
                    result.data.forEach(app => {
                        const dateObj = new Date(app.datetime_applied);
                        const prettyDate = isNaN(dateObj.getTime()) ? 'Recently' : dateObj.toLocaleDateString();

                        const statusSelect = `
                            <select onchange="updateAppStatus('${jobId}', '${app.user.id}', this.value)" class="form-input" style="padding: 0.3rem 0.5rem; font-size: 0.8rem; height: auto; width: auto;">
                                <option value="Pending" ${app.status.toLowerCase() === 'pending' ? 'selected' : ''}>Pending</option>
                                <option value="Accepted" ${app.status.toLowerCase() === 'accepted' ? 'selected' : ''}>Accepted</option>
                                <option value="Rejected" ${app.status.toLowerCase() === 'rejected' ? 'selected' : ''}>Rejected</option>
                            </select>
                        `;

                        html += `
                            <div class="dynamic-list-item" style="padding: 1rem;">
                                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap: wrap; gap: 1rem;">
                                    <strong style="font-size: 1.1rem; color: var(--text-primary);">${app.user.name}</strong>
                                    ${statusSelect}
                                </div>
                                <div style="font-size:0.85rem; color:var(--text-secondary); margin-top:0.5rem;">
                                    📧 <a href="mailto:${app.user.email}" style="color:var(--indigo-400); text-decoration:none;">${app.user.email}</a>
                                    <br>🕒 Applied on ${prettyDate}
                                </div>
                                <div style="margin-top:1rem;">
                                    <a href="user_details.php?id=${encodeURIComponent(app.user.id)}" target="_blank" class="dash-btn dash-btn-glass" style="font-size:0.8rem; padding:0.4rem 0.8rem;">View Full Profile ↗</a>
                                </div>
                            </div>
                        `;
                    });
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<p style="color:var(--rose-400); font-size:0.85rem;">Failed to load applicants.</p>';
                }
            } catch (e) {
                container.innerHTML = '<p style="color:var(--rose-400); font-size:0.85rem;">Error parsing applicant data.</p>';
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
                        container.innerHTML = '<div class="dash-empty"><p>You have not applied to any jobs yet.</p></div>';
                        return;
                    }

                    let html = '';
                    result.data.forEach(app => {
                        let statusColor = app.status.toLowerCase() === 'accepted' ? 'var(--emerald-400)' : (app.status.toLowerCase() === 'rejected' ? 'var(--rose-400)' : 'var(--amber-400)');
                        let statusBg = app.status.toLowerCase() === 'accepted' ? 'rgba(16,185,129,0.1)' : (app.status.toLowerCase() === 'rejected' ? 'rgba(251,113,133,0.1)' : 'rgba(245,158,11,0.1)');
                        let statusBorder = app.status.toLowerCase() === 'accepted' ? 'rgba(16,185,129,0.3)' : (app.status.toLowerCase() === 'rejected' ? 'rgba(251,113,133,0.3)' : 'rgba(245,158,11,0.3)');

                        const dateObj = new Date(app.datetime_applied);
                        const prettyDate = isNaN(dateObj.getTime()) ? 'Recently' : dateObj.toLocaleDateString();

                        const companyLink = app.job.company_id
                            ? `<a href="company.php?id=${encodeURIComponent(app.job.company_id)}" style="color: var(--cyan-400); font-weight: bold; text-decoration: none;">${app.job.company_name}</a>`
                            : (app.job.company_name || app.job.employer_name);

                        html += `
                            <div class="dash-card" style="border-left: 3px solid ${statusColor}; margin-bottom: 1rem;">
                                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap: wrap; gap: 0.5rem;">
                                    <h3 class="card-title" style="margin:0;">${app.job.title}</h3>
                                    <span class="dash-badge" style="background:${statusBg}; color:${statusColor}; border: 1px solid ${statusBorder};">${app.status.toUpperCase()}</span>
                                </div>
                                <div style="color: var(--text-secondary); font-size: 0.85rem; margin-top: 0.5rem;">
                                    🏢 ${companyLink} &nbsp;|&nbsp; 📍 ${app.job.location}
                                </div>
                                <div style="color: var(--text-muted); font-size: 0.75rem; margin-top: 0.75rem;">
                                    Applied on: ${prettyDate}
                                </div>
                            </div>
                        `;
                    });
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div class="dash-empty"><p>Failed to load applications.</p></div>';
                }
            } catch (e) {
                container.innerHTML = '<div class="dash-empty"><p>Error loading applications.</p></div>';
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
                tag.className = 'editable-skill-tag';
                tag.innerHTML = `${skill} <span onclick="removeSkill(${index})">×</span>`;
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
                <div class="form-group" style="margin-bottom: 1rem;">
                    <label class="checkbox-label">
                        <input type="checkbox" id="has_current_work" class="checkbox-input" onchange="toggleCurrentWorkFields()">
                        <span class="checkbox-custom"></span>
                        <span class="checkbox-text">I am currently employed</span>
                    </label>
                </div>
                <div id="current-work-fields" style="display: ${hasWork ? 'block' : 'none'};" class="dynamic-list-item">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                        <div class="form-group">
                            <label class="form-label">Job Title (Worked As) *</label>
                            <input type="text" id="cw_worked_as" class="form-input" value="${workedAs}" placeholder="e.g., Software Engineer" style="padding-left: 1rem;">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Company *</label>
                            <input type="text" id="cw_company" class="form-input" value="${company}" placeholder="e.g., Google" style="padding-left: 1rem;">
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Duration of Experience *</label>
                        <div style="display: flex; gap: 1rem;">
                            <input type="number" id="cw_exp_y" class="form-input" min="0" value="${years}" placeholder="Years" style="flex: 1; padding-left: 1rem;">
                            <input type="number" id="cw_exp_m" class="form-input" min="0" max="11" value="${months}" placeholder="Months" style="flex: 1; padding-left: 1rem;">
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
                prevExpContainer.innerHTML = '<div class="dash-empty" style="padding: 2rem;"><p>No previous experience added.</p></div>';
                return;
            }
            previousExperience.forEach((exp, index) => {
                const years = exp.exp_y || 0;
                const months = exp.exp_m || 0;

                const item = document.createElement('div');
                item.className = 'dynamic-list-item';
                item.innerHTML = `
                    <div class="remove-btn-corner" onclick="removeExperience(${index})">×</div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                        <div class="form-group">
                            <label class="form-label">Job Title (Worked As) *</label>
                            <input type="text" class="exp-worked-as form-input" value="${exp.worked_as || ''}" required style="padding-left: 1rem;">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Company *</label>
                            <input type="text" class="exp-company form-input" value="${exp.company || ''}" required style="padding-left: 1rem;">
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Duration of Experience *</label>
                        <div style="display: flex; gap: 1rem;">
                            <input type="number" class="exp-y form-input" min="0" value="${years}" placeholder="Years" required style="flex: 1; padding-left: 1rem;">
                            <input type="number" class="exp-m form-input" min="0" max="11" value="${months}" placeholder="Months" required style="flex: 1; padding-left: 1rem;">
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
                educationContainer.innerHTML = '<div class="dash-empty" style="padding: 2rem;"><p>No education records added.</p></div>';
                return;
            }
            educationRecords.forEach((edu, index) => {
                let currentEduValue = edu.education;
                if (typeof currentEduValue === 'number' && eduLevels[currentEduValue]) {
                    currentEduValue = eduLevels[currentEduValue].value;
                }
                const eduItem = document.createElement('div');
                eduItem.className = 'dynamic-list-item';
                eduItem.innerHTML = `
                    <div class="remove-btn-corner" onclick="removeEducation(${index})">×</div>
                    <div class="form-group" style="margin-bottom: 1rem; max-width: 50%;">
                        <label class="form-label">Education Level *</label>
                        <select class="edu-level form-input" required>
                            ${eduLevels.map(level => `<option value="${level.value}" ${currentEduValue === level.value ? 'selected' : ''}>${level.label}</option>`).join('')}
                        </select>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                        <div class="form-group">
                            <label class="form-label">Major/Field of Study *</label>
                            <input type="text" class="edu-major form-input" value="${edu.major || ''}" required style="padding-left: 1rem;">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Institution Name *</label>
                            <input type="text" class="edu-institution form-input" value="${edu.edu_institution || ''}" required style="padding-left: 1rem;">
                        </div>
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
            educationRecords = <?php echo json_encode($profile["education"] ?? []); ?>;
            currentWork = <?php echo json_encode($profile["current_work"] ?? null); ?>;
            previousExperience = <?php echo json_encode($profile["previous_experience"] ?? []); ?>;

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
            prevExpContainer.querySelectorAll('.dynamic-list-item').forEach(item => {
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
            educationContainer.querySelectorAll('.dynamic-list-item').forEach(item => {
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
            saveBtn.textContent = '⏳ Saving...';

            try {
                const response = await fetch('profile.php', {
                    method: 'POST',
                    body: fd
                });

                const text = await response.text();
                console.log('Response status:', response.status);
                console.log('Response text:', text);
                
                let result;
                try {
                    result = JSON.parse(text);
                } catch (parseErr) {
                    console.error('JSON Parse Error:', parseErr);
                    console.log('Raw response was:', text.substring(0, 500));
                    showAlert('Server response error. Check console for details.', 'error');
                    saveBtn.disabled = false;
                    saveBtn.textContent = '💾 Save Changes';
                    return;
                }

                if (result.status === 'success') {
                    showAlert('Profile updated successfully! Reloading...', 'success');
                    setTimeout(() => window.location.reload(), 1500);
                } else {
                    showAlert(result.message || 'Failed to update profile', 'error');
                    saveBtn.disabled = false;
                    saveBtn.textContent = '💾 Save Changes';
                }
            } catch (error) {
                console.error('Fetch Error:', error);
                showAlert('Network error or failed request. Check console for details.', 'error');
                saveBtn.disabled = false;
                saveBtn.textContent = '💾 Save Changes';
            }
        });

        function showAlert(message, type) {
            alertBox.innerHTML = `<span>${type === 'success' ? '✓' : '⚠️'}</span> ${message}`;
            alertBox.className = `profile-alert alert-${type} show`;
            setTimeout(() => alertBox.classList.remove('show'), 5000);
        }
        function clearAlert() { alertBox.classList.remove('show'); }

        window.removeSkill = removeSkill;
        window.removeEducation = removeEducation;
        window.removeExperience = removeExperience;
        window.updateToggleLabels = updateToggleLabels;
    </script>
</body>
</html>