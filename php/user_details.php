<?php
// user_details.php
require_once 'config.php';

if (!isAuthenticated()) {
    header('Location: signin.php');
    exit;
}

if (!isset($_GET['id']) || empty($_GET['id'])) {
    die("User ID not provided. <a href='dashboard.php'>Return to Dashboard</a>");
}

function formatExp($days) {
    if ($days === null || $days === '') return 'N/A';

    $days = (int)$days;
    $months = floor($days / 30);
    $rem_days = $days % 30;

    $parts = [];
    if ($months > 0) $parts[] = "{$months}m";
    if ($rem_days > 0) $parts[] = "{$rem_days}d";

    return empty($parts) ? "0d" : implode(' ', $parts);
}

$targetId = $_GET['id'];
$token = getJWTToken();

// Fetch the requested user's profile
$apiResult = callRustAPI('/user-profile/' . urlencode($targetId), 'GET', null, $token);

if (!$apiResult['success']) {
    die("Failed to load user profile. Check if the user exists. <br><br><a href='dashboard.php'>Return to Dashboard</a>");
}

$profile = $apiResult['data'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($profile['name']); ?> - Profile</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; }

        .profile-card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .header-section { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #eee; padding-bottom: 20px; }
        .header-section h1 { color: #333; font-size: 28px; }
        .status-badge { padding: 5px 10px; border-radius: 15px; font-size: 14px; font-weight: bold; }
        .status-job-seeker { background: #c6f6d5; color: #276749; }
        .status-employer { background: #e2e8f0; color: #4a5568; }

        .info-group { margin-bottom: 25px; }
        .info-group h3 { color: #667eea; margin-bottom: 10px; font-size: 18px; border-bottom: 2px solid #f0f0f0; padding-bottom: 5px; display: inline-block;}
        .info-item { margin-bottom: 10px; color: #555; font-size: 15px; }
        .info-item strong { color: #333; }

        .skills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
        .skill-tag { background: #764ba2; color: white; padding: 5px 12px; border-radius: 15px; font-size: 13px; }

        .edu-card { background: #fafafa; border: 1px solid #e0e0e0; padding: 15px; border-radius: 8px; margin-bottom: 10px; }

        .btn-back { display: inline-block; background: #6c757d; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; margin-bottom: 20px; font-weight: 600; transition: background 0.3s;}
        .btn-back:hover { background: #5a6268; }
    </style>
</head>
<body>
    <div class="container">
        <a href="dashboard.php" class="btn-back">← Back to Dashboard</a>

        <div class="profile-card">
            <div class="header-section">
                <div>
                    <h1><?php echo htmlspecialchars($profile['name']); ?></h1>
                    <div style="margin-top: 5px; color: #666;">📧 <?php echo htmlspecialchars($profile['email']); ?></div>
                </div>
                <div>
                    <?php if($profile['is_finding_job']): ?>
                        <span class="status-badge status-job-seeker">Job Seeker</span>
                    <?php else: ?>
                        <span class="status-badge status-employer">Employer</span>
                    <?php endif; ?>
                </div>
            </div>

            <div class="info-group">
                <h3>Work Experience</h3>
                <?php if (!empty($profile['current_work'])): ?>
                    <div class="edu-card" style="border-left: 4px solid #28a745;">
                        <div style="margin-bottom: 8px;"><span style="background: #28a745; color: white; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold;">Current Role</span></div>
                        <div class="info-item"><strong>Title:</strong> <?php echo htmlspecialchars($profile['current_work']['worked_as']); ?></div>
                        <div class="info-item"><strong>Company:</strong> <?php echo htmlspecialchars($profile['current_work']['company']); ?></div>
                        <div class="info-item"><strong>Duration:</strong> <?php echo formatExp($profile['current_work']['exp']); ?></div>
                    </div>
                <?php endif; ?>

                <?php if (!empty($profile['previous_experience'])): ?>
                    <?php foreach ($profile['previous_experience'] as $exp): ?>
                        <div class="edu-card">
                            <div class="info-item"><strong>Title:</strong> <?php echo htmlspecialchars($exp['worked_as']); ?></div>
                            <div class="info-item"><strong>Company:</strong> <?php echo htmlspecialchars($exp['company']); ?></div>
                            <div class="info-item"><strong>Duration:</strong> <?php echo formatExp($exp['exp']); ?></div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>

                <?php if (empty($profile['current_work']) && empty($profile['previous_experience'])): ?>
                    <p class="info-item">No work experience listed.</p>
                <?php endif; ?>
            </div>

            <div class="info-group">
                <h3>Skills</h3>
                <?php if (!empty($profile['skills'])): ?>
                    <div class="skills">
                        <?php foreach ($profile['skills'] as $skill): ?>
                            <span class="skill-tag"><?php echo htmlspecialchars($skill); ?></span>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <p class="info-item">No specific skills listed.</p>
                <?php endif; ?>
            </div>

            <div class="info-group">
                <h3>Education</h3>
                <?php if (!empty($profile['education'])): ?>
                    <?php foreach ($profile['education'] as $edu): ?>
                        <div class="edu-card">
                            <div class="info-item"><strong>Institution:</strong> <?php echo htmlspecialchars($edu['edu_institution'] ?? 'N/A'); ?></div>
                            <div class="info-item"><strong>Major:</strong> <?php echo htmlspecialchars($edu['major']); ?></div>
                            <div class="info-item"><strong>Level:</strong> <?php echo htmlspecialchars($edu['education']); ?></div>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <p class="info-item">No education history provided.</p>
                <?php endif; ?>
            </div>

            <div style="margin-top: 30px; text-align: center;">
                <a href="mailto:<?php echo htmlspecialchars($profile['email']); ?>" style="background: #28a745; color: white; text-decoration: none; padding: 12px 25px; border-radius: 5px; font-weight: bold; display: inline-block;">Contact <?php echo htmlspecialchars($profile['name']); ?></a>
            </div>
        </div>
    </div>
</body>
</html>
