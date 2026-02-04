<?php
// dashboard.php
require_once 'config.php';

// Check authentication - redirect to signin if not logged in
if (!isAuthenticated()) {
    header('Location: signin.php');
    exit;
}

// Get JWT token
$token = getJWTToken();

// Fetch user profile to get uid
$profileResult = callRustAPI('/profile', 'GET', null, $token);

if (!$profileResult['success']) {
    // Token might be expired or invalid
    clearJWTCookie();
    header('Location: signin.php');
    exit;
}

$userProfile = $profileResult['data'];
$uid = $userProfile['uid'];
$userName = $userProfile['name'];

// Fetch jobs using uid
$jobsResult = callRustAPI('/home', 'POST', ['uid' => $uid], $token);
$jobs = $jobsResult['success'] ? $jobsResult['data'] : [];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Job Portal - Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }

        .header h1 {
            color: #333;
            font-size: 28px;
        }

        .header .user-info {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .header .username {
            color: #667eea;
            font-weight: 600;
        }

        .logout-btn {
            background: #dc3545;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: background 0.3s;
        }

        .logout-btn:hover {
            background: #c82333;
        }

        .jobs-section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .jobs-section h2 {
            color: #333;
            margin-bottom: 20px;
            font-size: 24px;
        }

        .jobs-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
        }

        .job-card {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            transition: transform 0.2s, box-shadow 0.2s;
            background: #fafafa;
        }

        .job-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
        }

        .job-card h3 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 20px;
        }

        .job-card .employer {
            color: #666;
            font-size: 14px;
            margin-bottom: 10px;
            font-weight: 600;
        }

        .job-card .description {
            color: #555;
            margin-bottom: 15px;
            line-height: 1.6;
            font-size: 14px;
        }

        .job-card .details {
            display: flex;
            flex-direction: column;
            gap: 8px;
            margin-bottom: 15px;
        }

        .job-card .detail-item {
            font-size: 13px;
            color: #666;
        }

        .job-card .detail-item strong {
            color: #333;
        }

        .job-card .skills {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 15px;
        }

        .skill-tag {
            background: #667eea;
            color: white;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 12px;
        }

        .no-jobs {
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }

        .no-jobs h3 {
            font-size: 22px;
            margin-bottom: 10px;
        }

        .salary {
            color: #28a745;
            font-weight: 600;
        }

        .location {
            color: #17a2b8;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Job Portal Dashboard</h1>
            <div class="user-info">
                <span class="username">Welcome, <?php echo htmlspecialchars($userName); ?>!</span>
                <form action="logout.php" method="POST" style="margin: 0;">
                    <button type="submit" class="logout-btn">Logout</button>
                </form>
            </div>
        </div>

        <div class="jobs-section">
            <h2>📋 Recommended Jobs for You</h2>

            <?php if (empty($jobs)): ?>
                <div class="no-jobs">
                    <h3>No jobs found at the moment</h3>
                    <p>Check back later for new opportunities!</p>
                </div>
            <?php else: ?>
                <div class="jobs-grid">
                    <?php foreach ($jobs as $job): ?>
                        <div class="job-card">
                            <h3><?php echo htmlspecialchars($job['title']); ?></h3>
                            <div class="employer">
                                🏢 <?php echo htmlspecialchars($job['employer_name']); ?>
                            </div>
                            <div class="description">
                                <?php echo htmlspecialchars($job['description']); ?>
                            </div>

                            <div class="details">
                                <?php if (!empty($job['location'])): ?>
                                    <div class="detail-item location">
                                        📍 <strong>Location:</strong> <?php echo htmlspecialchars($job['location']); ?>
                                    </div>
                                <?php endif; ?>

                                <?php if (isset($job['salary_range_start']) && isset($job['salary_range_end'])): ?>
                                    <div class="detail-item salary">
                                        💰 <strong>Salary:</strong> $<?php echo number_format($job['salary_range_start']); ?> - $<?php echo number_format($job['salary_range_end']); ?>
                                    </div>
                                <?php endif; ?>

                                <?php if (!empty($job['datetime_due'])): ?>
                                    <div class="detail-item">
                                        ⏰ <strong>Apply by:</strong> <?php echo date('M d, Y', strtotime($job['datetime_due'])); ?>
                                    </div>
                                <?php endif; ?>

                                <?php if (!empty($job['min_ed_lvl'])): ?>
                                    <div class="detail-item">
                                        🎓 <strong>Min. Education Level:</strong> <?php echo htmlspecialchars($job['min_ed_lvl']); ?>
                                    </div>
                                <?php endif; ?>
                            </div>

                            <?php if (!empty($job['skills_required']) && is_array($job['skills_required'])): ?>
                                <div class="skills">
                                    <?php foreach ($job['skills_required'] as $skill): ?>
                                        <span class="skill-tag"><?php echo htmlspecialchars($skill); ?></span>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
