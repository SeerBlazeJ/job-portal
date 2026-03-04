<?php
// company.php
require_once "config.php";

if (!isAuthenticated()) {
    header("Location: signin.php");
    exit();
}

// 1. THIS MUST COME FIRST! Intercept AJAX requests before checking for GET IDs.
if (
    $_SERVER["REQUEST_METHOD"] === "POST" &&
    isset($_GET["action"]) &&
    $_GET["action"] === "join"
) {
    header("Content-Type: application/json");
    $input = json_decode(file_get_contents("php://input"), true);

    if (empty($input["designation"])) {
        echo json_encode([
            "success" => false,
            "message" => "Designation is required",
        ]);
        exit();
    }

    $res = callRustAPI("/join-company", "POST", $input, getJWTToken());
    echo json_encode($res);
    exit();
}

// 2. NOW we can safely check for the ID for standard page loads.
if (!isset($_GET["id"]) || empty($_GET["id"])) {
    echo "<script>alert('Error: No Company ID provided.'); window.location.href='dashboard.php';</script>";
    exit();
}

$targetId = $_GET["id"];
$token = getJWTToken();

$apiResult = callRustAPI(
    "/company/" . urlencode($targetId),
    "GET",
    null,
    $token,
);

if (!$apiResult["success"]) {
    echo "<script>alert('Failed to load company profile. It may have been deleted or is invalid.'); window.location.href='dashboard.php';</script>";
    exit();
}

$data = $apiResult["data"];
$company = $data["company"];
$employees = $data["employees"];
$is_employee = $data["is_employee"];
$is_owner = $data["is_owner"] ?? false;

// Make sure we catch the owner flag
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($company["name"]); ?> — Company Profile</title>
    <link rel="stylesheet" href="./css/styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="bg-orbs"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>

    <div class="dash-container">
        <header class="dash-header">
            <h1 class="dash-title">Company Profile</h1>
            <div class="dash-nav">
                <a href="dashboard.php" class="dash-btn dash-btn-glass">← Back to Dashboard</a>
            </div>
        </header>

        <div class="profile-wrapper">
            <div class="details-header" style="align-items: center;">
                <div style="display: flex; gap: 1.5rem; align-items:center;">
                    <?php if (!empty($company["logo"])): ?>
                        <img src="<?php echo htmlspecialchars($company["logo"]); ?>" style="width: 100px; height: 100px; border-radius: var(--r-md); object-fit: contain; border: 1px solid rgba(255,255,255,0.1); background: rgba(255,255,255,0.05);">
                    <?php else: ?>
                        <div style="width: 100px; height: 100px; border-radius: var(--r-md); background: rgba(99,102,241,0.1); border: 1px solid rgba(99,102,241,0.2); display: flex; align-items: center; justify-content: center; font-size: 2.5rem;">🏢</div>
                    <?php endif; ?>

                    <div>
                        <h1 class="details-title" style="font-size: 2rem; margin-bottom: 0.4rem;"><?php echo htmlspecialchars($company["name"]); ?></h1>
                        <div style="display: flex; gap: 1rem; flex-wrap: wrap; color: var(--text-secondary); font-size: 0.9rem;">
                            <?php if (!empty($company["location"])): ?>
                                <span>📍 <?php echo htmlspecialchars($company["location"]); ?></span>
                            <?php endif; ?>
                            <?php if (!empty($company["website"])): ?>
                                <span>🌐 <a href="<?php echo htmlspecialchars($company["website"]); ?>" target="_blank" style="color:var(--cyan-400); text-decoration:none;"><?php echo htmlspecialchars($company["website"]); ?></a></span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>

                <div>
                    <?php if ($is_employee): ?>
                        <button class="dash-btn dash-btn-glass" disabled style="color: var(--emerald-400); border-color: rgba(16,185,129,0.3); background: rgba(16,185,129,0.1);">✓ You work here</button>
                    <?php else: ?>
                        <button class="dash-btn dash-btn-primary" id="join-btn" onclick="promptJoin('<?php echo htmlspecialchars($company["id"]); ?>')">🤝 Join Company</button>
                    <?php endif; ?>
                </div>
            </div>

            <?php if (!empty($company["description"])): ?>
                <div class="profile-section">
                    <h3>🏢 About Us</h3>
                    <div style="background: rgba(99,102,241,0.02); padding: 1.5rem; border-radius: var(--r-md); border: 1px solid rgba(99,102,241,0.08);">
                        <p style="color: var(--text-main); line-height: 1.6;"><?php echo nl2br(htmlspecialchars($company["description"])); ?></p>
                    </div>
                </div>
            <?php endif; ?>

            <div class="profile-section">
                <h3>👥 Our Employees (<?php echo count($employees); ?>)</h3>
                
                <?php if (empty($employees)): ?>
                    <p class="dash-empty">No employees listed yet.</p>
                <?php else: ?>
                    <div class="dash-grid">
                        <?php foreach ($employees as $emp): ?>
                            <div class="dash-card">
                                <a href="user_details.php?id=<?php echo urlencode($emp["user"]["id"]); ?>" style="text-decoration: none; color: inherit; display: block; margin-bottom: 1rem;">
                                    <div style="display: flex; gap: 1rem; align-items: center;">
                                        <?php if (!empty($emp["user"]["profile_picture"])): ?>
                                            <img src="<?php echo htmlspecialchars($emp["user"]["profile_picture"]); ?>" style="width:50px; height:50px; border-radius:50%; object-fit:cover; border: 2px solid rgba(99,102,241,0.3);">
                                        <?php else: ?>
                                            <div style="width:50px; height:50px; border-radius:50%; background:rgba(99,102,241,0.1); border: 1px solid rgba(99,102,241,0.2); display:flex; align-items:center; justify-content:center; font-size:1.2rem;">👤</div>
                                        <?php endif; ?>

                                        <div>
                                            <h4 class="card-title" style="font-size: 1.1rem; margin-bottom: 0.2rem;"><?php echo htmlspecialchars($emp["user"]["name"]); ?></h4>
                                            
                                            <div style="display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.3rem;">
                                                <span style="font-size: 0.85rem; font-weight: 600; color: var(--indigo-400);"><?php echo htmlspecialchars($emp["designation"]); ?></span>
                                                <?php if ($emp["is_verified"]): ?>
                                                    <span class="dash-badge badge-salary" style="padding: 0.1rem 0.4rem; font-size: 0.65rem;">✓ Verified</span>
                                                <?php else: ?>
                                                    <span class="dash-badge" style="padding: 0.1rem 0.4rem; font-size: 0.65rem; background: rgba(245,158,11,0.1); color: var(--amber-400); border: 1px solid rgba(245,158,11,0.3);">⏳ Unverified</span>
                                                <?php endif; ?>
                                            </div>

                                            <div style="font-size: 0.75rem; color: var(--text-muted);">Since: <?php echo date("M Y", $emp["employee_since"]); ?></div>
                                        </div>
                                    </div>
                                </a>

                                <?php if ($is_owner && !$emp["is_verified"]): ?>
                                    <button onclick="verifyEmployee('<?php echo htmlspecialchars($company["id"]); ?>', '<?php echo htmlspecialchars($emp["user"]["id"]); ?>')" class="dash-btn dash-btn-glass" style="width: 100%; justify-content: center; color: var(--emerald-400); border-color: rgba(16,185,129,0.3);">
                                        ✓ Verify Employee
                                    </button>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script>
        async function promptJoin(companyId) {
            const designation = prompt("What is your designation/role at this company?\n\n(Note: Your status will be 'Unverified' until an admin verifies it.)");

            if (!designation) return;

            const btn = document.getElementById('join-btn');
            btn.disabled = true;
            btn.textContent = 'Joining...';

            try {
                const res = await fetch('company.php?action=join', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ company_id: companyId, designation: designation.trim() })
                });

                const result = await res.json();

                if (result.success || result.status === 'success') {
                    btn.textContent = '✓ You work here';
                    btn.className = 'dash-btn dash-btn-glass';
                    btn.style.color = 'var(--emerald-400)';
                    btn.style.borderColor = 'rgba(16,185,129,0.3)';
                    btn.style.background = 'rgba(16,185,129,0.1)';
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    alert('Failed to join: ' + (result.message || 'Unknown error'));
                    btn.disabled = false;
                    btn.textContent = '🤝 Join Company';
                }
            } catch(e) {
                alert('Error processing request. Please try again.');
                btn.disabled = false;
                btn.textContent = '🤝 Join Company';
            }
        }

        async function verifyEmployee(companyId, userId) {
            if (!confirm("Are you sure you want to verify this employee?")) return;
            try {
                const res = await fetch('employer_api.php?action=verify_employee', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ company_id: companyId, user_id: userId })
                });
                const result = await res.json();
                if (result.success || result.status === 'success') {
                    window.location.reload();
                } else {
                    alert('Verification failed.');
                }
            } catch(e) {
                alert('An error occurred.');
            }
        }
    </script>
</body>
</html>