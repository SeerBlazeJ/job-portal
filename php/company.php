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
    <title><?php echo htmlspecialchars(
        $company["name"],
    ); ?> - Company Profile</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; }
        .btn-back { display: inline-block; background: #6c757d; color: white; text-decoration: none; padding: 10px 20px; border-radius: 5px; margin-bottom: 20px; font-weight: 600; }
        .profile-card { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); margin-bottom: 30px; }
        .header-section { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #eee; padding-bottom: 25px; margin-bottom: 25px; }
        .comp-info { display: flex; gap: 25px; align-items: center; }
        .comp-info h1 { color: #333; font-size: 32px; margin-bottom: 8px; }
        .meta { color: #666; font-size: 14px; margin-bottom: 5px; }
        .btn-join { background: #28a745; color: white; border: none; padding: 12px 25px; border-radius: 5px; cursor: pointer; font-size: 15px; font-weight: bold; }
        .btn-join:disabled { background: #6c757d; cursor: default; }
        .about-section { margin-bottom: 30px; }
        .about-section h3 { color: #667eea; margin-bottom: 10px; font-size: 20px; }
        .about-section p { color: #555; line-height: 1.6; }
        .employees-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 20px; }
        .emp-card { border: 1px solid #e0e0e0; border-left: 4px solid #667eea; border-radius: 8px; padding: 15px; background: #fafafa; }
        .emp-card h4 { color: #333; margin-bottom: 3px; font-size: 16px; }
        .emp-card a { text-decoration: none; color: inherit; }
        .emp-card a:hover h4 { color: #667eea; }
        .emp-card .role { font-size: 13px; font-weight: bold; color: #667eea; margin-bottom: 5px; display: flex; align-items: center; flex-wrap: wrap; gap: 5px;}
        .emp-card .since { font-size: 12px; color: #888; margin-top: 4px; }
        .badge-verified { color: #28a745; font-size: 10px; border: 1px solid #28a745; padding: 2px 5px; border-radius: 4px; display: inline-block;}
        .badge-unverified { color: #856404; font-size: 10px; background: #fff3cd; padding: 3px 5px; border-radius: 4px; display: inline-block;}
    </style>
</head>
<body>
    <div class="container">
        <a href="dashboard.php" class="btn-back">← Back to Dashboard</a>

        <div class="profile-card">
            <div class="header-section">
                <div class="comp-info">
                    <?php if (!empty($company["logo"])): ?>
                        <img src="<?php echo htmlspecialchars(
                            $company["logo"],
                        ); ?>" style="width: 100px; height: 100px; border-radius: 10px; object-fit: contain; border: 1px solid #ddd; background: #fff;">
                    <?php else: ?>
                        <div style="width: 100px; height: 100px; border-radius: 10px; background: #e0e0e0; display: flex; align-items: center; justify-content: center; font-size: 40px;">🏢</div>
                    <?php endif; ?>

                    <div>
                        <h1><?php echo htmlspecialchars(
                            $company["name"],
                        ); ?></h1>
                        <?php if (!empty($company["location"])): ?>
                            <div class="meta">📍 <?php echo htmlspecialchars(
                                $company["location"],
                            ); ?></div>
                        <?php endif; ?>
                        <?php if (!empty($company["website"])): ?>
                            <div class="meta">🌐 <a href="<?php echo htmlspecialchars(
                                $company["website"],
                            ); ?>" target="_blank" style="color:#667eea;"><?php echo htmlspecialchars(
    $company["website"],
); ?></a></div>
                        <?php endif; ?>
                    </div>
                </div>

                <div>
                    <?php if ($is_employee): ?>
                        <button class="btn-join" disabled>✓ You work here</button>
                    <?php else: ?>
                        <button class="btn-join" id="join-btn" onclick="promptJoin('<?php echo htmlspecialchars(
                            $company["id"],
                        ); ?>')">🤝 Join Company</button>
                    <?php endif; ?>
                </div>
            </div>

            <?php if (!empty($company["description"])): ?>
                <div class="about-section">
                    <h3>About Us</h3>
                    <p><?php echo nl2br(
                        htmlspecialchars($company["description"]),
                    ); ?></p>
                </div>
            <?php endif; ?>

            <div class="about-section">
                <h3>Our Employees (<?php echo count($employees); ?>)</h3>
                <?php if (empty($employees)): ?>
                    <p style="color: #888; font-style: italic;">No employees listed yet.</p>
                <?php else: ?>
                    <div class="employees-grid">
                        <?php foreach ($employees as $emp): ?>
                            <div class="emp-card">
                                <a href="user_details.php?id=<?php echo urlencode(
                                    $emp["user"]["id"],
                                ); ?>" style="text-decoration: none; color: inherit; display: block; margin-bottom: 10px;">
                                    <div style="display: flex; gap: 12px; align-items: center;">
                                        <?php if (
                                            !empty(
                                                $emp["user"]["profile_picture"]
                                            )
                                        ): ?>
                                            <img src="<?php echo htmlspecialchars(
                                                $emp["user"]["profile_picture"],
                                            ); ?>" style="width:45px; height:45px; border-radius:50%; object-fit:cover;">
                                        <?php else: ?>
                                            <div style="width:45px; height:45px; border-radius:50%; background:#ddd; display:flex; align-items:center; justify-content:center; font-size:20px;">👤</div>
                                        <?php endif; ?>

                                        <div>
                                            <h4 style="color: #333; margin-bottom: 3px; font-size: 16px;"><?php echo htmlspecialchars(
                                                $emp["user"]["name"],
                                            ); ?></h4>

                                            <div class="role" style="display: flex; align-items: center; font-size: 13px; font-weight: bold; color: #667eea;">
                                                <?php echo htmlspecialchars(
                                                    $emp["designation"],
                                                ); ?>
                                                <?php if (
                                                    $emp["is_verified"]
                                                ): ?>
                                                    <span class="badge-verified" style="margin-left: 5px;">✓ Verified</span>
                                                <?php else: ?>
                                                    <span class="badge-unverified" style="margin-left: 5px;">⏳ Unverified</span>
                                                <?php endif; ?>
                                            </div>

                                            <div class="since">Since: <?php echo date(
                                                "M Y",
                                                $emp["employee_since"],
                                            ); ?></div>
                                        </div>
                                    </div>
                                </a>

                                <?php if ($is_owner && !$emp["is_verified"]): ?>
                                    <button onclick="verifyEmployee('<?php echo htmlspecialchars(
                                        $company["id"],
                                    ); ?>', '<?php echo htmlspecialchars(
    $emp["user"]["id"],
); ?>')" style="width: 100%; background: #28a745; color: white; border: none; padding: 8px; border-radius: 5px; cursor: pointer; font-size: 13px; font-weight: bold; margin-top: 5px;">
                                        Verify Employee
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
