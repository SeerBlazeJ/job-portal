<?php
// profile.php
require_once 'config.php';

// Check authentication
if (!isAuthenticated()) {
    header('Location: signin.php');
    exit;
}

// Get JWT token
$token = getJWTToken();

// Handle POST request (profile update)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    $input = json_decode(file_get_contents('php://input'), true);

    // Prepare update data (only include provided fields)
    $updateData = [];

    if (isset($input['name']) && !empty(trim($input['name']))) {
        $updateData['name'] = trim($input['name']);
    }
    if (isset($input['email']) && !empty(trim($input['email']))) {
        $updateData['email'] = trim($input['email']);
    }
    if (isset($input['is_finding_job'])) {
        $updateData['is_finding_job'] = (bool)$input['is_finding_job'];
    }
    if (isset($input['skills']) && is_array($input['skills'])) {
        $updateData['skills'] = array_values(array_filter($input['skills']));
    }
    if (isset($input['education']) && is_array($input['education'])) {
        // Validate and format education data
        $educationData = [];
        foreach ($input['education'] as $edu) {
            if (!empty($edu['education']) && !empty($edu['major']) && !empty($edu['edu_institution'])) {
                $educationData[] = [
                    'education' => $edu['education'],
                    'major' => trim($edu['major']),
                    'edu_institution' => trim($edu['edu_institution'])
                ];
            }
        }
        $updateData['education'] = $educationData;
    }

    if (empty($updateData)) {
        echo json_encode([
            'status' => 'error',
            'message' => 'No fields to update'
        ]);
        exit;
    }

    // Call Rust API
    $result = callRustAPI('/update-profile', 'POST', $updateData, $token);

    if ($result['success']) {
        echo json_encode([
            'status' => 'success',
            'message' => 'Profile updated successfully!',
            'data' => $result['data']
        ]);
    } else {
        echo json_encode([
            'status' => 'error',
            'message' => $result['message']
        ]);
    }
    exit;
}

// GET request - fetch profile and show page
$profileResult = callRustAPI('/profile', 'GET', null, $token);

if (!$profileResult['success']) {
    clearJWTCookie();
    header('Location: signin.php');
    exit;
}

$profile = $profileResult['data'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Profile - Job Portal</title>
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
            max-width: 900px;
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

        .header .nav-links {
            display: flex;
            gap: 15px;
            align-items: center;
        }

        .btn {
            padding: 10px 20px;
            border-radius: 5px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            border: none;
            transition: all 0.3s;
        }

        .btn-secondary {
            background: #6c757d;
            color: white;
        }

        .btn-secondary:hover {
            background: #5a6268;
        }

        .profile-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .profile-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #f0f0f0;
        }

        .profile-header h2 {
            color: #333;
            font-size: 24px;
        }

        .btn-edit {
            background: #667eea;
            color: white;
        }

        .btn-edit:hover {
            background: #5568d3;
        }

        .btn-cancel {
            background: #6c757d;
            color: white;
        }

        .btn-cancel:hover {
            background: #5a6268;
        }

        .profile-section {
            margin-bottom: 30px;
        }

        .profile-section h3 {
            color: #667eea;
            font-size: 18px;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .info-grid {
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 15px;
            align-items: start;
        }

        .info-label {
            font-weight: 600;
            color: #555;
        }

        .info-value {
            color: #333;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            color: #333;
            font-weight: 600;
            margin-bottom: 8px;
            font-size: 14px;
        }

        .form-group input,
        .form-group textarea,
        .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
            font-family: inherit;
        }

        .form-group input:focus,
        .form-group textarea:focus,
        .form-group select:focus {
            outline: none;
            border-color: #667eea;
        }

        .skills-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .skill-tag {
            background: #667eea;
            color: white;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .skill-tag-remove {
            cursor: pointer;
            font-weight: bold;
            font-size: 18px;
        }

        .tags-display {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
            min-height: 40px;
            padding: 10px;
            border: 2px dashed #e0e0e0;
            border-radius: 5px;
        }

        .education-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
        }

        .education-item strong {
            color: #667eea;
        }

        .education-form-item {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            border: 2px solid #e0e0e0;
            position: relative;
        }

        .education-form-item .remove-btn {
            position: absolute;
            top: 10px;
            right: 10px;
            background: #dc3545;
            color: white;
            border: none;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            cursor: pointer;
            font-size: 18px;
            font-weight: bold;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background 0.3s;
        }

        .education-form-item .remove-btn:hover {
            background: #c82333;
        }

        .btn-add {
            background: #28a745;
            color: white;
            padding: 10px 20px;
            margin-top: 10px;
        }

        .btn-add:hover {
            background: #218838;
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .checkbox-group input[type="checkbox"] {
            width: auto;
            cursor: pointer;
        }

        .alert {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: none;
        }

        .alert.show {
            display: block;
        }

        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .alert-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .btn-primary {
            background: #667eea;
            color: white;
            width: 100%;
            padding: 15px;
            font-size: 16px;
            margin-top: 20px;
        }

        .btn-primary:hover {
            background: #5568d3;
        }

        .btn-primary:disabled {
            background: #ccc;
            cursor: not-allowed;
        }

        .edit-mode {
            display: none;
        }

        .view-mode {
            display: block;
        }

        .helper-text {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }

        .status-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
        }

        .status-active {
            background: #d4edda;
            color: #155724;
        }

        .status-inactive {
            background: #f8d7da;
            color: #721c24;
        }

        .empty-state {
            color: #999;
            font-style: italic;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }

        .edu-level-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            background: #667eea;
            color: white;
        }
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
                <h2>Profile Information</h2>
                <div class="nav-links">
                    <button id="edit-btn" class="btn btn-edit view-mode">✏️ Edit Profile</button>
                    <button id="cancel-btn" class="btn btn-cancel edit-mode">✖ Cancel</button>
                </div>
            </div>

            <div id="alert" class="alert"></div>

            <!-- View Mode -->
            <div id="view-mode" class="view-mode">
                <div class="profile-section">
                    <h3>📋 Basic Information</h3>
                    <div class="info-grid">
                        <div class="info-label">Username:</div>
                        <div class="info-value"><?php echo htmlspecialchars($profile['uid']); ?></div>

                        <div class="info-label">Name:</div>
                        <div class="info-value"><?php echo htmlspecialchars($profile['name']); ?></div>

                        <div class="info-label">Email:</div>
                        <div class="info-value"><?php echo htmlspecialchars($profile['email']); ?></div>

                        <div class="info-label">Job Status:</div>
                        <div class="info-value">
                            <?php if ($profile['is_finding_job']): ?>
                                <span class="status-badge status-active">🔍 Actively Looking for Jobs</span>
                            <?php else: ?>
                                <span class="status-badge status-inactive">Not Looking for Jobs</span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>

                <div class="profile-section">
                    <h3>🎯 Skills</h3>
                    <?php if (!empty($profile['skills'])): ?>
                        <div class="skills-container">
                            <?php foreach ($profile['skills'] as $skill): ?>
                                <span class="skill-tag"><?php echo htmlspecialchars($skill); ?></span>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <p class="empty-state">No skills added yet</p>
                    <?php endif; ?>
                </div>

                <div class="profile-section">
                    <h3>🎓 Education</h3>
                    <?php if (!empty($profile['education'])): ?>
                        <?php foreach ($profile['education'] as $edu): ?>
                            <div class="education-item">
                                <div>
                                    <span class="edu-level-badge"><?php echo htmlspecialchars($edu['education']); ?></span>
                                    <strong style="margin-left: 10px;"><?php echo htmlspecialchars($edu['major']); ?></strong>
                                </div>
                                <div style="margin-top: 8px;">
                                    📍 <?php echo htmlspecialchars($edu['edu_institution']); ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <p class="empty-state">No education records added yet</p>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Edit Mode -->
            <div id="edit-mode" class="edit-mode">
                <form id="profile-form">
                    <div class="profile-section">
                        <h3>📋 Basic Information</h3>

                        <div class="form-group">
                            <label for="name">Name *</label>
                            <input type="text" id="name" name="name" value="<?php echo htmlspecialchars($profile['name']); ?>" required>
                        </div>

                        <div class="form-group">
                            <label for="email">Email *</label>
                            <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($profile['email']); ?>" required>
                        </div>

                        <div class="form-group">
                            <label class="checkbox-group">
                                <input type="checkbox" id="is_finding_job" name="is_finding_job"
                                    <?php echo $profile['is_finding_job'] ? 'checked' : ''; ?>>
                                <span>I am actively looking for job opportunities</span>
                            </label>
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
                        <h3>🎓 Education</h3>
                        <div id="education-container"></div>
                        <button type="button" class="btn btn-add" id="add-education-btn">
                            ➕ Add Education Record
                        </button>
                    </div>

                    <button type="submit" class="btn btn-primary" id="save-btn">
                        💾 Save Changes
                    </button>
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

        // Skills management
        const skillsInput = document.getElementById('skills_input');
        const skillsTagsContainer = document.getElementById('skills_tags');
        let skills = <?php echo json_encode($profile['skills'] ?? []); ?>;

        // Education management
        const educationContainer = document.getElementById('education-container');
        const addEducationBtn = document.getElementById('add-education-btn');
        let educationRecords = <?php echo json_encode($profile['education'] ?? []); ?>;

        // Education levels mapping
        const eduLevels = [
            { value: 'SecondarySchool', label: 'Secondary School' },
            { value: 'HighSchool', label: 'High School' },
            { value: 'Diploma', label: 'Diploma' },
            { value: 'Bachelors', label: "Bachelor's Degree" },
            { value: 'Masters', label: "Master's Degree" },
            { value: 'PhD', label: 'PhD/Doctorate' }
        ];

        // Initialize displays
        renderSkills();
        renderEducation();

        // Skills functions
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
                tag.innerHTML = `
                    ${skill}
                    <span class="skill-tag-remove" onclick="removeSkill(${index})">×</span>
                `;
                skillsTagsContainer.appendChild(tag);
            });
        }

        function removeSkill(index) {
            skills.splice(index, 1);
            renderSkills();
        }

        // Education functions
        function renderEducation() {
            educationContainer.innerHTML = '';

            if (educationRecords.length === 0) {
                educationContainer.innerHTML = '<p class="empty-state">No education records. Click "Add Education Record" to add one.</p>';
                return;
            }

            educationRecords.forEach((edu, index) => {
                const eduItem = document.createElement('div');
                eduItem.className = 'education-form-item';
                eduItem.innerHTML = `
                    <button type="button" class="remove-btn" onclick="removeEducation(${index})">×</button>

                    <div class="form-group">
                        <label>Education Level *</label>
                        <select class="edu-level" data-index="${index}" required>
                            ${eduLevels.map(level => `
                                <option value="${level.value}" ${edu.education === level.value ? 'selected' : ''}>
                                    ${level.label}
                                </option>
                            `).join('')}
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Major/Field of Study *</label>
                        <input type="text" class="edu-major" data-index="${index}"
                            value="${edu.major || ''}"
                            placeholder="e.g., Computer Science" required>
                    </div>

                    <div class="form-group">
                        <label>Institution Name *</label>
                        <input type="text" class="edu-institution" data-index="${index}"
                            value="${edu.edu_institution || ''}"
                            placeholder="e.g., University of Technology" required>
                    </div>
                `;
                educationContainer.appendChild(eduItem);
            });
        }

        function removeEducation(index) {
            educationRecords.splice(index, 1);
            renderEducation();
        }

        addEducationBtn.addEventListener('click', () => {
            educationRecords.push({
                education: 'Bachelors',
                major: '',
                edu_institution: ''
            });
            renderEducation();
        });

        // Toggle edit mode
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

            // Reset form
            profileForm.reset();
            skills = <?php echo json_encode($profile['skills'] ?? []); ?>;
            educationRecords = <?php echo json_encode($profile['education'] ?? []); ?>;
            renderSkills();
            renderEducation();
            clearAlert();
        });

        // Form submission
        profileForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // Collect education data from form
            const updatedEducation = [];
            educationContainer.querySelectorAll('.education-form-item').forEach((item, index) => {
                const level = item.querySelector('.edu-level').value;
                const major = item.querySelector('.edu-major').value.trim();
                const institution = item.querySelector('.edu-institution').value.trim();

                if (level && major && institution) {
                    updatedEducation.push({
                        education: level,
                        major: major,
                        edu_institution: institution
                    });
                }
            });

            const formData = {
                name: document.getElementById('name').value.trim(),
                email: document.getElementById('email').value.trim(),
                is_finding_job: document.getElementById('is_finding_job').checked,
                skills: skills.length > 0 ? skills : [],
                education: updatedEducation
            };

            saveBtn.disabled = true;
            saveBtn.textContent = '💾 Saving...';

            try {
                const response = await fetch('profile.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(formData)
                });

                const result = await response.json();

                if (result.status === 'success') {
                    showAlert('Profile updated successfully! Reloading...', 'success');
                    setTimeout(() => {
                        window.location.reload();
                    }, 1500);
                } else {
                    showAlert(result.message, 'error');
                    saveBtn.disabled = false;
                    saveBtn.textContent = '💾 Save Changes';
                }
            } catch (error) {
                console.error('Error:', error);
                showAlert('Failed to update profile. Please try again.', 'error');
                saveBtn.disabled = false;
                saveBtn.textContent = '💾 Save Changes';
            }
        });

        function showAlert(message, type) {
            alert.textContent = message;
            alert.className = `alert alert-${type} show`;
            setTimeout(() => {
                alert.classList.remove('show');
            }, 5000);
        }

        function clearAlert() {
            alert.classList.remove('show');
        }

        // Make functions globally accessible
        window.removeSkill = removeSkill;
        window.removeEducation = removeEducation;
    </script>
</body>
</html>
