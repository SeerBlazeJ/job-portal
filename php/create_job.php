<?php
// create_job.php (Combined Frontend + Backend)
require_once 'config.php';

// Check authentication
if (!isAuthenticated()) {
    header('Location: signin.php');
    exit;
}

// Handle POST request (form submission)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);

    // Validate required fields
    $required = ['title', 'description', 'location', 'datetime_due', 'min_ed_lvl'];
    foreach ($required as $field) {
        if (empty($input[$field])) {
            echo json_encode([
                'status' => 'error',
                'message' => ucfirst(str_replace('_', ' ', $field)) . ' is required'
            ]);
            exit;
        }
    }

    // Convert education level integer to enum string
    $eduLevelMap = [
        1 => 'HighSchool',
        2 => 'Diploma',
        3 => 'Bachelors',
        4 => 'Masters',
        5 => 'PhD'
    ];

    $eduLevel = $eduLevelMap[$input['min_ed_lvl']] ?? 'Bachelors';

    // Prepare data for Rust API
    $jobData = [
        'title' => trim($input['title']),
        'description' => trim($input['description']),
        'skills_required' => !empty($input['skills_required']) ? $input['skills_required'] : null,
        'majors_accepted' => !empty($input['majors_accepted']) ? $input['majors_accepted'] : null,
        'location' => trim($input['location']),
        'salary_range_start' => isset($input['salary_range_start']) && $input['salary_range_start'] !== '' ? (int)$input['salary_range_start'] : null,
        'salary_range_end' => isset($input['salary_range_end']) && $input['salary_range_end'] !== '' ? (int)$input['salary_range_end'] : null,
        'datetime_due' => $input['datetime_due'],
        'min_ed_lvl' => $eduLevel
    ];

    // Get JWT token
    $token = getJWTToken();

    // Call Rust API
    $result = callRustAPI('/create-job', 'POST', $jobData, $token);

    if ($result['success']) {
        echo json_encode([
            'status' => 'success',
            'message' => 'Job post created successfully!',
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

// If GET request, get user profile and show form
$token = getJWTToken();
$profileResult = callRustAPI('/profile', 'GET', null, $token);

if (!$profileResult['success']) {
    clearJWTCookie();
    header('Location: signin.php');
    exit;
}

$userProfile = $profileResult['data'];
$userName = $userProfile['name'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Job Post - Job Portal</title>
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

        .form-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .form-container h2 {
            color: #333;
            margin-bottom: 30px;
            font-size: 24px;
        }

        .form-group {
            margin-bottom: 25px;
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

        .form-group textarea {
            min-height: 120px;
            resize: vertical;
        }

        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        .tags-input-container {
            position: relative;
        }

        .tags-display {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 8px;
            min-height: 40px;
            padding: 8px;
            border: 2px dashed #e0e0e0;
            border-radius: 5px;
        }

        .tag {
            background: #667eea;
            color: white;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .tag-remove {
            cursor: pointer;
            font-weight: bold;
            font-size: 16px;
        }

        .btn-primary {
            background: #667eea;
            color: white;
            width: 100%;
            padding: 15px;
            font-size: 16px;
        }

        .btn-primary:hover {
            background: #5568d3;
        }

        .btn-primary:disabled {
            background: #ccc;
            cursor: not-allowed;
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

        .helper-text {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📝 Create Job Post</h1>
            <div class="nav-links">
                <a href="dashboard.php" class="btn btn-secondary">← Back to Dashboard</a>
            </div>
        </div>

        <div class="form-container">
            <h2>Post a New Job Opening</h2>

            <div id="alert" class="alert"></div>

            <form id="job-form">
                <div class="form-group">
                    <label for="title">Job Title *</label>
                    <input type="text" id="title" name="title" required placeholder="e.g., Senior Software Engineer">
                </div>

                <div class="form-group">
                    <label for="description">Job Description *</label>
                    <textarea id="description" name="description" required placeholder="Describe the role, responsibilities, and requirements..."></textarea>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label for="location">Location *</label>
                        <input type="text" id="location" name="location" required placeholder="e.g., Remote, New York, NY">
                    </div>

                    <div class="form-group">
                        <label for="min_ed_lvl">Minimum Education Level *</label>
                        <select id="min_ed_lvl" name="min_ed_lvl" required>
                            <option value="">Select education level</option>
                            <option value="1">High School</option>
                            <option value="2">Diploma</option>
                            <option value="3">Bachelor's Degree</option>
                            <option value="4">Master's Degree</option>
                            <option value="5">PhD/Doctorate</option>
                        </select>
                    </div>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label for="salary_start">Salary Range Start ($)</label>
                        <input type="number" id="salary_start" name="salary_range_start" min="0" placeholder="e.g., 80000">
                    </div>

                    <div class="form-group">
                        <label for="salary_end">Salary Range End ($)</label>
                        <input type="number" id="salary_end" name="salary_range_end" min="0" placeholder="e.g., 120000">
                    </div>
                </div>

                <div class="form-group">
                    <label for="datetime_due">Application Deadline *</label>
                    <input type="datetime-local" id="datetime_due" name="datetime_due" required>
                </div>

                <div class="form-group">
                    <label for="skills_input">Required Skills</label>
                    <input type="text" id="skills_input" placeholder="Type a skill and press Enter">
                    <div class="helper-text">Press Enter after typing each skill</div>
                    <div id="skills_tags" class="tags-display"></div>
                </div>

                <div class="form-group">
                    <label for="majors_input">Accepted Majors</label>
                    <input type="text" id="majors_input" placeholder="Type a major and press Enter">
                    <div class="helper-text">Press Enter after typing each major</div>
                    <div id="majors_tags" class="tags-display"></div>
                </div>

                <button type="submit" class="btn btn-primary" id="submit-btn">
                    Create Job Post
                </button>
            </form>
        </div>
    </div>

    <script>
        // Skills tags management
        const skillsInput = document.getElementById('skills_input');
        const skillsTagsContainer = document.getElementById('skills_tags');
        let skills = [];

        skillsInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const skill = skillsInput.value.trim();
                if (skill && !skills.includes(skill)) {
                    skills.push(skill);
                    renderTags(skills, skillsTagsContainer, skills);
                    skillsInput.value = '';
                }
            }
        });

        // Majors tags management
        const majorsInput = document.getElementById('majors_input');
        const majorsTagsContainer = document.getElementById('majors_tags');
        let majors = [];

        majorsInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                const major = majorsInput.value.trim();
                if (major && !majors.includes(major)) {
                    majors.push(major);
                    renderTags(majors, majorsTagsContainer, majors);
                    majorsInput.value = '';
                }
            }
        });

        function renderTags(tagsArray, container, sourceArray) {
            container.innerHTML = '';
            tagsArray.forEach((tag, index) => {
                const tagEl = document.createElement('div');
                tagEl.className = 'tag';
                tagEl.innerHTML = `
                    ${tag}
                    <span class="tag-remove" onclick="removeTag(${index}, '${container.id}')">×</span>
                `;
                container.appendChild(tagEl);
            });
        }

        function removeTag(index, containerId) {
            if (containerId === 'skills_tags') {
                skills.splice(index, 1);
                renderTags(skills, skillsTagsContainer, skills);
            } else {
                majors.splice(index, 1);
                renderTags(majors, majorsTagsContainer, majors);
            }
        }

        // Form submission
        document.getElementById('job-form').addEventListener('submit', async (e) => {
            e.preventDefault();

            const submitBtn = document.getElementById('submit-btn');
            const alert = document.getElementById('alert');

            // Get form data
            const formData = {
                title: document.getElementById('title').value.trim(),
                description: document.getElementById('description').value.trim(),
                location: document.getElementById('location').value.trim(),
                min_ed_lvl: parseInt(document.getElementById('min_ed_lvl').value),
                salary_range_start: document.getElementById('salary_start').value ? parseInt(document.getElementById('salary_start').value) : null,
                salary_range_end: document.getElementById('salary_end').value ? parseInt(document.getElementById('salary_end').value) : null,
                datetime_due: new Date(document.getElementById('datetime_due').value).toISOString(),
                skills_required: skills.length > 0 ? skills : null,
                majors_accepted: majors.length > 0 ? majors : null
            };

            // Disable button
            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating...';

            try {
                // POST to the same file
                const response = await fetch('create_job.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(formData)
                });

                const result = await response.json();

                if (result.status === 'success') {
                    showAlert('Job post created successfully! Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.href = 'dashboard.php';
                    }, 2000);
                } else {
                    showAlert(result.message, 'error');
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Create Job Post';
                }
            } catch (error) {
                console.error('Error:', error);
                showAlert('Failed to create job post. Please try again.', 'error');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Create Job Post';
            }
        });

        function showAlert(message, type) {
            const alert = document.getElementById('alert');
            alert.textContent = message;
            alert.className = `alert alert-${type} show`;
            setTimeout(() => {
                alert.classList.remove('show');
            }, 5000);
        }
    </script>
</body>
</html>
