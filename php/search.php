<?php
// search.php
require_once "config.php";

if (!isAuthenticated()) {
    header("Location: signin.php");
    exit();
}

$initialQuery = $_GET["q"] ?? "";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Global Search — JobPortal</title>
    <link rel="stylesheet" href="./css/styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>
    <div class="bg-orbs"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>

    <div class="dash-container" style="max-width: 1400px;">
        <header class="dash-header">
            <h1 class="dash-title">Global Search</h1>
            <div class="dash-nav">
                <a href="dashboard.php" class="dash-btn dash-btn-glass">← Back to Dashboard</a>
            </div>
        </header>

        <div class="search-layout">
            <aside class="filter-sidebar">
                <div class="filter-group">
                    <label class="filter-title">Search Keyword</label>
                    <input type="text" id="search-q" class="form-input" placeholder="Keyword..." value="<?php echo htmlspecialchars(
                        $initialQuery,
                    ); ?>" style="padding-left: 1rem;">
                </div>

                <div class="filter-group">
                    <div class="filter-title">Category</div>
                    <label class="checkbox-label" style="margin-bottom: 0.5rem;">
                        <input type="radio" name="category" value="all" class="checkbox-input" checked>
                        <span class="checkbox-custom" style="border-radius: 50%;"></span>
                        <span class="checkbox-text">Everything</span>
                    </label>
                    <label class="checkbox-label" style="margin-bottom: 0.5rem;">
                        <input type="radio" name="category" value="jobs" class="checkbox-input">
                        <span class="checkbox-custom" style="border-radius: 50%;"></span>
                        <span class="checkbox-text">💼 Job Posts</span>
                    </label>
                    <label class="checkbox-label" style="margin-bottom: 0.5rem;">
                        <input type="radio" name="category" value="companies" class="checkbox-input">
                        <span class="checkbox-custom" style="border-radius: 50%;"></span>
                        <span class="checkbox-text">🏢 Companies</span>
                    </label>
                    <label class="checkbox-label" style="margin-bottom: 0.5rem;">
                        <input type="radio" name="category" value="users" class="checkbox-input">
                        <span class="checkbox-custom" style="border-radius: 50%;"></span>
                        <span class="checkbox-text">👤 Users</span>
                    </label>
                </div>

                <div class="filter-group" id="location-filter-group">
                    <label class="filter-title">Location (Jobs/Companies)</label>
                    <input type="text" id="search-location" class="form-input" placeholder="e.g., Remote, NY" style="padding-left: 1rem;">
                </div>

                <div class="filter-group" id="user-filter-group">
                    <div class="filter-title">User Type</div>
                    <label class="checkbox-label" style="margin-bottom: 0.5rem;">
                        <input type="radio" name="user_type" value="any" class="checkbox-input" checked>
                        <span class="checkbox-custom" style="border-radius: 50%;"></span>
                        <span class="checkbox-text">Any</span>
                    </label>
                    <label class="checkbox-label" style="margin-bottom: 0.5rem;">
                        <input type="radio" name="user_type" value="seeker" class="checkbox-input">
                        <span class="checkbox-custom" style="border-radius: 50%;"></span>
                        <span class="checkbox-text">Job Seekers</span>
                    </label>
                    <label class="checkbox-label">
                        <input type="radio" name="user_type" value="employer" class="checkbox-input">
                        <span class="checkbox-custom" style="border-radius: 50%;"></span>
                        <span class="checkbox-text">Employers / HR</span>
                    </label>
                </div>
            </aside>

            <main>
                <div id="results-container">
                    <div class="dash-empty"><p>Loading results...</p></div>
                </div>
            </main>
        </div>
    </div>

    <script>
        const searchQ = document.getElementById('search-q');
        const locationInput = document.getElementById('search-location');
        const categoryRadios = document.getElementsByName('category');
        const userTypeRadios = document.getElementsByName('user_type');
        const resultsContainer = document.getElementById('results-container');
        const userFilterGroup = document.getElementById('user-filter-group');
        const locationFilterGroup = document.getElementById('location-filter-group');

        let timeout = null;

        // Auto trigger search on input change
        [searchQ, locationInput].forEach(el => {
            el.addEventListener('input', () => {
                clearTimeout(timeout);
                timeout = setTimeout(performSearch, 400);
            });
        });

        categoryRadios.forEach(el => {
            el.addEventListener('change', () => {
                // UI cleanup based on category
                if (el.value === 'users') {
                    locationFilterGroup.style.opacity = '0.3';
                    userFilterGroup.style.opacity = '1';
                } else if (el.value === 'jobs' || el.value === 'companies') {
                    locationFilterGroup.style.opacity = '1';
                    userFilterGroup.style.opacity = '0.3';
                } else {
                    locationFilterGroup.style.opacity = '1';
                    userFilterGroup.style.opacity = '1';
                }
                performSearch();
            });
        });

        userTypeRadios.forEach(el => el.addEventListener('change', performSearch));

        async function performSearch() {
            resultsContainer.innerHTML = '<div style="text-align:center; padding: 3rem;"><div class="btn-spinner" style="display:inline-block; border-top-color: var(--indigo-400); width: 30px; height: 30px;"></div></div>';

            let category = Array.from(categoryRadios).find(r => r.checked).value;
            let userType = Array.from(userTypeRadios).find(r => r.checked).value;

            let params = new URLSearchParams();
            if (searchQ.value.trim()) params.append('q', searchQ.value.trim());
            params.append('category', category);
            if (locationInput.value.trim()) params.append('location', locationInput.value.trim());

            if (userType === 'seeker') params.append('is_finding_job', 'true');
            if (userType === 'employer') params.append('is_finding_job', 'false');

            // Update URL without reloading
            window.history.replaceState({}, '', `${window.location.pathname}?q=${encodeURIComponent(searchQ.value.trim())}`);

            try {
                const res = await fetch('search_api.php?' + params.toString());
                const data = await res.json();

                if (data.success && data.data) {
                    renderResults(data.data);
                } else {
                    resultsContainer.innerHTML = `<div class="dash-empty"><p>Error: ${data.message}</p></div>`;
                }
            } catch(e) {
                resultsContainer.innerHTML = `<div class="dash-empty"><p>Network error while searching.</p></div>`;
            }
        }

        function renderResults(data) {
            let html = '';

            // JOBS
            if (data.jobs && data.jobs.length > 0) {
                html += `<h2 class="search-section-heading">💼 Jobs Found (${data.jobs.length})</h2><div class="dash-grid">`;
                data.jobs.forEach(job => {
                    html += `
                        <div class="dash-card dash-card-job" onclick="window.location.href='job_details.php?id=${encodeURIComponent(job.id)}'">
                            <h3 class="card-title">${job.title}</h3>
                            <div class="card-subtitle">🏢 ${job.company_name || job.employer_name}</div>
                            <div class="card-tags">
                                ${job.location ? `<span class="dash-badge badge-location">📍 ${job.location}</span>` : ''}
                                ${job.salary_range_start ? `<span class="dash-badge badge-salary">💰 $${job.salary_range_start}+</span>` : ''}
                            </div>
                        </div>`;
                });
                html += `</div>`;
            }

            // COMPANIES
            if (data.companies && data.companies.length > 0) {
                html += `<h2 class="search-section-heading">🏢 Companies Found (${data.companies.length})</h2><div class="dash-grid">`;
                data.companies.forEach(comp => {
                    html += `
                        <div class="dash-card dash-card-job" onclick="window.location.href='company.php?id=${encodeURIComponent(comp.id)}'">
                            <div style="display:flex; gap:1rem; align-items:center;">
                                ${comp.logo ? `<img src="${comp.logo}" style="width:45px;height:45px;border-radius:10px;object-fit:cover;">` : `<div style="width:45px;height:45px;border-radius:10px;background:rgba(99,102,241,0.1);display:flex;align-items:center;justify-content:center;font-size:1.2rem;">🏢</div>`}
                                <div>
                                    <h3 class="card-title" style="margin:0;">${comp.name}</h3>
                                    ${comp.location ? `<div style="font-size:0.8rem; color:var(--text-muted); margin-top:0.2rem;">📍 ${comp.location}</div>` : ''}
                                </div>
                            </div>
                        </div>`;
                });
                html += `</div>`;
            }

            // USERS
            if (data.users && data.users.length > 0) {
                html += `<h2 class="search-section-heading">👤 Users Found (${data.users.length})</h2><div class="dash-grid">`;
                data.users.forEach(user => {
                    let roleBadge = user.is_finding_job ? `<span class="dash-badge badge-role">Job Seeker</span>` : `<span class="dash-badge badge-salary" style="color: var(--amber-400); border-color: rgba(245,158,11,0.3); background: rgba(245,158,11,0.1);">Employer</span>`;
                    html += `
                        <div class="dash-card">
                            ${roleBadge}
                            <div class="candidate-header" style="margin-top: 1rem;">
                                ${user.profile_picture ? `<img src="${user.profile_picture}" class="candidate-avatar">` : `<div class="candidate-avatar">👤</div>`}
                                <div>
                                    <h3 class="card-title"><a href="user_details.php?id=${encodeURIComponent(user.id)}">${user.name}</a></h3>
                                    <span class="candidate-email">📧 ${user.email}</span>
                                </div>
                            </div>
                        </div>`;
                });
                html += `</div>`;
            }

            if (!html) {
                html = `<div class="dash-empty"><h3>No results found</h3><p>Try adjusting your filters or searching for something else.</p></div>`;
            }

            resultsContainer.innerHTML = html;
        }

        // Trigger initial search
        performSearch();
    </script>
</body>
</html>
