<?php
// signin.php
require_once "config.php";
if (isAuthenticated()) {
    header("Location: dashboard.php");
    exit();
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Sign in - Job Portal</title>
  <style>
    body { font-family: system-ui, Arial; background: linear-gradient(135deg,#667eea 0%,#764ba2 100%); min-height:100vh; margin:0; padding:20px; }
    .wrap { max-width: 520px; margin: 40px auto; }
    .card { background:#fff; border-radius:12px; box-shadow:0 6px 18px rgba(0,0,0,.15); padding:24px; }
    h1 { margin:0 0 8px; color:#333; font-size:24px; }
    .tabs { display:flex; gap:10px; margin: 16px 0 20px; }
    .tab { flex:1; padding:10px; border-radius:8px; border:1px solid #ddd; background:#f7f7f7; cursor:pointer; font-weight:600; text-align: center;}
    .tab.active { background:#667eea; color:#fff; border-color:#667eea; }
    label { display:block; font-size:13px; color:#333; margin: 12px 0 6px; font-weight:600; }
    input { width:100%; padding:10px; border-radius:8px; border:1px solid #ddd; font-size:14px; box-sizing:border-box; }
    button[type="submit"] { width:100%; margin-top:20px; padding:12px; border:0; border-radius:8px; background:#667eea; color:#fff; font-weight:700; cursor:pointer; }

    /* Role Toggle specific */
    .role-toggle { display: flex; gap: 10px; margin-top: 15px; }
    .role-btn { flex: 1; padding: 10px; border: 2px solid #ddd; border-radius: 8px; background: white; cursor: pointer; text-align: center; font-weight: bold; color: #555; transition: 0.2s;}
    .role-btn.selected { border-color: #28a745; background: #f0fdf4; color: #28a745; }

    /* Company Fields */
    .employer-fields { display: none; background: #f8f9fa; padding: 15px; border-radius: 8px; margin-top: 15px; border: 1px solid #eee; }
    .search-results { border: 1px solid #ddd; border-top: none; max-height: 150px; overflow-y: auto; background: white; border-radius: 0 0 8px 8px; position: absolute; width: 100%; z-index: 10; display: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    .search-item { padding: 10px; cursor: pointer; border-bottom: 1px solid #f0f0f0; font-size: 13px; }
    .search-item:hover { background: #f0fdf4; }
    .search-item.create-new { color: #667eea; font-weight: bold; background: #f8f9fa; text-align: center; }
    .alert { margin: 14px 0 0; padding: 12px; border-radius: 8px; display:none; }
    .alert.show { display:block; }
    .alert.error { background:#f8d7da; color:#721c24; border:1px solid #f5c6cb;}
    .alert.success { background:#d4edda; color:#155724; border:1px solid #c3e6cb;}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Job Portal</h1>
      <p style="color:#666; margin:0 0 16px;">Login or create a new account.</p>

      <div class="tabs">
        <div class="tab active" id="tabLogin" onclick="setMode('login')">Login</div>
        <div class="tab" id="tabSignup" onclick="setMode('signup')">Signup</div>
      </div>

      <div id="alert" class="alert"></div>

      <form id="authForm">
        <input type="hidden" name="mode" id="mode" value="login">
        <input type="hidden" name="role" id="role" value="seeker">

        <label>Username</label>
        <input name="username" id="username" type="text" required>

        <div id="emailBox" style="display:none;">
          <label>Email</label>
          <input name="email" id="email" type="email">
        </div>

        <label>Password</label>
        <input name="password" id="password" type="password" required>

        <div id="confirmBox" style="display:none;">
          <label>Confirm Password</label>
          <input id="confirm_password" type="password">
        </div>

        <div id="roleSelection" style="display: none;">
            <label>I am a...</label>
            <div class="role-toggle">
                <button type="button" class="role-btn selected" id="btnSeeker" onclick="setRole('seeker')">Job Seeker</button>
                <button type="button" class="role-btn" id="btnEmployer" onclick="setRole('employer')">Employer / HR</button>
            </div>
        </div>

        <div id="employerFields" class="employer-fields">
            <label>Your Role/Designation *</label>
            <input type="text" name="designation" id="designation" placeholder="e.g., Hiring Manager">

            <label>Company Name *</label>
            <div style="position: relative;">
                <input type="text" id="companySearch" placeholder="Search for your company..." autocomplete="off">
                <div id="searchResults" class="search-results"></div>
            </div>

            <input type="hidden" name="company_action" id="companyAction" value="create">
            <input type="hidden" name="company_id" id="selectedCompanyId">

            <div id="newCompanyFields">
                <p style="font-size: 12px; color: #888; margin: 10px 0 5px;">Company not found? Provide details to register it:</p>
                <input type="text" name="new_company_name" id="newCompanyName" placeholder="Company Name" style="margin-bottom: 8px;">
                <input type="text" name="new_company_location" id="newCompanyLocation" placeholder="Location (Optional)" style="margin-bottom: 8px;">
                <input type="url" name="new_company_website" id="newCompanyWebsite" placeholder="Website URL (Optional)">
            </div>
        </div>

        <button id="submitBtn" type="submit">Login</button>
      </form>
    </div>
  </div>

<script>
  function setMode(mode) {
    document.getElementById('mode').value = mode;
    const isSignup = mode === 'signup';

    document.getElementById('tabLogin').classList.toggle('active', !isSignup);
    document.getElementById('tabSignup').classList.toggle('active', isSignup);

    document.getElementById('emailBox').style.display = isSignup ? 'block' : 'none';
    document.getElementById('confirmBox').style.display = isSignup ? 'block' : 'none';
    document.getElementById('roleSelection').style.display = isSignup ? 'block' : 'none';

    document.getElementById('email').required = isSignup;
    document.getElementById('submitBtn').textContent = isSignup ? 'Create Account' : 'Login';

    if(!isSignup) {
        document.getElementById('employerFields').style.display = 'none';
    } else {
        setRole(document.getElementById('role').value);
    }
  }

  function setRole(role) {
      document.getElementById('role').value = role;
      const isEmployer = role === 'employer';

      document.getElementById('btnSeeker').classList.toggle('selected', !isEmployer);
      document.getElementById('btnEmployer').classList.toggle('selected', isEmployer);

      document.getElementById('employerFields').style.display = isEmployer ? 'block' : 'none';

      // Reset company states when switching
      document.getElementById('companySearch').value = '';
      resetCompanyToNew();
  }

  // Company Search Logic
  let debounceTimer;
  const searchInput = document.getElementById('companySearch');
  const searchResults = document.getElementById('searchResults');

  searchInput.addEventListener('input', (e) => {
      clearTimeout(debounceTimer);
      const val = e.target.value.trim();

      if (val.length < 2) {
          searchResults.style.display = 'none';
          resetCompanyToNew(val);
          return;
      }

      debounceTimer = setTimeout(async () => {
          try {
              const res = await fetch('search_companies.php?q=' + encodeURIComponent(val));
              const result = await res.json();

              if (result.success && result.data) {
                  renderResults(result.data, val);
              }
          } catch(e) {}
      }, 300);
  });

  function renderResults(companies, typedQuery) {
      let html = '';
      companies.forEach(c => {
          html += `<div class="search-item" onclick="selectExistingCompany('${c.id}', '${c.name.replace(/'/g, "\\'")}')">🏢 <strong>${c.name}</strong></div>`;
      });
      html += `<div class="search-item create-new" onclick="resetCompanyToNew('${typedQuery.replace(/'/g, "\\'")}')">+ Create "${typedQuery}" as a new company</div>`;

      searchResults.innerHTML = html;
      searchResults.style.display = 'block';
  }

  function selectExistingCompany(id, name) {
      searchInput.value = name;
      searchResults.style.display = 'none';

      document.getElementById('companyAction').value = 'join';
      document.getElementById('selectedCompanyId').value = id;
      document.getElementById('newCompanyFields').style.display = 'none';
  }

  function resetCompanyToNew(nameOverride = '') {
      searchResults.style.display = 'none';
      document.getElementById('companyAction').value = 'create';
      document.getElementById('selectedCompanyId').value = '';
      document.getElementById('newCompanyFields').style.display = 'block';
      if(nameOverride) document.getElementById('newCompanyName').value = nameOverride;
  }

  // Form Submit
  document.getElementById('authForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const mode = document.getElementById('mode').value;
    const alertBox = document.getElementById('alert');

    if (mode === 'signup' && document.getElementById('password').value !== document.getElementById('confirm_password').value) {
        alertBox.textContent = "Passwords do not match.";
        alertBox.className = 'alert error show';
        return;
    }

    const btn = document.getElementById('submitBtn');
    btn.disabled = true;

    try {
        const res = await fetch('auth.php', {
            method: 'POST',
            body: new FormData(e.target)
        });
        const data = await res.json();

        alertBox.textContent = data.message || (data.status === 'success' ? 'Success!' : 'Error occurred.');
        alertBox.className = `alert ${data.status} show`;

        if (data.status === 'success' && data.redirect) {
            setTimeout(() => window.location.href = data.redirect, 1000);
        } else {
            btn.disabled = false;
        }
    } catch(err) {
        alertBox.textContent = "A network error occurred.";
        alertBox.className = 'alert error show';
        btn.disabled = false;
    }
  });
</script>
</body>
</html>
