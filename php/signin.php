<?php
// signin.php
require_once 'config.php';

if (isAuthenticated()) {
    header('Location: dashboard.php');
    exit;
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
    .muted { color:#666; margin:0 0 16px; }
    .tabs { display:flex; gap:10px; margin: 16px 0 20px; }
    .tab { flex:1; padding:10px; border-radius:8px; border:1px solid #ddd; background:#f7f7f7; cursor:pointer; font-weight:600; }
    .tab.active { background:#667eea; color:#fff; border-color:#667eea; }
    label { display:block; font-size:13px; color:#333; margin: 12px 0 6px; font-weight:600; }
    input { width:100%; padding:12px; border-radius:8px; border:1px solid #ddd; font-size:14px; }
    button { width:100%; margin-top:16px; padding:12px; border:0; border-radius:8px; background:#667eea; color:#fff; font-weight:700; cursor:pointer; }
    button:disabled { opacity:.7; cursor:not-allowed; }
    .alert { margin: 14px 0 0; padding: 12px; border-radius: 8px; display:none; white-space: pre-wrap; }
    .alert.show { display:block; }
    .alert.error { background:#f8d7da; border:1px solid #f5c6cb; color:#721c24; }
    .alert.success { background:#d4edda; border:1px solid #c3e6cb; color:#155724; }
    .row { display:flex; gap:10px; }
    .row > div { flex: 1; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Job Portal</h1>
      <p class="muted">Login or create a new account.</p>

      <div class="tabs">
        <button class="tab active" id="tabLogin" type="button">Login</button>
        <button class="tab" id="tabSignup" type="button">Signup</button>
      </div>

      <div id="alert" class="alert"></div>

      <form id="authForm">
        <input type="hidden" name="mode" id="mode" value="login" />

        <label for="username">Username</label>
        <input id="username" name="username" type="text" autocomplete="username" required />

        <div id="emailBox" style="display:none;">
          <label for="email">Email</label>
          <input id="email" name="email" type="email" autocomplete="email" />
        </div>

        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required />

        <div id="confirmBox" style="display:none;">
          <label for="confirm_password">Confirm password</label>
          <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" />
        </div>

        <button id="submitBtn" type="submit">Continue</button>
      </form>
    </div>
  </div>

<script>
  const tabLogin = document.getElementById('tabLogin');
  const tabSignup = document.getElementById('tabSignup');
  const mode = document.getElementById('mode');
  const emailBox = document.getElementById('emailBox');
  const confirmBox = document.getElementById('confirmBox');
  const alertBox = document.getElementById('alert');
  const form = document.getElementById('authForm');
  const submitBtn = document.getElementById('submitBtn');

  function showAlert(type, msg) {
    alertBox.className = `alert show ${type}`;
    alertBox.textContent = msg;
  }
  function clearAlert() {
    alertBox.className = 'alert';
    alertBox.textContent = '';
  }

  function setMode(newMode) {
    mode.value = newMode;
    const signup = newMode === 'signup';

    tabLogin.classList.toggle('active', !signup);
    tabSignup.classList.toggle('active', signup);

    emailBox.style.display = signup ? 'block' : 'none';
    confirmBox.style.display = signup ? 'block' : 'none';

    document.getElementById('email').required = signup;
    document.getElementById('confirm_password').required = signup;

    submitBtn.textContent = signup ? 'Create account' : 'Login';
    clearAlert();
  }

  tabLogin.addEventListener('click', () => setMode('login'));
  tabSignup.addEventListener('click', () => setMode('signup'));

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAlert();

    const m = mode.value;
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const email = document.getElementById('email').value.trim();
    const confirm = document.getElementById('confirm_password').value;

    if (!username || !password) {
      showAlert('error', 'Username and password are required.');
      return;
    }

    if (m === 'signup') {
      if (!email) { showAlert('error', 'Email is required for signup.'); return; }
      if (password !== confirm) { showAlert('error', 'Passwords do not match.'); return; }
    }

    submitBtn.disabled = true;

    try {
      const fd = new FormData(form);

      const res = await fetch('auth.php', {
        method: 'POST',
        body: fd,
        credentials: 'same-origin',   // be explicit so Set-Cookie is honored
        cache: 'no-store',
      });

      const data = await res.json();

      if (data.status === 'success') {
        showAlert('success', data.message || 'Success');
        if (data.redirect === 'login') {
          setTimeout(() => setMode('login'), 800);
        } else if (data.redirect) {
          setTimeout(() => window.location.href = data.redirect, 500);
        }
      } else {
        // Show every error message we have
        const parts = [];
        if (data.message) parts.push(`Message: ${data.message}`);
        if (data.status_code) parts.push(`Status: ${data.status_code}`);
        if (data.backend_data) parts.push(`Backend data: ${JSON.stringify(data.backend_data, null, 2)}`);
        if (data.backend_raw) parts.push(`Backend raw: ${data.backend_raw}`);
        showAlert('error', parts.join('\n'));
      }
    } catch (err) {
      showAlert('error', 'Client error: ' + (err?.message || String(err)));
    } finally {
      submitBtn.disabled = false;
    }
  });

  setMode('login');
</script>
</body>
</html>
