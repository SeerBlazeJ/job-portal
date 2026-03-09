<?php
// signin.php
require_once "config.php";
if (isAuthenticated()) {
    header("Location: dashboard.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In / Sign Up — JobPortal</title>
     <link rel="stylesheet" href="./css/styles.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>

    <div class="bg-orbs">
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
        <div class="orb orb-3"></div>
    </div>

    <div class="auth-container">
        <div class="auth-form-container">
            <div class="auth-form-wrapper">

                <a href="index.php" class="auth-logo">
                    <svg width="30" height="30" viewBox="0 0 32 32" fill="none" style="color:var(--indigo-400);filter:drop-shadow(0 0 10px rgba(99,102,241,0.6));">
                        <path d="M16 4L4 10V22L16 28L28 22V10L16 4Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        <path d="M16 16L4 10M16 16V28M16 16L28 10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    <span>JobPortal</span>
                </a>

                <div class="auth-header">
                    <h2 class="auth-title" id="authTitle">Welcome back</h2>
                    <p class="auth-subtitle" id="authSubtitle">Sign in to pick up right where you left off.</p>
                </div>

                <div class="auth-tabs">
                    <div class="auth-tab-indicator" id="tabIndicator"></div>
                    <button class="auth-tab active" id="tab-signin">Sign In</button>
                    <button class="auth-tab" id="tab-signup">Sign Up</button>
                </div>

                <div id="authAlert" class="auth-alert"></div>

                <div class="forms-stack" id="formsStack">

                    <form class="auth-form" id="signinForm" novalidate>
                        <input type="hidden" name="mode" value="login">

                        <div class="form-group">
                            <label class="form-label" for="siUsername">Username</label>
                            <div class="input-wrapper">
                                <svg class="input-icon" width="17" height="17" viewBox="0 0 20 20" fill="none"><path d="M10 10C12.21 10 14 8.21 14 6S12.21 2 10 2 6 3.79 6 6s1.79 4 4 4z" stroke="currentColor" stroke-width="1.5"/><path d="M2 18c0-3.31 3.69-6 8-6s8 2.69 8 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                                <input type="text" id="siUsername" name="username" class="form-input" placeholder="Your username" autocomplete="username" required>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label" for="siPassword">Password</label>
                            <div class="input-wrapper">
                                <svg class="input-icon" width="17" height="17" viewBox="0 0 20 20" fill="none"><rect x="4" y="8" width="12" height="9" rx="1.5" stroke="currentColor" stroke-width="1.5"/><path d="M7 8V5.5C7 3.567 8.567 2 10.5 2 12.433 2 14 3.567 14 5.5V8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                                <input type="password" id="siPassword" name="password" class="form-input" placeholder="Your password" autocomplete="current-password" required>
                                <button type="button" class="password-toggle" onclick="togglePwd('siPassword',this)">
                                    <svg width="17" height="17" viewBox="0 0 20 20" fill="none"><path d="M10 4C5 4 1.73 7.11 1 10c.73 2.89 4 6 9 6s8.27-3.11 9-6c-.73-2.89-4-6-9-6z" stroke="currentColor" stroke-width="1.5"/><circle cx="10" cy="10" r="2.5" stroke="currentColor" stroke-width="1.5"/></svg>
                                </button>
                            </div>
                        </div>

                        <div class="form-options">
                            <label class="checkbox-label">
                                <input type="checkbox" class="checkbox-input">
                                <span class="checkbox-custom"></span>
                                <span class="checkbox-text">Stay signed in</span>
                            </label>
                            <a href="#" class="forgot-link">Forgot password?</a>
                        </div>

                        <button type="submit" class="btn-auth-submit" id="signinBtn">
                            <span class="btn-text">Sign In &nbsp;→</span>
                            <div class="btn-spinner"></div>
                        </button>




                        <p class="auth-footer-text">Don't have an account? <a href="#" class="auth-link" onclick="switchTab('signup');return false;">Sign up →</a></p>
                        <div class="trust-badges">
                            <div class="trust-badge"><svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M8 1L2 4v4c0 3.31 2.67 6.41 6 7 3.33-.59 6-3.69 6-7V4L8 1z" fill="currentColor" opacity=".9"/></svg>SSL Encrypted</div>
                            <div class="trust-badge"><svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M13 2H3C2.45 2 2 2.45 2 3V13c0 .55.45 1 1 1h10c.55 0 1-.45 1-1V3c0-.55-.45-1-1-1z" stroke="currentColor" stroke-width="1.3"/><path d="M5 8l2 2 4-4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>Zero spam</div>
                            <div class="trust-badge"><svg width="13" height="13" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.3"/><path d="M8 5v3l2 2" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>2-min setup</div>
                        </div>
                    </form>


                    <form class="auth-form form-hidden" id="signupForm" novalidate>
                        <input type="hidden" name="mode" value="signup">
                        <input type="hidden" name="role" id="roleInput" value="seeker">
                        <input type="hidden" name="company_action" id="companyAction" value="create">
                        <input type="hidden" name="company_id" id="selectedCompanyId">

                        <div class="form-group">
                            <label class="form-label" for="suUsername">Username</label>
                            <div class="input-wrapper">
                                <svg class="input-icon" width="17" height="17" viewBox="0 0 20 20" fill="none"><path d="M10 10C12.21 10 14 8.21 14 6S12.21 2 10 2 6 3.79 6 6s1.79 4 4 4z" stroke="currentColor" stroke-width="1.5"/><path d="M2 18c0-3.31 3.69-6 8-6s8 2.69 8 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                                <input type="text" id="suUsername" name="username" class="form-input" placeholder="Choose a username" autocomplete="username" required>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label" for="suEmail">Email address</label>
                            <div class="input-wrapper">
                                <svg class="input-icon" width="17" height="17" viewBox="0 0 20 20" fill="none"><path d="M3 4h14c.55 0 1 .45 1 1v10c0 .55-.45 1-1 1H3c-.55 0-1-.45-1-1V5c0-.55.45-1 1-1z" stroke="currentColor" stroke-width="1.5"/><path d="M18 5l-8 6-8-6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                                <input type="email" id="suEmail" name="email" class="form-input" placeholder="you@company.com" autocomplete="email" required>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label" for="suPassword">Password</label>
                            <div class="input-wrapper">
                                <svg class="input-icon" width="17" height="17" viewBox="0 0 20 20" fill="none"><rect x="4" y="8" width="12" height="9" rx="1.5" stroke="currentColor" stroke-width="1.5"/><path d="M7 8V5.5C7 3.567 8.567 2 10.5 2 12.433 2 14 3.567 14 5.5V8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                                <input type="password" id="suPassword" name="password" class="form-input" placeholder="Min. 8 characters" autocomplete="new-password" required>
                                <button type="button" class="password-toggle" onclick="togglePwd('suPassword',this)">
                                    <svg width="17" height="17" viewBox="0 0 20 20" fill="none"><path d="M10 4C5 4 1.73 7.11 1 10c.73 2.89 4 6 9 6s8.27-3.11 9-6c-.73-2.89-4-6-9-6z" stroke="currentColor" stroke-width="1.5"/><circle cx="10" cy="10" r="2.5" stroke="currentColor" stroke-width="1.5"/></svg>
                                </button>
                            </div>
                            <div class="strength-segments">
                                <div class="strength-segment" id="seg1"></div>
                                <div class="strength-segment" id="seg2"></div>
                                <div class="strength-segment" id="seg3"></div>
                                <div class="strength-segment" id="seg4"></div>
                            </div>
                            <span class="strength-text" id="strengthText">Enter a password</span>
                        </div>

                        <div class="form-group">
                            <label class="form-label" for="suConfirm">Confirm password</label>
                            <div class="input-wrapper">
                                <svg class="input-icon" width="17" height="17" viewBox="0 0 20 20" fill="none"><rect x="4" y="8" width="12" height="9" rx="1.5" stroke="currentColor" stroke-width="1.5"/><path d="M7 8V5.5C7 3.567 8.567 2 10.5 2 12.433 2 14 3.567 14 5.5V8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                                <input type="password" id="suConfirm" class="form-input" placeholder="Repeat password" autocomplete="new-password">
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">I am a…</label>
                            <div class="role-toggle-row">
                                <button type="button" class="role-btn selected" id="btnSeeker" onclick="setRole('seeker')">🔍 Job Seeker</button>
                                <button type="button" class="role-btn" id="btnEmployer" onclick="setRole('employer')">🏢 Employer / HR</button>
                            </div>
                        </div>

                        <div class="employer-fields" id="employerFields">
                            <div class="form-group">
                                <label class="form-label">Role / Designation *</label>
                                <div class="input-wrapper">
                                    <svg class="input-icon" width="17" height="17" viewBox="0 0 20 20" fill="none"><rect x="2" y="5" width="16" height="12" rx="1.5" stroke="currentColor" stroke-width="1.5"/><path d="M7 5V4c0-1.1.9-2 2-2h2c1.1 0 2 .9 2 2v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                                    <input type="text" name="designation" id="designation" class="form-input" placeholder="e.g. Hiring Manager">
                                </div>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Company *</label>
                                <div class="company-search-wrap">
                                    <div class="input-wrapper">
                                        <svg class="input-icon" width="17" height="17" viewBox="0 0 20 20" fill="none"><circle cx="9" cy="9" r="5.5" stroke="currentColor" stroke-width="1.5"/><path d="M14 14L18 18" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                                        <input type="text" id="companySearch" class="form-input" placeholder="Search company…" autocomplete="off">
                                    </div>
                                    <div id="searchResults" class="search-results-dropdown"></div>
                                </div>
                            </div>
                            <div class="new-company-fields" id="newCompanyFields">
                                <p class="new-company-note">Company not found? Register it here:</p>
                                <div class="input-wrapper"><input type="text" name="new_company_name" id="newCompanyName" class="form-input" placeholder="Company Name" style="padding-left:1rem;"></div>
                                <div class="input-wrapper"><input type="text" name="new_company_location" class="form-input" placeholder="Location (optional)" style="padding-left:1rem;"></div>
                                <div class="input-wrapper"><input type="url" name="new_company_website" class="form-input" placeholder="Website URL (optional)" style="padding-left:1rem;"></div>
                            </div>
                        </div>

                        <div class="form-options">
                            <label class="checkbox-label">
                                <input type="checkbox" class="checkbox-input" id="termsCheck" required>
                                <span class="checkbox-custom"></span>
                                <span class="checkbox-text">I agree to <a href="#" class="inline-link">Terms</a> &amp; <a href="#" class="inline-link">Privacy</a></span>
                            </label>
                        </div>

                        <button type="submit" class="btn-auth-submit" id="signupBtn">
                            <span class="btn-text">Sign Up &nbsp;→</span>
                            <div class="btn-spinner"></div>
                        </button>
                        <p class="auth-footer-text">Already have an account? <a href="#" class="auth-link" onclick="switchTab('signin');return false;">Sign in →</a></p>
                        <div class="trust-badges">
                            <div class="trust-badge"><svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M8 1L2 4v4c0 3.31 2.67 6.41 6 7 3.33-.59 6-3.69 6-7V4L8 1z" fill="currentColor" opacity=".9"/></svg>SSL Encrypted</div>
                            <div class="trust-badge"><svg width="13" height="13" viewBox="0 0 16 16" fill="none"><path d="M8 1L14 5v4c0 3.5-2.67 6.67-6 7.5C2.67 15.67 0 12.5 0 9V5L8 1z" stroke="currentColor" stroke-width="1.2" fill="none"/><path d="M5 8l2 2 4-4" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>Secure Setup</div>
                            <div class="trust-badge"><svg width="13" height="13" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.3"/><path d="M8 5v3l2 2" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>Cancel anytime</div>
                        </div>
                    </form>

                </div>
            </div>
        </div>
    </div>

    <script>
    (function () {
        const $ = id => document.getElementById(id);

        const signinForm = $('signinForm'), signupForm = $('signupForm');
        const formsStack = $('formsStack'), indicator  = $('tabIndicator');
        const titleEl    = $('authTitle'),  subtitleEl = $('authSubtitle');
        const alertBox   = $('authAlert'),  tabSignin  = $('tab-signin'), tabSignup = $('tab-signup');

        let activeTab = 'signin', isAnimating = false;

        function syncHeight(f) { formsStack.style.minHeight = f.offsetHeight + 'px'; }
        syncHeight(signinForm);

        window.switchTab = function(tab) {
            if (tab === activeTab || isAnimating) return;
            isAnimating = true;
            const toSignup = tab === 'signup';
            const outForm = toSignup ? signinForm : signupForm;
            const inForm  = toSignup ? signupForm : signinForm;
            tabSignin.classList.toggle('active', !toSignup);
            tabSignup.classList.toggle('active',  toSignup);
            indicator.classList.toggle('on-signup', toSignup);
            titleEl.textContent    = toSignup ? 'Sign Up' : 'Welcome back';
            subtitleEl.textContent = toSignup ? 'Create a new account to get started.' : 'Sign in to pick up right where you left off.';
            hideAlert();
            formsStack.style.minHeight = outForm.offsetHeight + 'px';
            outForm.classList.add('form-hidden', toSignup ? 'slide-out-left' : 'slide-out-right');
            setTimeout(() => {
                outForm.classList.remove('slide-out-left','slide-out-right');
                const cls = toSignup ? 'slide-in-right' : 'slide-in-left';
                inForm.classList.add(cls);
                inForm.classList.remove('form-hidden');
                syncHeight(inForm);
                setTimeout(() => { inForm.classList.remove(cls); activeTab = tab; isAnimating = false; }, 440);
            }, 290);
        };

        tabSignin.addEventListener('click', () => switchTab('signin'));
        tabSignup.addEventListener('click', () => switchTab('signup'));

        function showAlert(msg, type) { alertBox.textContent = msg; alertBox.className = `auth-alert ${type} show`; }
        function hideAlert() { alertBox.className = 'auth-alert'; }

        window.togglePwd = function(id, btn) {
            const inp = $(id), isText = inp.type === 'text';
            inp.type = isText ? 'password' : 'text';
            btn.innerHTML = isText
                ? `<svg width="17" height="17" viewBox="0 0 20 20" fill="none"><path d="M10 4C5 4 1.73 7.11 1 10c.73 2.89 4 6 9 6s8.27-3.11 9-6c-.73-2.89-4-6-9-6z" stroke="currentColor" stroke-width="1.5"/><circle cx="10" cy="10" r="2.5" stroke="currentColor" stroke-width="1.5"/></svg>`
                : `<svg width="17" height="17" viewBox="0 0 20 20" fill="none"><path d="M1 1L19 19M8.5 5.2C9 5.07 9.49 5 10 5c5 0 8.27 3.11 9 6-.41 1.64-1.39 3.11-2.72 4.2M5.42 6.5C3.54 7.74 2.18 9.24 1 10c.73 2.89 4 6 9 6 1.85 0 3.55-.52 5-1.42" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`;
        };

        const suPwd = $('suPassword'), stText = $('strengthText');
        const segs  = [1,2,3,4].map(i => $('seg'+i));
        const lcls  = ['active-weak','active-fair','active-good','active-strong'];
        const lnm   = ['weak','fair','good','strong'];
        const llbl  = ['Too weak','Fair — add symbols','Good strength','Strong ✓'];
        if (suPwd) suPwd.addEventListener('input', e => {
            const p = e.target.value; let s = 0;
            if (p.length >= 8) s++;
            if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++;
            if (/[0-9]/.test(p)) s++;
            if (/[^a-zA-Z0-9]/.test(p)) s++;
            segs.forEach((seg,i) => { seg.className='strength-segment'; if(i<s) seg.classList.add(lcls[s-1]); });
            stText.textContent = p.length===0 ? 'Enter a password' : (llbl[s-1]||llbl[0]);
            stText.className   = 'strength-text'+(p.length>0?' '+(lnm[s-1]||'weak'):'');
        });

        window.setRole = function(role) {
            $('roleInput').value = role;
            const emp = role === 'employer';
            $('btnSeeker').classList.toggle('selected', !emp);
            $('btnEmployer').classList.toggle('selected', emp);
            $('employerFields').classList.toggle('visible', emp);
            resetCompanyToNew(); syncHeight(signupForm);
        };

        let timer;
        const cInput = $('companySearch'), cResults = $('searchResults');
        if (cInput) cInput.addEventListener('input', e => {
            clearTimeout(timer);
            const v = e.target.value.trim();
            if (v.length < 2) { cResults.style.display='none'; resetCompanyToNew(v); return; }
            timer = setTimeout(async () => {
                try {
                    const r = await fetch('search_companies.php?q='+encodeURIComponent(v));
                    const d = await r.json();
                    if (d.success && d.data) {
                        cResults.innerHTML = d.data.map(c=>`<div class="search-result-item" onclick="selectCompany('${c.id}','${c.name.replace(/'/g,"\\'")}')">🏢 <strong>${c.name}</strong></div>`).join('')
                            + `<div class="search-result-item create-new" onclick="resetCompanyToNew('${v.replace(/'/g,"\\'")}')">+ Register "<strong>${v}</strong>"</div>`;
                        cResults.style.display='block';
                    }
                } catch(e) {}
            }, 300);
        });

        window.selectCompany = function(id, name) {
            cInput.value=name; cResults.style.display='none';
            $('companyAction').value='join'; $('selectedCompanyId').value=id;
            $('newCompanyFields').style.display='none'; syncHeight(signupForm);
        };
        window.resetCompanyToNew = function(n) {
            cResults.style.display='none'; $('companyAction').value='create'; $('selectedCompanyId').value='';
            $('newCompanyFields').style.display='flex'; if(n) $('newCompanyName').value=n; syncHeight(signupForm);
        };
        document.addEventListener('click', e => { if(cInput&&!cInput.contains(e.target)&&!cResults.contains(e.target)) cResults.style.display='none'; });

        window.handleSocial = function(p) { showNotif(p+' sign-in coming soon!','info'); };

        function showNotif(msg, type) {
            const ex = document.querySelector('.jp-notif'); if(ex) ex.remove();
            const n = document.createElement('div'); n.className='jp-notif';
            const col = {success:'#34D399',error:'#FB7185',info:'#818CF8'};
            n.style.cssText=`position:fixed;top:1.5rem;right:1.5rem;z-index:9999;padding:.8rem 1.2rem;background:rgba(6,9,24,.97);border:1.5px solid ${col[type]||col.info};border-radius:12px;color:#F1F5FF;font-size:.875rem;font-weight:600;display:flex;align-items:center;gap:.6rem;box-shadow:0 8px 32px rgba(0,0,0,.5);font-family:'DM Sans',sans-serif;`;
            n.innerHTML=`<span style="color:${col[type]||col.info};">${type==='success'?'✓':type==='error'?'✕':'ℹ'}</span>${msg}`;
            document.body.appendChild(n);
            setTimeout(()=>{ n.style.transition='.3s'; n.style.opacity='0'; setTimeout(()=>n.remove(),320); },3800);
        }

        function createConfetti(el) {
            const colors=['#6366F1','#8B5CF6','#34D399','#22D3EE','#FBBF24'];
            const rect=el.getBoundingClientRect();
            for(let i=0;i<26;i++){
                const c=document.createElement('div');
                Object.assign(c.style,{position:'fixed',width:'9px',height:'9px',background:colors[i%5],borderRadius:Math.random()>.5?'50%':'0',pointerEvents:'none',zIndex:'9999',left:rect.left+rect.width/2+'px',top:rect.top+rect.height/2+'px'});
                document.body.appendChild(c);
                const a=(Math.PI*2*i)/26,v=50+Math.random()*55;
                let x=0,y=0,op=1,vy=Math.sin(a)*v-50,vx=Math.cos(a)*v;
                (function f(){x+=vx*.1;y+=vy*.1;vy+=2.5;op-=.015;c.style.transform=`translate(${x}px,${y}px) rotate(${x*3}deg)`;c.style.opacity=op;if(op>0)requestAnimationFrame(f);else c.remove();})();
            }
        }

        signinForm.addEventListener('submit', async e => {
            e.preventDefault(); const btn=$('signinBtn'); hideAlert();
            if(!$('siUsername').value.trim()||!$('siPassword').value){showAlert('Please fill in all fields.','error');return;}
            btn.classList.add('loading'); btn.disabled=true;
            try {
                const res=await fetch('auth.php',{method:'POST',body:new FormData(signinForm)});;
                const data=await res.json();
                if(data.status==='success'){
                    btn.classList.remove('loading'); btn.style.background='linear-gradient(135deg,#10B981,#06B6D4)';
                    btn.innerHTML='<span class="btn-text">✓ Signed in!</span>';
                    showAlert(data.message||'Welcome back!','success'); createConfetti(btn);
                    if(data.redirect) setTimeout(()=>window.location.href=data.redirect,1200);
                } else { showAlert(data.message||'Invalid credentials.','error'); btn.classList.remove('loading'); btn.disabled=false; }
            } catch(err){ showAlert('Network error. Please try again.','error'); btn.classList.remove('loading'); btn.disabled=false; }
        });

        signupForm.addEventListener('submit', async e => {
            e.preventDefault(); const btn=$('signupBtn'); hideAlert();
            const u=$('suUsername').value.trim(),em=$('suEmail').value.trim(),p=$('suPassword').value,c=$('suConfirm').value;
            if(!u||!em||!p){showAlert('Please fill in all required fields.','error');return;}
            if(p!==c){showAlert('Passwords do not match.','error');return;}
            if(p.length<8){showAlert('Password must be at least 8 characters.','error');return;}
            if(!$('termsCheck').checked){showAlert('Please accept the Terms & Privacy Policy.','error');return;}
            btn.classList.add('loading'); btn.disabled=true;
            try {
                const res=await fetch('auth.php',{method:'POST',body:new FormData(signupForm)});;
                const data=await res.json();
                if(data.status==='success'){
                    btn.classList.remove('loading'); btn.style.background='linear-gradient(135deg,#10B981,#06B6D4)';
                    btn.innerHTML='<span class="btn-text">✓ Signed up successfully!</span>';
                    showAlert(data.message||'Account created!','success'); createConfetti(btn);
                    if(data.redirect) setTimeout(()=>window.location.href=data.redirect,1200);
                    else setTimeout(()=>switchTab('signin'),1600);
                } else { showAlert(data.message||'Registration failed.','error'); btn.classList.remove('loading'); btn.disabled=false; }
            } catch(err){ showAlert('Network error.','error'); btn.classList.remove('loading'); btn.disabled=false; }
        });

        document.body.style.opacity='0';
        setTimeout(()=>{ document.body.style.transition='opacity .4s ease'; document.body.style.opacity='1'; },50);
    })();
    </script>
</body>
</html>
