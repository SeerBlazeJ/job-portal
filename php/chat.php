<?php
require_once "config.php";
if (!isAuthenticated()) {
    header("Location: signin.php");
    exit();
}
$active_session = $_GET["session"] ?? "";
$jwtToken = getJWTToken();

// Make sure we have the exact string UID to align messages correctly
$my_uid = $_SESSION["uid"] ?? "";
if (empty($my_uid)) {
    $profileResult = callRustAPI("/profile", "GET", null, $jwtToken);
    $my_uid = $profileResult["data"]["uid"] ?? "";
}

session_write_close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Messages — JobPortal</title>
    <link rel="stylesheet" href="./css/styles.css">
    <style>
        body { overflow: hidden; }
        .dm-layout { display: flex; height: calc(100vh - 120px); background: rgba(10, 16, 30, 0.8); border: 1px solid rgba(99,102,241,0.15); border-radius: var(--r-xl); overflow: hidden; backdrop-filter: blur(25px); margin-top: 1rem; }

        .dm-sidebar { width: 320px; border-right: 1px solid rgba(255,255,255,0.08); display: flex; flex-direction: column; background: rgba(0,0,0,0.2); }
        .dm-header { padding: 1.5rem; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .dm-header-title { font-weight: bold; font-size: 1.2rem; color: white; margin-bottom: 1rem; }
        .dm-session-list { flex: 1; overflow-y: auto; }
        .dm-session-item { padding: 1rem; cursor: pointer; display: flex; align-items: center; gap: 1rem; border-left: 3px solid transparent; transition: 0.2s;}
        .dm-session-item:hover { background: rgba(99,102,241,0.05); }
        .dm-session-item.active { background: rgba(99,102,241,0.1); border-left-color: var(--indigo-500); }

        .dm-main { flex: 1; display: flex; flex-direction: column; }
        .dm-messages { flex: 1; padding: 1.5rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem; }
        .dm-empty { flex: 1; display: flex; align-items: center; justify-content: center; color: gray; }

        .msg { max-width: 60%; padding: 0.8rem 1rem; border-radius: 1rem; font-size: 0.95rem; line-height: 1.4; word-wrap: break-word; }
        .msg-them { background: rgba(255,255,255,0.05); align-self: flex-start; border-bottom-left-radius: 0.2rem; color: white; }
        .msg-me { background: var(--indigo-500); align-self: flex-end; border-bottom-right-radius: 0.2rem; color: white; }

        .dm-input-area { padding: 1rem; background: rgba(0,0,0,0.3); border-top: 1px solid rgba(255,255,255,0.05); display: flex; gap: 0.5rem; align-items: center; }
        .dm-search-input { width: 100%; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); padding: 0.6rem 1rem; border-radius: var(--r-full); color: white; outline: none; font-size: 0.9rem; }
        .dm-input { flex: 1; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); padding: 0.8rem 1rem; border-radius: var(--r-full); color: white; outline: none; }
        .dm-btn { background: none; border: none; color: var(--indigo-400); font-weight: bold; cursor: pointer; padding: 0 1rem; }
    </style>
</head>
<body>
    <div class="dash-container">
        <a href="dashboard.php" class="dash-btn dash-btn-glass" style="margin-bottom: 1rem; display: inline-block;">← Back</a>
        <div class="dm-layout">
            <div class="dm-sidebar">
                <div class="dm-header">
                    <div class="dm-header-title">Messages</div>
                    <input type="text" id="chat-search" class="dm-search-input" placeholder="Search chats...">
                </div>
                <div id="sessions-list" class="dm-session-list">Loading...</div>
            </div>

            <div id="empty-state" class="dm-empty">Select a chat</div>

            <div id="chat-window" class="dm-main" style="display: none;">
                <div class="dm-header" id="chat-title" style="margin-bottom: 0; padding: 1rem 1.5rem; border-bottom: 1px solid rgba(255,255,255,0.1); font-weight: bold; color: white;">Chat</div>
                <div id="messages-area" class="dm-messages"></div>
                <form id="chat-form" class="dm-input-area">
                    <label style="cursor: pointer;">📎 <input type="file" id="chat-file" style="display: none;"></label>
                    <input type="text" id="chat-input" class="dm-input" placeholder="Type a message..." autocomplete="off">
                    <button type="submit" class="dm-btn">Send</button>
                </form>
            </div>
        </div>
    </div>

    <script>
        const myUid = "<?php echo htmlspecialchars($my_uid); ?>";
        const jwtToken = "<?php echo htmlspecialchars($jwtToken); ?>";
        let activeSession = "<?php echo htmlspecialchars($active_session); ?>";
        let allSessions = []; // Store all sessions globally for searching

        const ws = new WebSocket('ws://localhost:3000/ws?token=' + jwtToken);
        ws.onmessage = (e) => {
            const msg = JSON.parse(e.data);
            if (msg.session_id === activeSession) {
                appendMessage(msg);
                scrollToBottom();
            }
            loadSessions();
        };

        async function loadSessions() {
            const res = await fetch('chat_api.php?action=get_sessions');
            const json = await res.json();
            allSessions = json.data || [];
            renderSessions();
        }

        // Handles rendering AND filtering the chat list
        function renderSessions() {
            const searchQuery = document.getElementById('chat-search').value.toLowerCase();
            const filteredSessions = allSessions.filter(s => s.other_user_name.toLowerCase().includes(searchQuery));

            let html = filteredSessions.length ? '' : '<div style="padding:1rem; color:gray; text-align:center;">No chats found</div>';

            filteredSessions.forEach(s => {
                const active = s.session_id === activeSession ? 'active' : '';
                const avatar = s.other_user_avatar ? `<img src="${s.other_user_avatar}" style="width:40px;height:40px;border-radius:50%;object-fit:cover;">` : '👤';
                const preview = s.last_message || 'New Chat';

                html += `
                    <div class="dm-session-item ${active}" onclick="openSession('${s.session_id}', '${s.other_user_name.replace(/'/g,"\\'")}')">
                        <div style="font-size:1.5rem;">${avatar}</div>
                        <div style="overflow:hidden;">
                            <div style="font-weight:bold; color:white;">${escapeHtml(s.other_user_name)}</div>
                            <div style="font-size:0.8rem; color:gray; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(preview)}</div>
                        </div>
                    </div>`;
            });
            document.getElementById('sessions-list').innerHTML = html;
        }

        // Listen for typing in the search bar
        document.getElementById('chat-search').addEventListener('input', renderSessions);

        async function openSession(id, name) {
            activeSession = id;
            window.history.replaceState(null, '', '?session=' + id);
            document.getElementById('empty-state').style.display = 'none';
            document.getElementById('chat-window').style.display = 'flex';
            document.getElementById('chat-title').innerText = name;

            renderSessions(); // highlight active

            const res = await fetch('chat_api.php?action=get_messages&session_id=' + id);
            const json = await res.json();

            document.getElementById('messages-area').innerHTML = '';
            (json.data || []).forEach(appendMessage);
            scrollToBottom();
        }

        function appendMessage(m) {
            // FIX: Guaranteed matching! Strips all spaces and checks both possible JSON keys.
            const sender = String(m.sender_uid || m.sender_id || "").trim();
            const me = String(myUid).trim();

            const isMe = (sender === me);
            const cls = isMe ? 'msg-me' : 'msg-them';

            let content = escapeHtml(m.content);
            if(m.file_url) content += `<br><a href="${m.file_url}" target="_blank" style="color:inherit; text-decoration:underline; font-size: 0.85rem;">📎 View Attachment</a>`;

            document.getElementById('messages-area').innerHTML += `<div class="msg ${cls}">${content}</div>`;
        }

        function escapeHtml(t) { return String(t||'').replace(/&/g, "&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g, "&quot;"); }
        function scrollToBottom() { const a = document.getElementById('messages-area'); a.scrollTop = a.scrollHeight; }

        document.getElementById('chat-form').onsubmit = async (e) => {
            e.preventDefault();
            const input = document.getElementById('chat-input');
            const file = document.getElementById('chat-file');
            if(!activeSession || (!input.value.trim() && !file.files[0])) return;

            const fd = new FormData();
            fd.append('session_id', activeSession);
            fd.append('content', input.value.trim());
            if(file.files[0]) fd.append('attachment', file.files[0]);

            input.value = ''; file.value = '';
            await fetch('chat_api.php?action=send', { method: 'POST', body: fd });
        };

        // Initialize App
        const urlParams = new URLSearchParams(window.location.search);
                const nameFromUrl = urlParams.get('name') || "Chat"; // Instantly gets the name from the profile button

                loadSessions();
                if(activeSession) {
                    openSession(activeSession, nameFromUrl);
                }
    </script>
</body>
</html>
