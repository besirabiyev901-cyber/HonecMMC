// ══════════════════════════════════════════════════════════════════
//  admin.js — Honec Admin Panel
//  Admin-only: user management, role changes, ban/delete,
//  messages, newsletter, posts, permissions.
//  Requires: supabase-config.js (window.SUPABASE_URL, window.SUPABASE_ANON)
// ══════════════════════════════════════════════════════════════════

import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm';

const supabase = createClient(window.SUPABASE_URL, window.SUPABASE_ANON);

// ── Globals ─────────────────────────────────────────────────────
let currentUser    = null;
let currentProfile = null;
let allUsers       = [];
let allMessages    = [];
let allSubs        = [];
let allPosts       = [];

// ── Utils ────────────────────────────────────────────────────────

function esc(str = '') {
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtDate(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleString('en-GB', {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}

function fmtDateShort(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

function initials(name = '') {
    return name.trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase() || '??';
}

function toast(msg, ok = true) {
    const c = document.getElementById('admToastContainer');
    const t = document.createElement('div');
    t.className = `adm-toast ${ok ? 'ok' : 'err'}`;
    t.innerHTML = ok
        ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>${esc(msg)}`
        : `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>${esc(msg)}`;
    c.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, 3500);
}

function confirm(title, body, okLabel = 'Confirm', danger = true) {
    return new Promise(resolve => {
        const modal  = document.getElementById('confirmModal');
        document.getElementById('confirmTitle').textContent = title;
        document.getElementById('confirmBody').textContent  = body;
        const okBtn  = document.getElementById('confirmOk');
        okBtn.textContent = okLabel;
        okBtn.className = `adm-btn ${danger ? 'adm-btn-danger' : 'adm-btn-primary'}`;
        modal.style.display = 'flex';
        const done = (val) => { modal.style.display = 'none'; resolve(val); ok.removeEventListener('click', yes); no.removeEventListener('click', no_fn); };
        const yes   = () => done(true);
        const no_fn = () => done(false);
        const ok    = document.getElementById('confirmOk');
        const no    = document.getElementById('confirmCancel');
        ok.addEventListener('click', yes);
        no.addEventListener('click', no_fn);
        modal.addEventListener('click', e => { if (e.target === modal) done(false); }, { once: true });
    });
}

// ── Navigation ────────────────────────────────────────────────────

function initNav() {
    document.querySelectorAll('.adm-nav-link[data-section]').forEach(btn => {
        btn.addEventListener('click', () => goTo(btn.dataset.section));
    });
    document.querySelectorAll('[data-goto]').forEach(btn => {
        btn.addEventListener('click', () => goTo(btn.dataset.goto));
    });
    document.getElementById('sidebarToggle')?.addEventListener('click', () => {
        document.getElementById('admSidebar').classList.toggle('open');
    });
}

function goTo(section) {
    document.querySelectorAll('.adm-sections').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.adm-nav-link').forEach(b => b.classList.remove('active'));
    const sec = document.getElementById(`sec-${section}`);
    if (sec) sec.classList.add('active');
    const btn = document.querySelector(`.adm-nav-link[data-section="${section}"]`);
    if (btn) btn.classList.add('active');
    document.getElementById('admSidebar').classList.remove('open');
}

// ── Auth Gate ─────────────────────────────────────────────────────

async function authGate() {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) { window.location.replace('auth.html'); return false; }
    const { data: profile } = await supabase.from('profiles').select('*').eq('id', user.id).single();
    if (!profile || !['admin', 'moderator'].includes(profile.role)) {
        window.location.replace('index.html');
        return false;
    }
    currentUser    = user;
    currentProfile = profile;

    // Reveal page now that auth is confirmed
    document.body.style.visibility = 'visible';

    // Update topbar
    document.getElementById('topbarEmail').textContent = profile.name || user.email;
    const roleEl = document.getElementById('topbarRole');
    roleEl.textContent = profile.role;
    roleEl.className   = `adm-badge-role ${profile.role}`;

    // Hide admin-only nav for moderators
    if (profile.role === 'moderator') {
        document.getElementById('permissionsNav')?.remove();
    }

    document.getElementById('logoutBtn').addEventListener('click', async () => {
        await supabase.auth.signOut();
        window.location.replace('auth.html');
    });

    return true;
}

// ── Load all data ─────────────────────────────────────────────────

async function loadAll() {
    const isAdmin = currentProfile.role === 'admin';

    // Parallel fetch
    const [usersRes, msgsRes, subsRes, postsRes] = await Promise.all([
        supabase.from('profiles').select('id,name,email,role,banned,auth_provider,created_at').order('created_at', { ascending: false }),
        supabase.from('messages').select('*').order('created_at', { ascending: false }),
        supabase.from('newsletters').select('*').order('created_at', { ascending: false }),
        supabase.from('posts').select('id,title,description,published,author_id,created_at,updated_at').order('created_at', { ascending: false }),
    ]);

    allUsers    = usersRes.data    || [];
    allMessages = msgsRes.data     || [];
    allSubs     = subsRes.data     || [];
    allPosts    = postsRes.data    || [];

    // Stats
    updateStats();
    updateNavBadges();

    // Render sections
    renderOverview();
    renderUsersTable();
    renderMessagesSection();
    renderSubsTable();
    renderPostsTable();
}

function updateStats() {
    const banned = allUsers.filter(u => u.banned).length;
    const mods   = allUsers.filter(u => u.role === 'moderator').length;
    document.getElementById('statUsers').textContent    = allUsers.length;
    document.getElementById('statMods').textContent     = mods;
    document.getElementById('statBanned').textContent   = banned;
    document.getElementById('statPosts').textContent    = allPosts.length;
    document.getElementById('statMessages').textContent = allMessages.length;
    document.getElementById('statSubs').textContent     = allSubs.length;
}

function updateNavBadges() {
    document.getElementById('navUserCount').textContent = allUsers.length;
    document.getElementById('navMsgCount').textContent  = allMessages.length;
    document.getElementById('navSubCount').textContent  = allSubs.length;
    document.getElementById('navPostCount').textContent = allPosts.length;
}

// ── OVERVIEW ─────────────────────────────────────────────────────

function renderOverview() {
    // Recent messages (last 5)
    const msgContainer = document.getElementById('overviewMessages');
    const recent = allMessages.slice(0, 5);
    if (!recent.length) {
        msgContainer.innerHTML = `<div class="adm-empty">No messages yet.</div>`;
    } else {
        msgContainer.innerHTML = recent.map(m => messagCardHTML(m)).join('');
    }

    // Recent users (last 5)
    const tbody = document.getElementById('overviewUsers');
    const recentUsers = allUsers.slice(0, 5);
    tbody.innerHTML = recentUsers.map(u => `
        <tr>
            <td>
                <div class="adm-user-cell">
                    <div class="adm-avatar">${initials(u.name)}</div>
                    <div>
                        <div class="adm-user-info-name">${esc(u.name || '—')}</div>
                        <div class="adm-user-info-email">${esc(u.email)}</div>
                    </div>
                </div>
            </td>
            <td><span class="adm-pill ${u.role}">${u.role}</span></td>
            <td><span class="adm-pill ${u.banned ? 'banned' : 'active'}">${u.banned ? 'banned' : 'active'}</span></td>
            <td class="adm-mono adm-text-muted" style="font-size:.75rem">${fmtDateShort(u.created_at)}</td>
        </tr>`).join('');
}

// ── USERS TABLE ───────────────────────────────────────────────────

function renderUsersTable(users = allUsers) {
    const tbody = document.getElementById('usersTableBody');
    if (!users.length) {
        tbody.innerHTML = `<tr><td colspan="6"><div class="adm-empty">No users found.</div></td></tr>`;
        return;
    }
    const isAdmin = currentProfile.role === 'admin';
    tbody.innerHTML = users.map(u => {
        const isMe = u.id === currentUser.id;
        const roleOpts = ['user', 'moderator', 'admin'].map(r =>
            `<option value="${r}" ${u.role === r ? 'selected' : ''}>${r}</option>`).join('');

        const roleControl = (isAdmin && !isMe)
            ? `<select class="adm-role-select" data-uid="${u.id}" data-action="role">${roleOpts}</select>`
            : `<span class="adm-pill ${u.role}">${u.role}</span>`;

        const banBtn = (isAdmin && !isMe)
            ? `<button class="adm-btn adm-btn-sm ${u.banned ? 'adm-btn-green' : 'adm-btn-danger'}"
                    data-uid="${u.id}" data-banned="${u.banned}" data-action="ban">
                    ${u.banned ? 'Unban' : 'Ban'}
                </button>` : '';

        const delBtn = (isAdmin && !isMe)
            ? `<button class="adm-btn adm-btn-sm adm-btn-danger" data-uid="${u.id}" data-action="delete-user" style="opacity:.7">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                    Delete
                </button>` : '';

        const provider = u.auth_provider && u.auth_provider !== 'email'
            ? `<span class="adm-pill ${u.auth_provider === 'google' ? 'published' : 'user'}" style="font-size:.65rem">${u.auth_provider}</span>`
            : `<span style="font-size:.78rem;color:var(--adm-muted)">email</span>`;

        return `<tr data-uid="${u.id}">
            <td>
                <div class="adm-user-cell">
                    <div class="adm-avatar">${initials(u.name)}</div>
                    <div>
                        <div class="adm-user-info-name">${esc(u.name || '—')}${isMe ? ' <span style="font-size:.7rem;color:var(--adm-muted)">(you)</span>' : ''}</div>
                        <div class="adm-user-info-email">${esc(u.email)}</div>
                    </div>
                </div>
            </td>
            <td>${roleControl}</td>
            <td><span class="adm-pill ${u.banned ? 'banned' : 'active'}">${u.banned ? 'banned' : 'active'}</span></td>
            <td>${provider}</td>
            <td class="adm-mono adm-text-muted" style="font-size:.75rem">${fmtDateShort(u.created_at)}</td>
            <td>
                <div class="adm-actions-cell">
                    ${banBtn}${delBtn}
                </div>
            </td>
        </tr>`;
    }).join('');

    // Events
    tbody.querySelectorAll('[data-action="role"]').forEach(sel => {
        sel.addEventListener('change', async () => {
            const uid = sel.dataset.uid;
            const newRole = sel.value;
            const u = allUsers.find(u => u.id === uid);
            if (!u) return;
            const ok = await confirm(
                'Change Role',
                `Change ${u.name || u.email} from "${u.role}" to "${newRole}"?`,
                'Change Role', false
            );
            if (!ok) { sel.value = u.role; return; }
            const { error } = await supabase.rpc('set_user_role', { target_id: uid, new_role: newRole });
            if (error) { toast(error.message, false); sel.value = u.role; return; }
            u.role = newRole;
            updateStats();
            // Update pill in same row
            const row = tbody.querySelector(`tr[data-uid="${uid}"]`);
            const statusPill = row?.querySelector('.adm-pill.active, .adm-pill.banned');
            toast(`Role updated to ${newRole}`);
        });
    });

    tbody.querySelectorAll('[data-action="ban"]').forEach(btn => {
        btn.addEventListener('click', async () => {
            const uid    = btn.dataset.uid;
            const banned = btn.dataset.banned === 'true';
            const u      = allUsers.find(u => u.id === uid);
            if (!u) return;
            const ok = await confirm(
                banned ? 'Unban User' : 'Ban User',
                `${banned ? 'Unban' : 'Ban'} ${u.name || u.email}? ${banned ? 'They will regain access.' : 'They cannot comment or like posts.'}`,
                banned ? 'Unban' : 'Ban User',
                !banned
            );
            if (!ok) return;
            const { error } = await supabase.rpc('ban_user', { target_id: uid, should_ban: !banned });
            if (error) { toast(error.message, false); return; }
            u.banned = !banned;
            updateStats();
            renderUsersTable(filteredUsers());
            toast(banned ? 'User unbanned.' : 'User banned.');
        });
    });

    tbody.querySelectorAll('[data-action="delete-user"]').forEach(btn => {
        btn.addEventListener('click', async () => {
            const uid = btn.dataset.uid;
            const u   = allUsers.find(u => u.id === uid);
            if (!u) return;
            const ok = await confirm(
                'Delete Account',
                `Permanently delete "${u.name || u.email}"? This cannot be undone. All their posts, comments, and data will be removed.`,
                'Delete Forever',
                true
            );
            if (!ok) return;
            const { error } = await supabase.rpc('delete_user_profile', { target_id: uid });
            if (error) { toast(error.message, false); return; }
            allUsers = allUsers.filter(u => u.id !== uid);
            updateStats();
            updateNavBadges();
            renderUsersTable(filteredUsers());
            toast('Account deleted.');
        });
    });
}

function filteredUsers() {
    const q      = (document.getElementById('userSearch')?.value || '').toLowerCase();
    const role   = document.getElementById('userRoleFilter')?.value || '';
    const status = document.getElementById('userStatusFilter')?.value || '';
    return allUsers.filter(u => {
        const matchQ      = !q || u.name?.toLowerCase().includes(q) || u.email?.toLowerCase().includes(q);
        const matchRole   = !role   || u.role === role;
        const matchStatus = !status || (status === 'banned' ? u.banned : !u.banned);
        return matchQ && matchRole && matchStatus;
    });
}

// ── MESSAGES ─────────────────────────────────────────────────────

function messagCardHTML(m) {
    const isAdmin = currentProfile.role === 'admin';
    const delBtn  = isAdmin
        ? `<button class="adm-btn adm-btn-sm adm-btn-danger" data-msgid="${m.id}" data-action="delete-msg" style="opacity:.7">Delete</button>`
        : '';
    return `
        <div class="adm-msg-card" data-msgid="${m.id}">
            <div class="adm-msg-header">
                <div>
                    <div class="adm-msg-from">${esc(m.name)}</div>
                    <div class="adm-msg-email">${esc(m.email)}</div>
                </div>
                <div style="display:flex;align-items:center;gap:.75rem">
                    <span class="adm-msg-time">${fmtDate(m.created_at)}</span>
                    ${delBtn}
                </div>
            </div>
            <div class="adm-msg-subject">${esc(m.subject)}</div>
            <div class="adm-msg-body">${esc(m.message)}</div>
        </div>`;
}

function renderMessagesSection(messages = allMessages) {
    const body = document.getElementById('messagesBody');
    if (!messages.length) {
        body.innerHTML = `<div class="adm-empty">No messages yet.</div>`;
        return;
    }
    body.innerHTML = messages.map(m => messagCardHTML(m)).join('');

    body.querySelectorAll('[data-action="delete-msg"]').forEach(btn => {
        btn.addEventListener('click', async () => {
            const mid = btn.dataset.msgid;
            const ok  = await confirm('Delete Message', 'Permanently delete this contact message?', 'Delete');
            if (!ok) return;
            const { error } = await supabase.from('messages').delete().eq('id', mid);
            if (error) { toast(error.message, false); return; }
            allMessages = allMessages.filter(m => m.id !== mid);
            updateStats();
            updateNavBadges();
            renderMessagesSection(filteredMessages());
            renderOverview();
            toast('Message deleted.');
        });
    });
}

function filteredMessages() {
    const q = (document.getElementById('msgSearch')?.value || '').toLowerCase();
    return !q ? allMessages : allMessages.filter(m =>
        m.name?.toLowerCase().includes(q) || m.email?.toLowerCase().includes(q) ||
        m.subject?.toLowerCase().includes(q) || m.message?.toLowerCase().includes(q)
    );
}

// ── SUBSCRIBERS ───────────────────────────────────────────────────

function renderSubsTable(subs = allSubs) {
    const tbody = document.getElementById('subsTableBody');
    if (!subs.length) {
        tbody.innerHTML = `<tr><td colspan="3"><div class="adm-empty">No subscribers yet.</div></td></tr>`;
        return;
    }
    tbody.innerHTML = subs.map(s => `
        <tr data-subid="${s.id}">
            <td class="adm-mono" style="font-size:.84rem">${esc(s.email)}</td>
            <td class="adm-mono adm-text-muted" style="font-size:.75rem">${fmtDateShort(s.created_at)}</td>
            <td></td>
        </tr>`).join('');
}

function filteredSubs() {
    const q = (document.getElementById('subSearch')?.value || '').toLowerCase();
    return !q ? allSubs : allSubs.filter(s => s.email?.toLowerCase().includes(q));
}

// ── POSTS TABLE ───────────────────────────────────────────────────

function renderPostsTable(posts = allPosts) {
    const tbody = document.getElementById('postsTableBody');
    if (!posts.length) {
        tbody.innerHTML = `<tr><td colspan="5"><div class="adm-empty">No posts yet.</div></td></tr>`;
        return;
    }
    const authorMap = Object.fromEntries(allUsers.map(u => [u.id, u]));
    tbody.innerHTML = posts.map(p => {
        const author = authorMap[p.author_id] || {};
        return `
        <tr class="adm-post-row" data-postid="${p.id}">
            <td>
                <div class="adm-post-title">${esc(p.title)}</div>
                <div class="adm-post-preview">${esc(p.description)}</div>
            </td>
            <td style="font-size:.84rem">${esc(author.name || 'Unknown')}</td>
            <td><span class="adm-pill ${p.published ? 'published' : 'draft'}">${p.published ? 'Published' : 'Draft'}</span></td>
            <td class="adm-mono adm-text-muted" style="font-size:.75rem">${fmtDateShort(p.created_at)}</td>
            <td>
                <div class="adm-actions-cell">
                    <button class="adm-btn adm-btn-sm ${p.published ? 'adm-btn-ghost' : 'adm-btn-green'}" data-postid="${p.id}" data-action="toggle-pub" data-published="${p.published}">
                        ${p.published ? 'Unpublish' : 'Publish'}
                    </button>
                    <a class="adm-btn adm-btn-sm adm-btn-blue" href="news.html#edit-${p.id}">Edit</a>
                    <button class="adm-btn adm-btn-sm adm-btn-danger" data-postid="${p.id}" data-action="delete-post" style="opacity:.7">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
                    </button>
                </div>
            </td>
        </tr>`;
    }).join('');

    tbody.querySelectorAll('[data-action="toggle-pub"]').forEach(btn => {
        btn.addEventListener('click', async () => {
            const pid       = btn.dataset.postid;
            const published = btn.dataset.published === 'true';
            const { error } = await supabase.from('posts').update({ published: !published }).eq('id', pid);
            if (error) { toast(error.message, false); return; }
            const post = allPosts.find(p => p.id === pid);
            if (post) post.published = !published;
            renderPostsTable(filteredPosts());
            updateStats();
            toast(published ? 'Post unpublished.' : 'Post published.');
        });
    });

    tbody.querySelectorAll('[data-action="delete-post"]').forEach(btn => {
        btn.addEventListener('click', async () => {
            const pid  = btn.dataset.postid;
            const post = allPosts.find(p => p.id === pid);
            if (!post) return;
            const ok = await confirm('Delete Post', `Permanently delete "${post.title}"? All comments and likes will be removed.`, 'Delete Forever');
            if (!ok) return;
            const { error } = await supabase.from('posts').delete().eq('id', pid);
            if (error) { toast(error.message, false); return; }
            allPosts = allPosts.filter(p => p.id !== pid);
            updateStats();
            updateNavBadges();
            renderPostsTable(filteredPosts());
            toast('Post deleted.');
        });
    });
}

function filteredPosts() {
    const q      = (document.getElementById('postSearch')?.value || '').toLowerCase();
    const status = document.getElementById('postStatusFilter')?.value || '';
    return allPosts.filter(p => {
        const matchQ = !q || p.title?.toLowerCase().includes(q) || p.description?.toLowerCase().includes(q);
        const matchS = !status || (status === 'published' ? p.published : !p.published);
        return matchQ && matchS;
    });
}

// ── SEARCH / FILTER EVENT LISTENERS ──────────────────────────────

function initFilters() {
    const debounce = (fn, ms = 250) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

    document.getElementById('userSearch')?.addEventListener('input', debounce(() => renderUsersTable(filteredUsers())));
    document.getElementById('userRoleFilter')?.addEventListener('change', () => renderUsersTable(filteredUsers()));
    document.getElementById('userStatusFilter')?.addEventListener('change', () => renderUsersTable(filteredUsers()));

    document.getElementById('msgSearch')?.addEventListener('input', debounce(() => renderMessagesSection(filteredMessages())));

    document.getElementById('subSearch')?.addEventListener('input', debounce(() => renderSubsTable(filteredSubs())));

    document.getElementById('postSearch')?.addEventListener('input', debounce(() => renderPostsTable(filteredPosts())));
    document.getElementById('postStatusFilter')?.addEventListener('change', () => renderPostsTable(filteredPosts()));
}

// ── INIT ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
    const ok = await authGate();
    if (!ok) return;
    initNav();
    initFilters();
    await loadAll();
});