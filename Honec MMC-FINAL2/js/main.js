// ══════════════════════════════════════════════════════════════════
//  main.js  v6 — Security upgrade
//
//  SECURITY CHANGES (v6):
//    1. Import csrf.js — apiPost/apiDelete wrappers attach X-CSRF-Token
//       header automatically to all /api/* calls.
//    2. handleContact() now calls rpc_insert_message() instead of
//       direct table insert — server-side validation + 5-min rate limit.
//    3. handleNewsletter() now calls rpc_insert_newsletter() — direct
//       anon INSERT on newsletter table is revoked in Supabase.
//    4. loadPosts() queries v_public_posts (SECURITY DEFINER view) for
//       non-privileged users instead of posts with client-side filter,
//       preventing RLS bypass via crafted queries.
//
//  BUG FIXES vs uploaded version (v5):
//    1. handleNewsletter() used supabase.from('newsletter') but the
//       DB table is 'newsletters' (with an 's'). Fixed to 'newsletters'.
//    2. handleOAuthCallback() awaited new Promise(r => setTimeout(r,100))
//       with no await — it was called but the session check ran
//       immediately before Supabase finished processing the hash/code.
//       Added proper await.
//    3. loadPosts() fetched author profiles in a second round-trip
//       inside a loop (N+1 pattern). Collapsed into one .in() call
//       outside the loop.
//    4. handleRealtimeCommentInsert() built HTML for a comment then
//       attached the delete event listener via querySelector AFTER
//       insertBefore, but querySelector searches the entire section —
//       it would match the wrong button if multiple comments were
//       inserting simultaneously. Fixed to use the direct el reference.
//    5. initOAuth() checked window.location.search.includes('code=')
//       but PKCE codes can also appear in the hash. Added hash check.
//    6. Missing DOMContentLoaded closing brace — the last init block
//       was left open. Added proper closure.
// ══════════════════════════════════════════════════════════════════

import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm';
import { apiPost, apiDelete } from './csrf.js';

const supabase = createClient(window.SUPABASE_URL, window.SUPABASE_ANON, {
    realtime: { params: { eventsPerSecond: 10 } }
});

// ══════════════════════════════════════════════════════════════════
//  UTILITIES
// ══════════════════════════════════════════════════════════════════

function setStatus(form, msg, ok = true) {
    const el = form.querySelector('.form-status');
    if (!el) return;
    el.textContent = msg;
    el.style.color = ok ? 'var(--orange)' : '#c0392b';
}

function fmtDate(iso) {
    return new Date(iso).toLocaleString('en-GB', {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}

function fmtRelative(iso) {
    const diff = Date.now() - new Date(iso).getTime();
    const s = Math.floor(diff / 1000);
    if (s < 10) return 'just now';
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return fmtDate(iso);
}

function escHtml(str = '') {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function isYouTubeUrl(url) {
    return /youtube\.com|youtu\.be/.test(url);
}

function youtubeEmbedUrl(url) {
    const match = url.match(/(?:v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
    return match ? `https://www.youtube.com/embed/${match[1]}` : url;
}

function fmtBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1024 / 1024).toFixed(1) + ' MB';
}

function debounce(fn, ms = 300) {
    let timer;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
}

const ICONS = {
    heart:    `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>`,
    comment:  `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>`,
    link:     `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
    file:     `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>`,
    download: `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
    edit:     `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
    trash:    `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>`,
    close:    `<svg width="11" height="11" viewBox="0 0 12 12"><path d="M1 1l10 10M11 1L1 11" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`,
    send:     `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>`,
    spinner:  `<svg class="spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10" stroke-opacity=".25"/><path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/></svg>`,
    google:   `<svg width="18" height="18" viewBox="0 0 48 48"><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/></svg>`,
    github:   `<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222 0 1.606-.015 2.896-.015 3.286 0 .315.216.69.825.57C20.565 21.795 24 17.295 24 12c0-6.63-5.37-12-12-12z"/></svg>`,
};

const PROVIDER_LABEL = { google: 'Google', github: 'GitHub', email: 'email & password' };

// ══════════════════════════════════════════════════════════════════
//  DASHBOARD NAV VISIBILITY
// ══════════════════════════════════════════════════════════════════

function hideDashboardLinks() {
    document.querySelectorAll('a[href="messages.html"]').forEach(a => {
        const li = a.closest('li');
        if (li) li.style.display = 'none';
        else a.style.display = 'none';
    });
}

async function applyDashboardVisibility() {
    // Dashboard is always visible to ALL logged-in users.
    // Users see a personal profile page; moderators/admins see the full panel.
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) {
        hideDashboardLinks();
        return;
    }
    // Show dashboard link for everyone who is logged in
    document.querySelectorAll('a[href="messages.html"]').forEach(a => {
        const li = a.closest('li');
        if (li) li.style.display = '';
        else a.style.display = '';
    });
}

// ══════════════════════════════════════════════════════════════════
//  SESSION BADGE
// ══════════════════════════════════════════════════════════════════

async function updateBadge() {
    const badge = document.getElementById('userBadge');
    if (!badge) return;
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) { badge.textContent = 'Not logged in'; return; }
    const { data: profile } = await supabase.from('profiles').select('name, role, auth_provider').eq('id', user.id).single();
    const name     = profile?.name || user.email;
    const role     = profile?.role || 'user';
    const provider = profile?.auth_provider || 'email';
    const providerBadge = provider !== 'email'
        ? `<span class="provider-tag provider-tag--${provider}">${provider}</span>` : '';
    badge.innerHTML = `<span class="status-pill">${escHtml(name)} — ${escHtml(role)}</span>${providerBadge}`;
}

// ══════════════════════════════════════════════════════════════════
//  PROVIDER CHECK
// ══════════════════════════════════════════════════════════════════

async function checkEmailProvider(email) {
    try {
        const { data, error } = await supabase.rpc('check_email_provider', {
            p_email: email.toLowerCase().trim()
        });
        if (error) {
            console.warn('check_email_provider RPC error:', error.message);
            return null;
        }
        return data?.provider ?? null;
    } catch (e) {
        console.warn('check_email_provider threw:', e);
        return null;
    }
}

function providerConflictMessage(existingProvider, attempted) {
    const existing = PROVIDER_LABEL[existingProvider] || existingProvider;
    if (existingProvider === 'email') {
        return `This email is already registered with a password. Please use the "Sign in" form and enter your password.`;
    }
    return `This email is already linked to ${existing}. Please use the "Continue with ${existing}" button ${attempted === 'register' ? 'to sign up' : 'to sign in'}.`;
}

// ══════════════════════════════════════════════════════════════════
//  AUTH – REGISTER
// ══════════════════════════════════════════════════════════════════

async function handleRegister(form) {
    const name     = form.querySelector('#registerName').value.trim();
    const email    = form.querySelector('#registerEmail').value.trim();
    const password = form.querySelector('#registerPassword').value;

    if (!name)               return setStatus(form, 'Please enter your name.', false);
    if (!email)              return setStatus(form, 'Please enter your email.', false);
    if (password.length < 6) return setStatus(form, 'Password must be at least 6 characters.', false);

    // CAPTCHA: Supabase requires the Turnstile token when captcha is enabled in project settings.
    // window._turnstileRegisterToken is set by onRegisterTurnstileSuccess() in auth.html.
    const captchaToken = window._turnstileRegisterToken || undefined;

    setStatus(form, 'Checking email…');
    const existingProvider = await checkEmailProvider(email);

    if (existingProvider !== null) {
        return setStatus(form, providerConflictMessage(existingProvider, 'register'), false);
    }

    setStatus(form, 'Creating account…');
    const { data: authData, error: authErr } = await supabase.auth.signUp({
        email,
        password,
        options: { captchaToken },   // ← NEW: Turnstile token
    });

    if (authErr) {
        // Reset Turnstile widget so user can get a fresh token
        if (window.turnstile) window.turnstile.reset();
        window._turnstileRegisterToken = null;

        if (authErr.message?.toLowerCase().includes('already registered')) {
            return setStatus(form, 'This email is already registered. Please use the Sign In form.', false);
        }
        return setStatus(form, authErr.message, false);
    }

    const userId = authData.user?.id;
    if (!userId) return setStatus(form, 'Signup failed – please try again.', false);

    const { error: nameErr } = await supabase
        .from('profiles')
        .update({ name })
        .eq('id', userId);
    if (nameErr) console.warn('Profile name patch warning:', nameErr.message);

    if (authData.session) {
        setStatus(form, 'Account created! Redirecting…');
        await updateBadge();
        setTimeout(() => { window.location.href = 'messages.html'; }, 800);
    } else {
        setStatus(form, 'Account created! Check your email to confirm your address before logging in.');
    }
    form.reset();
}

// ══════════════════════════════════════════════════════════════════
//  AUTH – LOGIN
// ══════════════════════════════════════════════════════════════════

async function handleLogin(form) {
    const email    = form.querySelector('#loginEmail').value.trim();
    const password = form.querySelector('#loginPassword').value;
    if (!email || !password) return setStatus(form, 'Please enter your email and password.', false);

    // CAPTCHA
    const captchaToken = window._turnstileLoginToken || undefined;

    setStatus(form, 'Signing in…');
    const { error } = await supabase.auth.signInWithPassword({
        email,
        password,
        options: { captchaToken },   // ← NEW: Turnstile token
    });

    if (error) {
        if (window.turnstile) window.turnstile.reset();
        window._turnstileLoginToken = null;

        if (error.message?.toLowerCase().includes('invalid login credentials')) {
            const existingProvider = await checkEmailProvider(email);
            if (existingProvider && existingProvider !== 'email') {
                const label = PROVIDER_LABEL[existingProvider] || existingProvider;
                return setStatus(form,
                    `This email is linked to ${label}. Please use the "Continue with ${label}" button to sign in.`,
                    false);
            }
        }
        return setStatus(form, error.message, false);
    }

    setStatus(form, 'Logged in! Redirecting…');
    await updateBadge();
    setTimeout(() => { window.location.href = 'messages.html'; }, 800);
}

// ══════════════════════════════════════════════════════════════════
//  AUTH – LOGOUT
// ══════════════════════════════════════════════════════════════════

async function handleLogout() {
    await supabase.auth.signOut();
    window.location.href = 'auth.html';
}

// ══════════════════════════════════════════════════════════════════
//  OAUTH
// ══════════════════════════════════════════════════════════════════

async function signInWithProvider(provider, btn) {
    if (btn) {
        btn.dataset.loading = '1';
        btn.setAttribute('aria-busy', 'true');
        const originalHTML = btn.innerHTML;
        btn.dataset.originalHtml = originalHTML;
        btn.innerHTML = `${ICONS.spinner} Connecting…`;
    }

    const { error } = await supabase.auth.signInWithOAuth({
        provider,
        options: {
            redirectTo: window.location.origin + '/auth.html',
        },
    });

    if (error) {
        if (btn) {
            delete btn.dataset.loading;
            btn.removeAttribute('aria-busy');
            btn.innerHTML = btn.dataset.originalHtml || btn.innerHTML;
        }
        const card   = btn?.closest('.auth-card');
        const status = card?.querySelector('.form-status');
        if (status) {
            status.textContent = error.message;
            status.style.color = '#c0392b';
        }
        showToast(error.message, false);
    }
}

// ── OAuth callback ─────────────────────────────────────────────────

async function handleOAuthCallback() {
    // FIX: was `await new Promise(r => setTimeout(r, 100))` without
    // actually awaiting in the original — added explicit await.
    await new Promise(r => setTimeout(r, 100));

    const { data: { user }, error } = await supabase.auth.getUser();
    if (error || !user) return;

    const { data: profile } = await supabase
        .from('profiles')
        .select('name, role')
        .eq('id', user.id)
        .single();

    if (profile && (!profile.name || profile.name === profile.email?.split('@')[0])) {
        const meta       = user.user_metadata || {};
        const betterName = meta.full_name || meta.name || meta.preferred_username || meta.user_name;
        if (betterName && betterName !== profile.name) {
            await supabase.from('profiles').update({ name: betterName }).eq('id', user.id);
        }
    }

    await updateBadge();
    await applyDashboardVisibility();
    window.history.replaceState({}, document.title, window.location.pathname);
    setTimeout(() => { window.location.href = 'messages.html'; }, 600);
}

function initOAuth() {
    document.getElementById('registerGoogleBtn')
        ?.addEventListener('click', e => signInWithProvider('google', e.currentTarget));
    document.getElementById('registerGithubBtn')
        ?.addEventListener('click', e => signInWithProvider('github', e.currentTarget));
    document.getElementById('loginGoogleBtn')
        ?.addEventListener('click', e => signInWithProvider('google', e.currentTarget));
    document.getElementById('loginGithubBtn')
        ?.addEventListener('click', e => signInWithProvider('github', e.currentTarget));

    // FIX: also check hash for PKCE code (some Supabase versions use
    // #code= in the hash, not ?code= in the query string).
    const loc = window.location;
    const isOAuthReturn = loc.hash.includes('access_token') ||
                        loc.search.includes('code=') ||
                        loc.hash.includes('code=');
    if (isOAuthReturn) handleOAuthCallback();
}

// ══════════════════════════════════════════════════════════════════
//  CONTACT FORM
// ══════════════════════════════════════════════════════════════════

async function handleContact(form) {
    const name    = form.querySelector('#name').value.trim();
    const email   = form.querySelector('#contactEmail').value.trim();
    const subject = form.querySelector('#subject').value.trim();
    const message = form.querySelector('#message').value.trim();
    if (!name || !email || !subject || !message)
        return setStatus(form, 'Please fill in all fields.', false);
    setStatus(form, 'Sending…');
    const { error } = await supabase.rpc('rpc_insert_message', {
        p_name: name, p_email: email, p_subject: subject, p_message: message
    });
    if (error) return setStatus(form, 'Failed to send. Please try again.', false);
    setStatus(form, 'Message sent! We will reply soon.');
    form.reset();
}

// ══════════════════════════════════════════════════════════════════
//  NEWSLETTER FORM
//  FIX: table was 'newsletter' — corrected to 'newsletters' to match DB.
// ══════════════════════════════════════════════════════════════════

async function handleNewsletter(form) {
    const emailInput = form.querySelector('#emailField');
    const email = emailInput?.value.trim();
    if (!email) return;

    let statusEl = form.querySelector('.form-status');
    if (!statusEl) {
        statusEl = document.createElement('p');
        statusEl.className = 'form-status';
        form.appendChild(statusEl);
    }
    statusEl.style.color = 'var(--orange)';
    statusEl.textContent = 'Subscribing…';

    // FIX: 'newsletter' → 'newsletters' (previous fix), now uses rate-limited RPC
    const { error } = await supabase.rpc('rpc_insert_newsletter', { p_email: email });
    if (error?.code === '23505') {
        statusEl.textContent = 'You are already subscribed!';
    } else if (error) {
        statusEl.textContent = 'Something went wrong, try again.';
        statusEl.style.color = '#c0392b';
    } else {
        statusEl.textContent = 'Subscribed! Thank you.';
        form.reset();
    }
}

// ══════════════════════════════════════════════════════════════════
//  NEWS PAGE – STATE
// ══════════════════════════════════════════════════════════════════

let currentUser    = null;
let currentProfile = null;
const pendingUploads = [];
const _channels = [];

// ── Emoji reaction palette ────────────────────────────────────────
const EMOJI_SET = ['👍','❤️','😂','😮','😢','🔥','👏','🎉','🤔','💪'];

function isUserBanned() {
    return currentProfile?.banned === true;
}

// ══════════════════════════════════════════════════════════════════
//  NEWS PAGE – INIT
// ══════════════════════════════════════════════════════════════════

async function initNewsPage() {
    const feed = document.getElementById('newsFeed');
    if (!feed) return;

    const { data: { user } } = await supabase.auth.getUser();
    currentUser = user;

    if (user) {
        const { data: profile } = await supabase.from('profiles').select('*').eq('id', user.id).single();
        currentProfile = profile;
    }

    // Show Admin nav link for admins and moderators on any page
    const adminNavItem = document.getElementById('adminNavItem');
    if (adminNavItem) {
        adminNavItem.style.display =
            (currentProfile?.role === 'admin' || currentProfile?.role === 'moderator') ? '' : 'none';
    }

    const toggleBtn = document.getElementById('toggleCreatorBtn');
    if (toggleBtn && (currentProfile?.role === 'admin' || currentProfile?.role === 'moderator')) {
        toggleBtn.style.display = 'inline-flex';
    }

    const panel = document.getElementById('postCreatorPanel');
    toggleBtn?.addEventListener('click', () => {
        const open = panel.style.display === 'block';
        panel.style.display = open ? 'none' : 'block';
        toggleBtn.setAttribute('aria-expanded', String(!open));
        if (!open) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });

    document.querySelectorAll('.creator-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const key = tab.dataset.tab;
            document.querySelectorAll('.creator-tab').forEach(t => t.classList.toggle('active', t === tab));
            document.querySelectorAll('.creator-section').forEach(s =>
                s.classList.toggle('active', s.dataset.section === key));
        });
    });

    document.getElementById('addAttachmentRowBtn')?.addEventListener('click', addAttachmentRow);
    document.getElementById('attachmentRows')?.addEventListener('click', e => {
        if (e.target.closest('.row-remove')) e.target.closest('.attachment-row').remove();
    });

    document.getElementById('publishBtn')?.addEventListener('click', handlePublishPost);
    document.getElementById('cancelEditBtn')?.addEventListener('click', cancelEdit);

    initFileUpload();
    await loadPosts();
    subscribeRealtime();
}

// ══════════════════════════════════════════════════════════════════
//  REALTIME
// ══════════════════════════════════════════════════════════════════

function subscribeRealtime() {
    const commentsChannel = supabase
        .channel('public:post_comments')
        .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'post_comments' },
            debounce(payload => handleRealtimeCommentInsert(payload.new), 150))
        .on('postgres_changes', { event: 'DELETE', schema: 'public', table: 'post_comments' },
            payload => handleRealtimeCommentDelete(payload.old))
        .subscribe();

    const likesChannel = supabase
        .channel('public:post_likes')
        .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'post_likes' },
            payload => handleRealtimeLikeChange(payload.new.post_id, +1))
        .on('postgres_changes', { event: 'DELETE', schema: 'public', table: 'post_likes' },
            payload => handleRealtimeLikeChange(payload.old.post_id, -1))
        .subscribe();

    const reactionsChannel = supabase
        .channel('public:post_reactions')
        .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'post_reactions' },
            payload => handleRealtimeReactionChange(payload.new, +1))
        .on('postgres_changes', { event: 'DELETE', schema: 'public', table: 'post_reactions' },
            payload => handleRealtimeReactionChange(payload.old, -1))
        .subscribe();

    // ── Posts auto-refresh ──────────────────────────────────────────
    // Watches the posts table so any INSERT (new post), UPDATE (edit/
    // publish toggle), or DELETE is reflected immediately for every
    // visitor without a manual page reload.
    const postsChannel = supabase
        .channel('public:posts')
        .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'posts' },
            debounce(payload => handleRealtimePostInsert(payload.new), 300))
        .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'posts' },
            debounce(payload => handleRealtimePostUpdate(payload.new), 300))
        .on('postgres_changes', { event: 'DELETE', schema: 'public', table: 'posts' },
            payload => handleRealtimePostDelete(payload.old))
        .subscribe();

    _channels.push(commentsChannel, likesChannel, reactionsChannel, postsChannel);
}

// ── Realtime: new post inserted ────────────────────────────────────
// Skips if the card already exists (e.g. the author just published it
// via handlePublishPost which calls loadPosts() itself).
async function handleRealtimePostInsert(row) {
    const feed = document.getElementById('newsFeed');
    if (!feed) return;

    // Don't show drafts to non-privileged users
    const isPrivileged = currentProfile?.role === 'admin' || currentProfile?.role === 'moderator';
    if (!row.published && !isPrivileged) return;

    // Already rendered (e.g. the author sees it via loadPosts after publish)
    if (document.querySelector(`article.post-card[data-post-id="${row.id}"]`)) return;

    // Remove "No posts yet." placeholder if present
    const placeholder = feed.querySelector('.feed-state');
    if (placeholder) placeholder.remove();

    // Fetch full post data (files, comments, likes, author)
    const { data: post } = await supabase
        .from('posts')
        .select(`id, author_id, title, description, image_url, video_url,
                    link_url, link_label, published, created_at, updated_at,
                    post_files(*), post_comments(id, content, created_at, author_id, profiles(name)),
                    post_likes(user_id)`)
        .eq('id', row.id)
        .single();
    if (!post) return;

    const { data: author } = await supabase.from('profiles').select('id, name, role').eq('id', post.author_id).single();
    const likes    = post.post_likes    || [];
    const comments = post.post_comments || [];
    const files    = post.post_files    || [];
    const myLike   = currentUser ? likes.some(l => l.user_id === currentUser.id) : false;
    const { reactions, myReactions } = await loadReactionsForPost(post.id);

    const card = document.createElement('article');
    card.className = 'post-card post-card--new';
    card.dataset.postId = post.id;
    card.innerHTML = buildPostCardHTML({ post, author: author || {}, likes, comments, files, myLike, isPrivileged, reactions, myReactions });

    // Newest post goes to the top (matches created_at DESC order)
    feed.insertBefore(card, feed.firstChild);

    showToast('New post published!');
    requestAnimationFrame(() => card.classList.add('post-card--highlight'));
    setTimeout(() => card.classList.remove('post-card--new', 'post-card--highlight'), 1800);
}

// ── Realtime: post updated ─────────────────────────────────────────
// Re-fetches and replaces the card so edits (title, body, image, etc.)
// appear instantly. Preserves the open/closed state of the comment section.
async function handleRealtimePostUpdate(row) {
    const existingCard = document.querySelector(`article.post-card[data-post-id="${row.id}"]`);

    // If the post was just unpublished and user is not privileged, remove it
    const isPrivileged = currentProfile?.role === 'admin' || currentProfile?.role === 'moderator';
    if (!row.published && !isPrivileged) {
        existingCard?.remove();
        return;
    }

    // If post doesn't exist in DOM yet (e.g. just published from draft), treat as insert
    if (!existingCard) { handleRealtimePostInsert(row); return; }

    // Remember if comments section was open
    const commentSection = existingCard.querySelector('.comments-section');
    const wasOpen = commentSection?.classList.contains('open') ?? false;

    // Fetch fresh data
    const { data: post } = await supabase
        .from('posts')
        .select(`id, author_id, title, description, image_url, video_url,
                    link_url, link_label, published, created_at, updated_at,
                    post_files(*), post_comments(id, content, created_at, author_id, profiles(name)),
                    post_likes(user_id)`)
        .eq('id', row.id)
        .single();
    if (!post) return;

    const { data: author } = await supabase.from('profiles').select('id, name, role').eq('id', post.author_id).single();
    const likes    = post.post_likes    || [];
    const comments = post.post_comments || [];
    const files    = post.post_files    || [];
    const myLike   = currentUser ? likes.some(l => l.user_id === currentUser.id) : false;
    const { reactions, myReactions } = await loadReactionsForPost(post.id);

    const newCard = document.createElement('article');
    newCard.className = 'post-card';
    newCard.dataset.postId = post.id;
    newCard.innerHTML = buildPostCardHTML({ post, author: author || {}, likes, comments, files, myLike, isPrivileged, reactions, myReactions });

    existingCard.replaceWith(newCard);

    // Restore comment section state
    if (wasOpen) {
        const newSection = newCard.querySelector('.comments-section');
        newSection?.classList.add('open');
        newCard.querySelector('.toggle-comments-btn')?.setAttribute('aria-expanded', 'true');
    }
}

// ── Realtime: post deleted ─────────────────────────────────────────
function handleRealtimePostDelete(row) {
    const card = document.querySelector(`article.post-card[data-post-id="${row.id}"]`);
    if (!card) return;
    card.style.transition = 'opacity .35s, transform .35s';
    card.style.opacity    = '0';
    card.style.transform  = 'translateY(-6px)';
    setTimeout(() => {
        card.remove();
        // Show "No posts yet." if feed is now empty
        const feed = document.getElementById('newsFeed');
        if (feed && !feed.querySelector('article.post-card')) {
            feed.innerHTML = `<div class="feed-state">No posts yet.</div>`;
        }
    }, 350);
}

async function handleRealtimeCommentInsert(row) {
    const alreadyExists = document.querySelector(`.comment-item[data-comment-id="${row.id}"]`);
    if (alreadyExists) return;

    const { data: author } = await supabase.from('profiles').select('name').eq('id', row.author_id).single();
    const authorName = author?.name || 'User';

    const section = document.getElementById(`comments-${row.post_id}`);
    if (!section) return;

    const placeholder = section.querySelector('p[data-placeholder]');
    placeholder?.remove();

    const canDelete = currentUser?.id === row.author_id || currentProfile?.role === 'admin';
    const el = document.createElement('div');
    el.className = 'comment-item comment-item--new';
    el.dataset.commentId = row.id;
    el.innerHTML = buildCommentHTML({ id: row.id, authorName, content: row.content, created_at: row.created_at, canDelete });

    const form = section.querySelector('.comment-form, .signin-note');
    section.insertBefore(el, form || null);
    updateCommentCount(row.post_id, +1);

    requestAnimationFrame(() => el.classList.add('comment-item--highlight'));
    setTimeout(() => el.classList.remove('comment-item--new', 'comment-item--highlight'), 1200);

    // FIX: use el directly instead of a querySelector that could match wrong element
    // if multiple comments arrive concurrently.
    el.querySelector('.comment-del-btn')?.addEventListener('click', async () => {
        if (!confirm('Delete this comment?')) return;
        await supabase.from('post_comments').delete().eq('id', row.id);
    });
}

function handleRealtimeCommentDelete(row) {
    const el = document.querySelector(`.comment-item[data-comment-id="${row.id}"]`);
    if (!el) return;
    el.classList.add('comment-item--removing');
    setTimeout(() => {
        el.remove();
        updateCommentCount(row.post_id, -1);
        const section = document.getElementById(`comments-${row.post_id}`);
        const hasComments = section?.querySelector('.comment-item');
        if (!hasComments) {
            const p = document.createElement('p');
            p.dataset.placeholder = '1';
            p.style.cssText = 'color:var(--text-muted);font-size:.875rem';
            p.textContent = 'No comments yet.';
            section?.insertBefore(p, section.querySelector('.comment-form, .signin-note'));
        }
    }, 300);
}

function handleRealtimeLikeChange(postId, delta) {
    const card = document.querySelector(`article.post-card[data-post-id="${postId}"]`);
    if (!card) return;
    const countEl = card.querySelector('.like-count');
    if (!countEl) return;
    countEl.textContent = Math.max(0, (parseInt(countEl.textContent) || 0) + delta);
}

// ── Realtime reaction change ──────────────────────────────────────
function handleRealtimeReactionChange(row, delta) {
    const card = document.querySelector(`article.post-card[data-post-id="${row.post_id}"]`);
    if (!card) return;
    const btn = card.querySelector(`.emoji-btn[data-emoji="${CSS.escape(row.emoji)}"]`);
    if (!btn) return;
    const countEl = btn.querySelector('.emoji-count');
    const newCount = Math.max(0, (parseInt(countEl?.textContent) || 0) + delta);
    if (countEl) countEl.textContent = newCount;
    btn.classList.toggle('emoji-btn--active', newCount > 0 && currentUser?.id === row.user_id);
    if (newCount === 0) countEl.textContent = '';
}

// ══════════════════════════════════════════════════════════════════
//  EMOJI REACTIONS
// ══════════════════════════════════════════════════════════════════

function buildReactionBarHTML(postId, reactions, myReactions) {
    // reactions = [{emoji, count}], myReactions = Set of emoji user has reacted with
    const pickerEmoji = EMOJI_SET.map(e => `
        <button class="emoji-picker-btn" data-emoji="${escHtml(e)}" data-post="${postId}" title="React with ${e}">${e}</button>
    `).join('');

    const pills = reactions.map(r => {
        const mine = myReactions.has(r.emoji);
        return `<button class="emoji-btn${mine ? ' emoji-btn--active' : ''}" data-emoji="${escHtml(r.emoji)}" data-post="${postId}" title="${escHtml(r.emoji)}">
            ${r.emoji}<span class="emoji-count">${r.count}</span>
        </button>`;
    }).join('');

    return `<div class="reaction-bar" data-post="${postId}">
        <div class="reaction-pills">${pills}</div>
        <div class="emoji-picker-wrap">
            <button class="emoji-add-btn" data-post="${postId}" title="Add reaction">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>
            </button>
            <div class="emoji-picker" style="display:none" data-post="${postId}">${pickerEmoji}</div>
        </div>
    </div>`;
}

async function loadReactionsForPost(postId) {
    const { data } = await supabase.from('post_reactions')
        .select('emoji, user_id')
        .eq('post_id', postId);
    if (!data) return { reactions: [], myReactions: new Set() };

    const counts = {};
    const myReactions = new Set();
    for (const r of data) {
        counts[r.emoji] = (counts[r.emoji] || 0) + 1;
        if (currentUser && r.user_id === currentUser.id) myReactions.add(r.emoji);
    }
    const reactions = Object.entries(counts).map(([emoji, count]) => ({ emoji, count }));
    return { reactions, myReactions };
}

async function handleEmojiReaction(postId, emoji) {
    if (!currentUser) { window.location.href = 'auth.html'; return; }
    if (isUserBanned()) { showToast('Your account has been suspended.', false); return; }

    const { data: existing } = await supabase.from('post_reactions')
        .select('id').eq('post_id', postId).eq('user_id', currentUser.id).eq('emoji', emoji).maybeSingle();

    if (existing) {
        await supabase.from('post_reactions').delete().eq('id', existing.id);
    } else {
        await supabase.from('post_reactions').insert({ post_id: postId, user_id: currentUser.id, emoji });
    }
    // Re-render reaction bar for this post
    const card = document.querySelector(`article.post-card[data-post-id="${postId}"]`);
    if (!card) return;
    const bar = card.querySelector('.reaction-bar');
    if (!bar) return;
    const { reactions, myReactions } = await loadReactionsForPost(postId);
    bar.outerHTML = buildReactionBarHTML(postId, reactions, myReactions);
    // Re-attach parent click delegation handles this automatically
}

// ══════════════════════════════════════════════════════════════════
//  COMMENT REPLIES
// ══════════════════════════════════════════════════════════════════

function buildReplyHTML({ id, authorName, content, created_at, canDelete }) {
    return `<div class="reply-item" data-reply-id="${id}">
        <div class="reply-header">
            <span class="reply-author">${escHtml(authorName)}</span>
            <time class="comment-time" datetime="${created_at}" title="${fmtDate(created_at)}">${fmtRelative(created_at)}</time>
            ${canDelete ? `<button class="reply-del-btn" data-id="${id}" title="Delete reply">${ICONS.close}</button>` : ''}
        </div>
        <p class="reply-text">${escHtml(content)}</p>
    </div>`;
}

async function loadRepliesForComment(commentId) {
    const { data: replies } = await supabase.from('comment_replies')
        .select('id, content, created_at, author_id, profiles(name)')
        .eq('comment_id', commentId)
        .order('created_at', { ascending: true });
    return replies || [];
}

function renderReplies(commentEl, replies) {
    let repliesWrap = commentEl.querySelector('.replies-wrap');
    if (!repliesWrap) {
        repliesWrap = document.createElement('div');
        repliesWrap.className = 'replies-wrap';
        commentEl.appendChild(repliesWrap);
    }
    if (!replies.length) {
        repliesWrap.innerHTML = '';
        return;
    }
    repliesWrap.innerHTML = replies.map(r => {
        const authorName = r.profiles?.name || 'User';
        const canDelete = currentUser?.id === r.author_id || currentProfile?.role === 'admin' || currentProfile?.role === 'moderator';
        return buildReplyHTML({ id: r.id, authorName, content: r.content, created_at: r.created_at, canDelete });
    }).join('');
    // Wire up delete buttons
    repliesWrap.querySelectorAll('.reply-del-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            if (!confirm('Delete this reply?')) return;
            await supabase.from('comment_replies').delete().eq('id', btn.dataset.id);
            btn.closest('.reply-item').remove();
        });
    });
}

async function toggleReplyForm(commentEl, commentId) {
    let form = commentEl.querySelector('.reply-form');
    if (form) { form.remove(); return; }

    if (!currentUser) { window.location.href = 'auth.html'; return; }

    // Load and render existing replies first
    const replies = await loadRepliesForComment(commentId);
    renderReplies(commentEl, replies);

    form = document.createElement('div');
    form.className = 'reply-form';
    form.innerHTML = `
        <div class="reply-input-row">
            <input class="reply-input" type="text" placeholder="Write a reply…" maxlength="500">
            <button class="send-reply-btn" type="button" data-comment="${commentId}">${ICONS.send}</button>
        </div>`;
    commentEl.appendChild(form);
    form.querySelector('.reply-input')?.focus();

    form.querySelector('.send-reply-btn').addEventListener('click', async () => {
        const input = form.querySelector('.reply-input');
        const content = input.value.trim();
        if (!content) { input.focus(); return; }
        if (isUserBanned()) { showToast('Your account has been suspended.', false); return; }
        const btn = form.querySelector('.send-reply-btn');
        btn.disabled = true;
        const { data: inserted, error } = await supabase.from('comment_replies')
            .insert({ comment_id: commentId, author_id: currentUser.id, content })
            .select('id, content, created_at, author_id').single();
        btn.disabled = false;
        if (error) { showToast('Failed to post reply.', false); return; }
        const authorName = currentProfile?.name || currentUser.email;
        const canDelete = true;
        let repliesWrap = commentEl.querySelector('.replies-wrap');
        if (!repliesWrap) {
            repliesWrap = document.createElement('div');
            repliesWrap.className = 'replies-wrap';
            commentEl.insertBefore(repliesWrap, form);
        }
        const replyEl = document.createElement('div');
        replyEl.innerHTML = buildReplyHTML({ id: inserted.id, authorName, content: inserted.content, created_at: inserted.created_at, canDelete });
        const replyItem = replyEl.firstElementChild;
        repliesWrap.appendChild(replyItem);
        replyItem.querySelector('.reply-del-btn')?.addEventListener('click', async () => {
            if (!confirm('Delete this reply?')) return;
            await supabase.from('comment_replies').delete().eq('id', inserted.id);
            replyItem.remove();
        });
        input.value = '';
    });

    // Allow Enter key
    form.querySelector('.reply-input').addEventListener('keydown', e => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            form.querySelector('.send-reply-btn').click();
        }
    });
}

function updateCommentCount(postId, delta) {
    const btn = document.querySelector(`.toggle-comments-btn[data-post="${postId}"]`);
    if (!btn) return;
    const span = btn.querySelector('.comment-count');
    if (!span) return;
    const n = Math.max(0, (parseInt(span.dataset.count) || 0) + delta);
    span.dataset.count = n;
    span.textContent = `${n} comment${n !== 1 ? 's' : ''}`;
}

// ══════════════════════════════════════════════════════════════════
//  COMMENT HTML BUILDER
// ══════════════════════════════════════════════════════════════════

function buildCommentHTML({ id, authorName, content, created_at, canDelete }) {
    return `
        <div class="comment-header">
            <span class="comment-author">${escHtml(authorName)}</span>
            <time class="comment-time" datetime="${created_at}" title="${fmtDate(created_at)}">${fmtRelative(created_at)}</time>
            ${canDelete ? `<button class="comment-del-btn" data-id="${id}" title="Delete comment">${ICONS.close}</button>` : ''}
        </div>
        <p class="comment-text">${escHtml(content)}</p>
        ${currentUser ? `<button class="reply-toggle-btn" data-comment="${id}" title="Reply">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/></svg>
            Reply
        </button>` : ''}`;
}

// ══════════════════════════════════════════════════════════════════
//  FILE UPLOAD
// ══════════════════════════════════════════════════════════════════

function initFileUpload() {
    const zone  = document.getElementById('fileDropZone');
    const input = document.getElementById('filePickerInput');
    if (!zone || !input) return;
    zone.addEventListener('click', () => input.click());
    input.addEventListener('change', () => addFilesToQueue([...input.files]));
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('dragover');
        addFilesToQueue([...e.dataTransfer.files]);
    });
}

function addFilesToQueue(files) {
    const queue = document.getElementById('uploadQueue');
    if (!queue) return;
    files.forEach(file => {
        const id = 'uf_' + Math.random().toString(36).slice(2);
        pendingUploads.push({ file, label: file.name, id });
        const item = document.createElement('div');
        item.className = 'upload-item';
        item.dataset.id = id;
        item.innerHTML = `
            ${ICONS.file}
            <span class="fname" title="${escHtml(file.name)}">${escHtml(file.name)}</span>
            <span class="fsize">${fmtBytes(file.size)}</span>
            <div class="fprogress"><div class="fprogress-bar" id="bar_${id}"></div></div>
            <button type="button" class="fremove" data-id="${id}" title="Remove">${ICONS.close}</button>
        `;
        queue.appendChild(item);
        item.querySelector('.fremove').addEventListener('click', () => removeFromQueue(id));
    });
}

function removeFromQueue(id) {
    const idx = pendingUploads.findIndex(u => u.id === id);
    if (idx !== -1) pendingUploads.splice(idx, 1);
    document.querySelector(`.upload-item[data-id="${id}"]`)?.remove();
}

async function uploadFileToStorage(uploadObj) {
    const { file, id } = uploadObj;
    const ext  = file.name.split('.').pop();
    const path = `posts/${Date.now()}_${id}.${ext}`;
    const bar  = document.getElementById(`bar_${id}`);
    if (bar) bar.style.width = '30%';
    const { data, error } = await supabase.storage
        .from('post-media').upload(path, file, { upsert: false });
    if (error) throw error;
    if (bar) bar.style.width = '100%';
    const { data: urlData } = supabase.storage.from('post-media').getPublicUrl(data.path);
    return urlData.publicUrl;
}

// ══════════════════════════════════════════════════════════════════
//  ATTACHMENT ROWS
// ══════════════════════════════════════════════════════════════════

function addAttachmentRow() {
    const rows = document.getElementById('attachmentRows');
    const row  = document.createElement('div');
    row.className = 'attachment-row';
    row.innerHTML = `
        <input type="text" placeholder="Label">
        <input type="url" placeholder="https://…">
        <select>
            <option value="file">File</option>
            <option value="link">Link</option>
        </select>
        <button type="button" class="row-remove" title="Remove">${ICONS.close}</button>
    `;
    rows.appendChild(row);
}

// ══════════════════════════════════════════════════════════════════
//  PUBLISH / EDIT POST
// ══════════════════════════════════════════════════════════════════

async function handlePublishPost() {
    const statusEl    = document.getElementById('creatorStatus');
    const progressTxt = document.getElementById('uploadProgressText');
    const publishBtn  = document.getElementById('publishBtn');

    const editId    = document.getElementById('editPostId').value;
    const title     = document.getElementById('postTitle').value.trim();
    const desc      = document.getElementById('postDesc').value.trim();
    const image     = document.getElementById('postImage').value.trim() || null;
    const video     = document.getElementById('postVideo').value.trim() || null;
    const link      = document.getElementById('postLink').value.trim() || null;
    const linkLbl   = document.getElementById('postLinkLabel').value.trim() || null;
    const published = document.getElementById('postPublished').value === 'true';

    if (!title || !desc) {
        statusEl.textContent = 'Title and description are required.';
        statusEl.style.color = '#c0392b';
        document.querySelector('.creator-tab[data-tab="content"]')?.click();
        return;
    }

    publishBtn.disabled = true;
    statusEl.textContent = 'Saving…';
    statusEl.style.color = 'var(--orange)';

    let postId = editId;
    try {
        if (editId) {
            const { error } = await supabase.from('posts').update({
                title, description: desc, image_url: image, video_url: video,
                link_url: link, link_label: linkLbl, published,
                updated_at: new Date().toISOString()
            }).eq('id', editId);
            if (error) throw error;
            await supabase.from('post_files').delete().eq('post_id', editId);
        } else {
            const { data, error } = await supabase.from('posts').insert({
                author_id: currentUser.id, title, description: desc,
                image_url: image, video_url: video, link_url: link,
                link_label: linkLbl, published
            }).select('id').single();
            if (error) throw error;
            postId = data.id;
        }

        const fileInserts = [];
        if (pendingUploads.length) {
            statusEl.textContent = `Uploading ${pendingUploads.length} file(s)…`;
            for (let i = 0; i < pendingUploads.length; i++) {
                const u = pendingUploads[i];
                progressTxt.textContent = `File ${i + 1} / ${pendingUploads.length}`;
                try {
                    const url = await uploadFileToStorage(u);
                    fileInserts.push({ post_id: postId, name: u.file.name, url, type: 'file' });
                } catch (e) { console.warn('Upload failed for', u.file.name, e.message); }
            }
            progressTxt.textContent = '';
        }

        document.querySelectorAll('#attachmentRows .attachment-row').forEach(row => {
            const inputs = row.querySelectorAll('input');
            const name   = inputs[0]?.value.trim();
            const url    = inputs[1]?.value.trim();
            const type   = row.querySelector('select')?.value || 'file';
            if (name && url) fileInserts.push({ post_id: postId, name, url, type });
        });

        if (fileInserts.length) await supabase.from('post_files').insert(fileInserts);

        statusEl.textContent = editId ? 'Post updated.' : 'Post published.';
        clearCreatorForm();
        await loadPosts();
    } catch (err) {
        statusEl.textContent = err.message;
        statusEl.style.color = '#c0392b';
    } finally {
        publishBtn.disabled = false;
    }
}

function clearCreatorForm() {
    document.getElementById('editPostId').value      = '';
    document.getElementById('postTitle').value       = '';
    document.getElementById('postDesc').value        = '';
    document.getElementById('postImage').value       = '';
    document.getElementById('postVideo').value       = '';
    document.getElementById('postLink').value        = '';
    document.getElementById('postLinkLabel').value   = '';
    document.getElementById('postPublished').value   = 'true';
    document.getElementById('creatorTitle').textContent = 'New Post';
    document.getElementById('cancelEditBtn').style.display = 'none';
    document.getElementById('uploadQueue').innerHTML = '';
    pendingUploads.length = 0;
    document.getElementById('attachmentRows').innerHTML = `
        <div class="attachment-row">
            <input type="text" placeholder="Label (e.g. Report)">
            <input type="url" placeholder="https://…">
            <select><option value="file">File</option><option value="link">Link</option></select>
            <button type="button" class="row-remove" title="Remove">${ICONS.close}</button>
        </div>`;
    document.querySelector('.creator-tab[data-tab="content"]')?.click();
}

function cancelEdit() {
    clearCreatorForm();
    document.getElementById('postCreatorPanel').style.display = 'none';
    document.getElementById('toggleCreatorBtn').setAttribute('aria-expanded', 'false');
}

// ══════════════════════════════════════════════════════════════════
//  LOAD & RENDER POSTS
//  FIX: was fetching author profiles in a loop (N+1).
//  Collapsed into a single .in() query outside the loop.
// ══════════════════════════════════════════════════════════════════

async function loadPosts() {
    const feed = document.getElementById('newsFeed');
    if (!feed) return;

    feed.innerHTML = `<div class="feed-state">${ICONS.spinner} Loading posts…</div>`;

    const isPrivileged = currentProfile?.role === 'admin' || currentProfile?.role === 'moderator';
    // Security upgrade: non-privileged users query the v_public_posts view
    // (SECURITY DEFINER — always returns only published=true server-side).
    // Privileged users query posts directly so they can see drafts.
    const table = isPrivileged ? 'posts' : 'v_public_posts';
    let query = supabase.from(table).select(`
        id, author_id, title, description, image_url, video_url,
        link_url, link_label, ${isPrivileged ? 'published, ' : ''}created_at, updated_at,
        post_files(*),
        post_comments(id, content, created_at, author_id, profiles(name)),
        post_likes(user_id)
    `).order('created_at', { ascending: false });

    const { data: posts, error } = await query;
    if (error) { feed.innerHTML = `<div class="feed-state" style="color:#c0392b">Failed to load posts.</div>`; return; }
    if (!posts?.length) { feed.innerHTML = `<div class="feed-state">No posts yet.</div>`; return; }

    // FIX: single batch fetch instead of N+1 loop
    const authorIds = [...new Set(posts.map(p => p.author_id))];
    const { data: authors } = await supabase.from('profiles').select('id, name, role').in('id', authorIds);
    const authorMap = Object.fromEntries((authors || []).map(a => [a.id, a]));

    feed.innerHTML = '';
    const frag = document.createDocumentFragment();
    for (const post of posts) {
        const author   = authorMap[post.author_id] || {};
        const likes    = post.post_likes    || [];
        const comments = post.post_comments || [];
        const files    = post.post_files    || [];
        const myLike   = currentUser ? likes.some(l => l.user_id === currentUser.id) : false;

        // Load emoji reactions for this post
        const { reactions, myReactions } = await loadReactionsForPost(post.id);

        const card = document.createElement('article');
        card.className = 'post-card';
        card.dataset.postId = post.id;
        card.innerHTML = buildPostCardHTML({ post, author, likes, comments, files, myLike, isPrivileged, reactions, myReactions });
        frag.appendChild(card);
    }
    feed.appendChild(frag);

    if (feed._listener) feed.removeEventListener('click', feed._listener);
    feed._listener = handlePostInteraction;
    feed.addEventListener('click', feed._listener);
}

// ══════════════════════════════════════════════════════════════════
//  BUILD POST CARD HTML
// ══════════════════════════════════════════════════════════════════

function buildPostCardHTML({ post, author, likes, comments, files, myLike, isPrivileged, reactions = [], myReactions = new Set() }) {
    let mediaHtml = '';
    if (post.image_url) {
        mediaHtml += `<img class="post-card-image" src="${escHtml(post.image_url)}" alt="${escHtml(post.title)}" loading="lazy">`;
    }
    if (post.video_url) {
        if (isYouTubeUrl(post.video_url)) {
            mediaHtml += `<iframe class="post-card-video" style="height:340px" src="${escHtml(youtubeEmbedUrl(post.video_url))}" allowfullscreen loading="lazy"></iframe>`;
        } else {
            mediaHtml += `<video class="post-card-video" controls preload="none"><source src="${escHtml(post.video_url)}"></video>`;
        }
    }

    const linkHtml = post.link_url
        ? `<a class="post-link-chip" href="${escHtml(post.link_url)}" target="_blank" rel="noopener noreferrer">${ICONS.link} ${escHtml(post.link_label || 'Read more')}</a>` : '';

    const filesHtml = files.length
        ? `<div class="post-files">${files.map(f => `
            <a class="post-file-chip" href="${escHtml(f.url)}" target="_blank" rel="noopener noreferrer" download>
                ${f.type === 'link' ? ICONS.link : ICONS.download}
                ${escHtml(f.name)}
            </a>`).join('')}</div>` : '';

    const draftBadge    = (!post.published && isPrivileged) ? `<span class="draft-pill">Draft</span>` : '';
    const adminControls = isPrivileged
        ? `<div class="post-admin-actions">
                <button class="admin-btn edit-post-btn"   data-id="${post.id}">${ICONS.edit} Edit</button>
                <button class="admin-btn danger delete-post-btn" data-id="${post.id}">${ICONS.trash} Delete</button>
            </div>` : '';

    const roleClass = author.role === 'admin' ? '' : (author.role === 'moderator' ? 'mod' : 'user');

    let commentsHtml = '';
    if (comments.length) {
        commentsHtml = comments.map(c => {
            const canDelete = currentUser?.id === c.author_id || currentProfile?.role === 'admin' || currentProfile?.role === 'moderator';
            return `<div class="comment-item" data-comment-id="${c.id}">
                ${buildCommentHTML({ id: c.id, authorName: c.profiles?.name || 'User', content: c.content, created_at: c.created_at, canDelete })}
            </div>`;
        }).join('');
    } else {
        commentsHtml = `<p data-placeholder="1" style="color:var(--text-muted);font-size:.875rem">No comments yet.</p>`;
    }

    const commentFormHtml = (() => {
        if (!currentUser) return `<p class="signin-note"><a href="auth.html">Sign in</a> to leave a comment.</p>`;
        if (isUserBanned()) return `<p class="signin-note" style="color:#e74c3c">Your account has been suspended.</p>`;
        return `<div class="comment-form">
            <input type="text" placeholder="Leave a comment…" class="comment-input" maxlength="1000" aria-label="Comment">
            <button type="button" class="send-comment-btn" data-post="${post.id}" aria-label="Post comment">${ICONS.send} Post</button>
        </div>`;
    })();

    const commentCount = comments.length;
    const reactionBarHtml = buildReactionBarHTML(post.id, reactions, myReactions);

    return `
        ${mediaHtml}
        <div class="post-card-body">
            <div class="post-meta">
                <span class="author-role ${roleClass}">${escHtml(author.role || 'staff')}</span>
                <span>${escHtml(author.name || 'Honec Team')}</span>
                <span class="meta-dot">·</span>
                <time datetime="${post.created_at}" title="${fmtDate(post.created_at)}">${fmtRelative(post.created_at)}</time>
                ${draftBadge}
                ${adminControls}
            </div>
            <h2>${escHtml(post.title)}</h2>
            <p>${escHtml(post.description)}</p>
            ${linkHtml}
            ${filesHtml}
            ${reactionBarHtml}
            <div class="post-actions">
                <button class="like-btn${myLike ? ' liked' : ''}" data-post="${post.id}" data-liked="${myLike}" aria-label="Like post" aria-pressed="${myLike}">
                    ${ICONS.heart}
                    <span class="like-count">${likes.length}</span>
                </button>
                <button class="toggle-comments-btn" data-post="${post.id}" aria-expanded="false">
                    ${ICONS.comment}
                    <span class="comment-count" data-count="${commentCount}">${commentCount} comment${commentCount !== 1 ? 's' : ''}</span>
                </button>
            </div>
        </div>
        <div class="comments-section" id="comments-${post.id}" aria-live="polite" aria-label="Comments">
            ${commentsHtml}
            ${commentFormHtml}
        </div>`;
}

// ══════════════════════════════════════════════════════════════════
//  POST INTERACTIONS
// ══════════════════════════════════════════════════════════════════

async function handlePostInteraction(e) {
    const likeBtn = e.target.closest('.like-btn');
    if (likeBtn) {
        if (!currentUser) { window.location.href = 'auth.html'; return; }
        if (isUserBanned()) { showToast('Your account has been suspended.', false); return; }
        if (likeBtn.dataset.pending === 'true') return;

        const postId  = likeBtn.dataset.post;
        const liked   = likeBtn.dataset.liked === 'true';
        const countEl = likeBtn.querySelector('.like-count');
        const heartSvg= likeBtn.querySelector('svg');

        likeBtn.dataset.pending = 'true';
        likeBtn.classList.toggle('liked', !liked);
        likeBtn.dataset.liked = String(!liked);
        likeBtn.setAttribute('aria-pressed', String(!liked));
        countEl.textContent = Math.max(0, parseInt(countEl.textContent) + (liked ? -1 : +1));
        heartSvg.style.fill = liked ? 'none' : 'var(--orange)';

        try {
            if (liked) {
                const { error } = await supabase.from('post_likes').delete().eq('post_id', postId).eq('user_id', currentUser.id);
                if (error) throw error;
            } else {
                const { error } = await supabase.from('post_likes').insert({ post_id: postId, user_id: currentUser.id });
                if (error) throw error;
            }
        } catch (err) {
            likeBtn.classList.toggle('liked', liked);
            likeBtn.dataset.liked = String(liked);
            likeBtn.setAttribute('aria-pressed', String(liked));
            countEl.textContent = Math.max(0, parseInt(countEl.textContent) + (liked ? +1 : -1));
            heartSvg.style.fill = liked ? 'var(--orange)' : 'none';
            showToast(err.message, false);
        } finally { delete likeBtn.dataset.pending; }
        return;
    }

    const toggleBtn = e.target.closest('.toggle-comments-btn');
    if (toggleBtn) {
        const postId  = toggleBtn.dataset.post;
        const section = document.getElementById(`comments-${postId}`);
        if (!section) return;
        const open = section.classList.toggle('open');
        toggleBtn.setAttribute('aria-expanded', String(open));
        if (open) {
            const input = section.querySelector('.comment-input');
            if (input) setTimeout(() => input.focus(), 320);
        }
        return;
    }

    const sendBtn = e.target.closest('.send-comment-btn');
    if (sendBtn) {
        if (!currentUser) { window.location.href = 'auth.html'; return; }
        if (isUserBanned()) { showToast('Your account has been suspended.', false); return; }

        const postId  = sendBtn.dataset.post;
        const input   = sendBtn.closest('.comment-form').querySelector('.comment-input');
        const content = input.value.trim();
        if (!content) { input.focus(); return; }
        if (content.length > 1000) { showToast('Comment too long (max 1000 characters).', false); return; }

        const tempId  = 'temp_' + Date.now();
        const section = document.getElementById(`comments-${postId}`);
        const placeholder = section?.querySelector('p[data-placeholder]');
        placeholder?.remove();

        const tempEl = document.createElement('div');
        tempEl.className = 'comment-item comment-item--new';
        tempEl.dataset.commentId = tempId;
        tempEl.innerHTML = buildCommentHTML({
            id: tempId, authorName: currentProfile?.name || currentUser.email,
            content, created_at: new Date().toISOString(), canDelete: true
        });
        const form = section.querySelector('.comment-form');
        section?.insertBefore(tempEl, form || null);
        input.value = '';
        sendBtn.disabled = true;
        updateCommentCount(postId, +1);

        const { data: inserted, error } = await supabase.from('post_comments').insert({
            post_id: postId, author_id: currentUser.id, content
        }).select('id').single();
        sendBtn.disabled = false;

        if (error) {
            tempEl.remove();
            updateCommentCount(postId, -1);
            if (!section?.querySelector('.comment-item')) {
                const p = document.createElement('p');
                p.dataset.placeholder = '1';
                p.style.cssText = 'color:var(--text-muted);font-size:.875rem';
                p.textContent = 'No comments yet.';
                section?.insertBefore(p, form || null);
            }
            showToast('Failed to post comment: ' + error.message, false);
        } else {
            tempEl.dataset.commentId = inserted.id;
            tempEl.querySelector('.comment-del-btn')?.setAttribute('data-id', inserted.id);
        }
        return;
    }

    const delCommentBtn = e.target.closest('.comment-del-btn');
    if (delCommentBtn) {
        if (!confirm('Delete this comment?')) return;
        const id = delCommentBtn.dataset.id;
        const { error } = await supabase.from('post_comments').delete().eq('id', id);
        if (error) showToast('Failed to delete comment.', false);
        return;
    }

    const editBtn = e.target.closest('.edit-post-btn');
    if (editBtn) { await openEditPost(editBtn.dataset.id); return; }

    const delPostBtn = e.target.closest('.delete-post-btn');
    if (delPostBtn) {
        if (!confirm('Permanently delete this post?')) return;
        const { error } = await supabase.from('posts').delete().eq('id', delPostBtn.dataset.id);
        if (error) { showToast('Failed to delete post.', false); return; }
        delPostBtn.closest('.post-card')?.remove();
        return;
    }

    // ── Emoji: open/close picker ───────────────────────────────────
    const emojiAddBtn = e.target.closest('.emoji-add-btn');
    if (emojiAddBtn) {
        const picker = emojiAddBtn.nextElementSibling;
        if (!picker) return;
        // Close all other pickers first
        document.querySelectorAll('.emoji-picker').forEach(p => { if (p !== picker) p.style.display = 'none'; });
        picker.style.display = picker.style.display === 'none' ? 'flex' : 'none';
        return;
    }

    // ── Emoji: pick from picker ────────────────────────────────────
    const emojiPickerBtn = e.target.closest('.emoji-picker-btn');
    if (emojiPickerBtn) {
        const postId = emojiPickerBtn.dataset.post;
        const emoji  = emojiPickerBtn.dataset.emoji;
        // Close picker
        emojiPickerBtn.closest('.emoji-picker').style.display = 'none';
        await handleEmojiReaction(postId, emoji);
        return;
    }

    // ── Emoji: click existing pill ─────────────────────────────────
    const emojiPillBtn = e.target.closest('.emoji-btn');
    if (emojiPillBtn) {
        const postId = emojiPillBtn.dataset.post;
        const emoji  = emojiPillBtn.dataset.emoji;
        await handleEmojiReaction(postId, emoji);
        return;
    }

    // Close open emoji pickers when clicking elsewhere
    if (!e.target.closest('.emoji-picker-wrap')) {
        document.querySelectorAll('.emoji-picker').forEach(p => p.style.display = 'none');
    }

    // ── Comment reply toggle ────────────────────────────────────────
    const replyToggle = e.target.closest('.reply-toggle-btn');
    if (replyToggle) {
        const commentId = replyToggle.dataset.comment;
        const commentEl = replyToggle.closest('.comment-item');
        if (commentEl) await toggleReplyForm(commentEl, commentId);
        return;
    }
}

// ══════════════════════════════════════════════════════════════════
//  TOAST
// ══════════════════════════════════════════════════════════════════

function showToast(msg, ok = true) {
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.style.cssText = `position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;display:flex;flex-direction:column;gap:.5rem;pointer-events:none`;
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.style.cssText = `background:${ok ? 'var(--orange)' : '#c0392b'};color:#fff;padding:.65rem 1.2rem;border-radius:.6rem;font-size:.88rem;font-weight:600;box-shadow:0 2px 12px rgba(0,0,0,.18);animation:toastIn .2s ease;pointer-events:auto`;
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0'; toast.style.transition = 'opacity .3s';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// ══════════════════════════════════════════════════════════════════
//  OPEN EDIT POST
// ══════════════════════════════════════════════════════════════════

async function openEditPost(postId) {
    const { data: post } = await supabase.from('posts').select('*, post_files(*)').eq('id', postId).single();
    if (!post) return;

    document.getElementById('editPostId').value    = post.id;
    document.getElementById('postTitle').value     = post.title;
    document.getElementById('postDesc').value      = post.description;
    document.getElementById('postImage').value     = post.image_url || '';
    document.getElementById('postVideo').value     = post.video_url || '';
    document.getElementById('postLink').value      = post.link_url  || '';
    document.getElementById('postLinkLabel').value = post.link_label || '';
    document.getElementById('postPublished').value = post.published ? 'true' : 'false';

    const rows = document.getElementById('attachmentRows');
    rows.innerHTML = '';
    const urlFiles = (post.post_files || []).filter(f => f.url && !f.url.includes('supabase'));
    if (urlFiles.length) {
        urlFiles.forEach(f => {
            const row = document.createElement('div');
            row.className = 'attachment-row';
            row.innerHTML = `
                <input type="text" value="${escHtml(f.name)}" placeholder="Label">
                <input type="url" value="${escHtml(f.url)}" placeholder="https://…">
                <select>
                    <option value="file" ${f.type === 'file' ? 'selected' : ''}>File</option>
                    <option value="link" ${f.type === 'link' ? 'selected' : ''}>Link</option>
                </select>
                <button type="button" class="row-remove" title="Remove">${ICONS.close}</button>`;
            rows.appendChild(row);
        });
    } else { addAttachmentRow(); }

    document.getElementById('uploadQueue').innerHTML = '';
    pendingUploads.length = 0;
    document.getElementById('creatorTitle').textContent        = 'Edit Post';
    document.getElementById('cancelEditBtn').style.display     = '';
    document.getElementById('postCreatorPanel').style.display  = 'block';
    document.getElementById('toggleCreatorBtn').setAttribute('aria-expanded', 'true');
    document.getElementById('postCreatorPanel').scrollIntoView({ behavior: 'smooth' });
    document.querySelector('.creator-tab[data-tab="content"]')?.click();
}

// ══════════════════════════════════════════════════════════════════
//  DASHBOARD
// ══════════════════════════════════════════════════════════════════

async function loadDashboard() {
    const section = document.querySelector('.messages-section');
    if (!section) return;

    section.style.visibility = 'hidden';
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) { window.location.replace('auth.html'); return; }

    const { data: profile } = await supabase.from('profiles').select('*').eq('id', user.id).single();

    section.style.visibility = '';

    // ── USER DASHBOARD (regular users) ────────────────────────────────
    if (!profile || profile.role === 'user') {
        renderUserDashboard(section, user, profile);
        return;
    }

    // ── MODERATOR / ADMIN DASHBOARD ───────────────────────────────────
    const statusEl = section.querySelector('.messages-status');
    if (statusEl) statusEl.textContent = `${profile.role === 'admin' ? 'Admin' : 'Moderator'} access granted.`;

    const msgList = document.getElementById('messagesList');
    if (msgList) {
        const { data: messages } = await supabase.from('messages').select('*').order('created_at', { ascending: false });
        msgList.innerHTML = messages?.length
            ? messages.map(m => `
                <article class="message-card">
                    <div>
                        <div><strong>${escHtml(m.name)}</strong>
                            <p style="margin:0;font-size:.95rem">${escHtml(m.email)}</p>
                        </div>
                        <time>${fmtDate(m.created_at)}</time>
                    </div>
                    <p><strong>Subject:</strong> ${escHtml(m.subject)}</p>
                    <p>${escHtml(m.message)}</p>
                </article>`).join('')
            : '<p style="color:var(--text-muted)">No messages yet.</p>';
    }

    const userList = document.getElementById('usersList');
    if (userList) await renderUsersList(userList, profile.role, user.id);

    const logsList = document.getElementById('logsList');
    if (logsList) {
        // FIX: table name consistency — 'newsletters'
        const { data: subs } = await supabase.from('newsletters').select('email, created_at').order('created_at', { ascending: false });
        logsList.innerHTML = subs?.length
            ? subs.map(s => `
                <article class="log-card">
                    <strong>Newsletter</strong>
                    <span>${fmtDate(s.created_at)}</span>
                    <p>${escHtml(s.email)}</p>
                </article>`).join('')
            : '<p style="color:var(--text-muted)">No subscribers yet.</p>';
    }
}

// ══════════════════════════════════════════════════════════════════
//  USER DASHBOARD — rendered for role='user' on messages.html
// ══════════════════════════════════════════════════════════════════

function renderUserDashboard(section, user, profile) {
    const name     = profile?.name || user.email.split('@')[0];
    const email    = user.email || '';
    const provider = profile?.auth_provider || 'email';
    const joined   = profile?.created_at ? fmtDate(profile.created_at) : '—';
    const initial  = name.trim().charAt(0).toUpperCase() || '?';

    const providerBadgeHTML = provider !== 'email'
        ? `<span class="provider-tag provider-tag--${escHtml(provider)}" style="display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:999px;font-size:.75rem;font-weight:700;text-transform:capitalize;margin-left:8px">${escHtml(provider)}</span>` : '';

    // Replace entire section contents with a beautiful user profile card
    section.innerHTML = `
        <div class="user-dashboard-wrap">
            <div class="user-dashboard-card">
                <div class="ud-hero">
                    <div class="ud-avatar-ring">
                        <div class="ud-avatar">${initial}</div>
                    </div>
                    <div class="ud-hero-info">
                        <h1 class="ud-name">${escHtml(name)}${providerBadgeHTML}</h1>
                        <p class="ud-email">${escHtml(email)}</p>
                        <span class="ud-role-badge">Member</span>
                    </div>
                </div>

                <div class="ud-stats-row">
                    <div class="ud-stat">
                        <span class="ud-stat-icon">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                        </span>
                        <span class="ud-stat-label">Account type</span>
                        <span class="ud-stat-value">Community member</span>
                    </div>
                    <div class="ud-stat">
                        <span class="ud-stat-icon">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
                        </span>
                        <span class="ud-stat-label">Member since</span>
                        <span class="ud-stat-value">${joined}</span>
                    </div>
                    <div class="ud-stat">
                        <span class="ud-stat-icon">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        </span>
                        <span class="ud-stat-label">Auth provider</span>
                        <span class="ud-stat-value">${escHtml(provider === 'email' ? 'Email & Password' : provider.charAt(0).toUpperCase() + provider.slice(1))}</span>
                    </div>
                </div>

                <div class="ud-links-row">
                    <a class="ud-link-btn" href="news.html">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                        Browse News &amp; Comment
                    </a>
                    <a class="ud-link-btn" href="services.html">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                        Our Services
                    </a>
                    <a class="ud-link-btn" href="contacts.html">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                        Contact Us
                    </a>
                </div>

                <div class="ud-footer">
                    <button class="ud-logout-btn" id="logoutButton">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                        Sign out
                    </button>
                </div>
            </div>
        </div>`;

    // Inject user dashboard styles
    if (!document.getElementById('ud-styles')) {
        const s = document.createElement('style');
        s.id = 'ud-styles';
        s.textContent = `
            .user-dashboard-wrap { display:flex; justify-content:center; padding:4rem 1rem 6rem; }
            .user-dashboard-card {
                background:var(--card, #fff); border-radius:1.25rem; max-width:640px; width:100%;
                box-shadow:0 4px 40px rgba(0,0,0,.09); overflow:hidden;
            }
            .ud-hero {
                background:linear-gradient(135deg, var(--orange, #f16f20) 0%, #e85d0c 100%);
                padding:2.5rem 2rem 2rem; display:flex; align-items:center; gap:1.5rem; flex-wrap:wrap;
            }
            .ud-avatar-ring {
                width:80px; height:80px; border-radius:50%; border:3px solid rgba(255,255,255,.6);
                padding:3px; flex-shrink:0;
            }
            .ud-avatar {
                width:100%; height:100%; border-radius:50%; background:rgba(255,255,255,.25);
                display:flex; align-items:center; justify-content:center;
                font-size:2rem; font-weight:800; color:#fff;
            }
            .ud-hero-info { flex:1; min-width:180px; }
            .ud-name { color:#fff; font-size:1.4rem; font-weight:800; margin:0 0 .25rem; }
            .ud-email { color:rgba(255,255,255,.8); font-size:.9rem; margin:0 0 .6rem; }
            .ud-role-badge {
                display:inline-block; background:rgba(255,255,255,.2); color:#fff;
                border-radius:999px; padding:2px 10px; font-size:.75rem; font-weight:700;
                text-transform:uppercase; letter-spacing:.06em;
            }
            .ud-stats-row { display:grid; grid-template-columns:repeat(3,1fr); border-bottom:1px solid var(--border, #f0f0f0); }
            .ud-stat {
                display:flex; flex-direction:column; align-items:center; gap:.35rem;
                padding:1.5rem 1rem; border-right:1px solid var(--border, #f0f0f0);
                text-align:center;
            }
            .ud-stat:last-child { border-right:none; }
            .ud-stat-icon { color:var(--orange, #f16f20); }
            .ud-stat-label { font-size:.72rem; text-transform:uppercase; letter-spacing:.05em; color:var(--text-muted, #888); font-weight:600; }
            .ud-stat-value { font-size:.82rem; font-weight:700; color:var(--text, #222); }
            .ud-links-row { display:flex; gap:.75rem; padding:1.5rem 2rem; flex-wrap:wrap; }
            .ud-link-btn {
                display:inline-flex; align-items:center; gap:.45rem; padding:.6rem 1.1rem;
                border-radius:.5rem; background:var(--surface, #f8f8f8); color:var(--text, #222);
                font-size:.85rem; font-weight:600; text-decoration:none;
                border:1px solid var(--border, #e8e8e8); transition:background .15s, border-color .15s;
            }
            .ud-link-btn:hover { background:var(--orange-dim, rgba(241,111,32,.08)); border-color:var(--orange, #f16f20); color:var(--orange, #f16f20); }
            .ud-footer { padding:1.25rem 2rem 1.75rem; }
            .ud-logout-btn {
                display:inline-flex; align-items:center; gap:.5rem; padding:.65rem 1.25rem;
                border-radius:.5rem; background:transparent; border:1.5px solid var(--border, #e8e8e8);
                color:var(--text-muted, #888); font-size:.88rem; font-weight:600; cursor:pointer;
                transition:border-color .15s, color .15s, background .15s;
            }
            .ud-logout-btn:hover { border-color:#c0392b; color:#c0392b; background:rgba(192,57,43,.05); }
            @media(max-width:520px){
                .ud-stats-row { grid-template-columns:1fr 1fr; }
                .ud-stat:nth-child(2) { border-right:none; }
                .ud-stat:nth-child(3) { grid-column:1/-1; border-right:none; border-top:1px solid var(--border,#f0f0f0); }
                .ud-hero { padding:1.75rem 1.25rem 1.5rem; }
                .ud-links-row, .ud-footer { padding:1.25rem; }
            }
        `;
        document.head.appendChild(s);
    }

    // Wire up the logout button rendered inside
    document.getElementById('logoutButton')?.addEventListener('click', handleLogout);
}

// ══════════════════════════════════════════════════════════════════
//  USERS LIST
// ══════════════════════════════════════════════════════════════════

async function renderUsersList(container, myRole, myId) {
    const { data: users } = await supabase.from('profiles')
        .select('id, name, email, role, auth_provider, banned, created_at')
        .order('created_at', { ascending: false });

    if (!users?.length) {
        container.innerHTML = '<p style="color:var(--text-muted)">No users yet.</p>';
        return;
    }

    const isAdmin = myRole === 'admin';

    container.innerHTML = users.map(u => {
        const isMe = u.id === myId;
        const providerTag = u.auth_provider !== 'email'
            ? `<span class="provider-tag provider-tag--${u.auth_provider}" style="font-size:.75rem">${u.auth_provider}</span>` : '';

        const roleControl = (isAdmin && !isMe) ? `
            <select class="role-select" data-uid="${u.id}" style="margin-top:.4rem;border:1px solid #ddd;border-radius:.4rem;padding:.2rem .5rem;font-size:.82rem">
                <option value="user"      ${u.role === 'user'      ? 'selected' : ''}>user</option>
                <option value="moderator" ${u.role === 'moderator' ? 'selected' : ''}>moderator</option>
                <option value="admin"     ${u.role === 'admin'     ? 'selected' : ''}>admin</option>
            </select>` : '';

        const banControl = (isAdmin && !isMe) ? `
            <button class="${u.banned ? 'unban-btn' : 'ban-btn'}" data-uid="${u.id}" data-banned="${u.banned}"
                style="margin-top:.4rem;padding:.25rem .7rem;border-radius:.4rem;border:none;cursor:pointer;font-size:.82rem;background:${u.banned ? '#27ae60' : '#e74c3c'};color:#fff">
                ${u.banned ? 'Unban' : 'Ban'}
            </button>` : '';

        const deleteControl = (isAdmin && !isMe) ? `
            <button class="delete-user-btn" data-uid="${u.id}"
                style="margin-top:.4rem;padding:.25rem .7rem;border-radius:.4rem;border:none;cursor:pointer;font-size:.82rem;background:#c0392b;color:#fff">
                Delete
            </button>` : '';

        return `
            <article class="message-card" data-user-card="${u.id}">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:.5rem">
                    <div>
                        <strong>${escHtml(u.name)}</strong> ${providerTag}
                        <p style="margin:0;font-size:.9rem;color:var(--text-muted)">${escHtml(u.email)}</p>
                    </div>
                    <span class="status-pill" style="${u.banned ? 'background:#e74c3c' : ''}">${u.banned ? 'banned' : escHtml(u.role)}</span>
                </div>
                <p style="font-size:.85rem;color:var(--text-light);margin:.3rem 0 0">Registered: ${fmtDate(u.created_at)}</p>
                <div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
                    ${roleControl}${banControl}${deleteControl}
                </div>
            </article>`;
    }).join('');

    if (!isAdmin) return;

    container.querySelectorAll('.role-select').forEach(sel => {
        sel.addEventListener('change', async () => {
            const { error } = await supabase.rpc('set_user_role', { target_id: sel.dataset.uid, new_role: sel.value });
            if (error) showToast('Error: ' + error.message, false);
            else sel.closest('article').querySelector('.status-pill').textContent = sel.value;
        });
    });

    container.querySelectorAll('.ban-btn, .unban-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const banned = btn.dataset.banned === 'true';
            if (!confirm(`${banned ? 'Unban' : 'Ban'} this user?`)) return;
            const { error } = await supabase.rpc('ban_user', { target_id: btn.dataset.uid, should_ban: !banned });
            if (error) { showToast('Error: ' + error.message, false); return; }
            await renderUsersList(container, myRole, myId);
        });
    });

    container.querySelectorAll('.delete-user-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            if (!confirm('Permanently delete this user? This cannot be undone.')) return;
            const { error } = await supabase.rpc('delete_user_profile', { target_id: btn.dataset.uid });
            if (error) { showToast('Error: ' + error.message, false); return; }
            btn.closest('article').remove();
        });
    });
}

// ══════════════════════════════════════════════════════════════════
//  MOBILE BURGER
// ══════════════════════════════════════════════════════════════════

function initBurger() {
    const burger = document.querySelector('.burger');
    const nav    = document.querySelector('.site-nav');
    if (!burger || !nav) return;
    burger.addEventListener('click', () => {
        const open = burger.classList.toggle('active');
        nav.classList.toggle('active', open);
        burger.setAttribute('aria-expanded', String(open));
    });
    nav.querySelectorAll('a').forEach(a => a.addEventListener('click', () => {
        burger.classList.remove('active');
        nav.classList.remove('active');
        burger.setAttribute('aria-expanded', 'false');
    }));
}

// ══════════════════════════════════════════════════════════════════
//  PARTICLES
// ══════════════════════════════════════════════════════════════════

(function () {
    const CFG = { count: 70, minR: 1.2, maxR: 3.6, speed: 0.45, linkDist: 100, linkAlpha: 0.16, color: '241,111,32' };
    let canvas = document.getElementById('particles-canvas');
    if (!canvas) {
        canvas = document.createElement('canvas');
        canvas.id = 'particles-canvas';
        document.body.insertBefore(canvas, document.body.firstChild);
    }
    Object.assign(canvas.style, { position:'fixed', top:'0', left:'0', width:'100%', height:'100%', zIndex:'-1', pointerEvents:'none' });
    const ctx = canvas.getContext('2d');
    let W, H;
    const resize = () => { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; };
    resize();
    window.addEventListener('resize', resize);
    const rand = (a, b) => a + Math.random() * (b - a);
    const rgba = a => `rgba(${CFG.color},${a.toFixed(3)})`;
    const make = y => ({ x: rand(0,W), y: y !== undefined ? y : rand(0,H), r: rand(CFG.minR,CFG.maxR), vx: rand(-0.3,0.3), vy: -rand(0.1,CFG.speed), alpha: rand(0.3,0.85), dAlpha: rand(0.002,0.005)*(Math.random()<0.5?1:-1), pulse: rand(0,Math.PI*2) });
    const pts = Array.from({ length: CFG.count }, () => make());
    (function tick() {
        ctx.clearRect(0, 0, W, H);
        for (let i = 0; i < pts.length; i++) {
            const p = pts[i];
            p.pulse += 0.016; p.alpha += p.dAlpha;
            if (p.alpha > 0.88 || p.alpha < 0.12) p.dAlpha *= -1;
            p.x += p.vx; p.y += p.vy;
            if (p.y < -8) { pts[i] = make(H + 4); continue; }
            if (p.x < -8) p.x = W + 4;
            if (p.x > W + 8) p.x = -4;
            const r = p.r + Math.sin(p.pulse) * 0.35;
            ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, Math.PI*2);
            ctx.fillStyle = rgba(p.alpha); ctx.fill();
            for (let j = i+1; j < pts.length; j++) {
                const q = pts[j], dx = p.x-q.x, dy = p.y-q.y, d = Math.sqrt(dx*dx+dy*dy);
                if (d < CFG.linkDist) { ctx.beginPath(); ctx.moveTo(p.x,p.y); ctx.lineTo(q.x,q.y); ctx.strokeStyle = rgba((1-d/CFG.linkDist)*CFG.linkAlpha); ctx.lineWidth=0.7; ctx.stroke(); }
            }
        }
        requestAnimationFrame(tick);
    })();
})();

// ══════════════════════════════════════════════════════════════════
//  INIT
// ══════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    const style = document.createElement('style');
    style.textContent = `
    /*
    const forgotForm = document.getElementById('forgotForm');
    if (forgotForm) {
        forgotForm.addEventListener('submit', e => { e.preventDefault(); handleForgotPassword(forgotForm); });
    }

    // Toggle between login form and forgot-password form
    document.getElementById('forgotPasswordLink')?.addEventListener('click', e => {
        e.preventDefault();
        document.getElementById('loginForm').style.display  = 'none';
        document.getElementById('forgotForm').style.display = '';
        document.getElementById('forgotEmail').focus();
    });

    document.getElementById('backToLoginLink')?.addEventListener('click', e => {
        e.preventDefault();
        document.getElementById('forgotForm').style.display = 'none';
        document.getElementById('loginForm').style.display  = '';
    });

    // Handle password reset redirect (?reset=1 appended by Supabase after clicking email link)
    // Supabase puts the recovery token in the URL hash; getSession() picks it up automatically.
    if (window.location.search.includes('reset=1') || window.location.hash.includes('type=recovery')) {
        const { data: { session } } = await supabase.auth.getSession();
        if (session) {
            // User clicked the reset link — show a password-change prompt
            // Simple approach: redirect to messages.html where they can update their profile,
            // or show an inline new-password form here.
            const newPw = prompt('Enter your new password (minimum 6 characters):');
            if (newPw && newPw.length >= 6) {
                const { error } = await supabase.auth.updateUser({ password: newPw });
                if (error) alert('Error: ' + error.message);
                else {
                    alert('Password updated successfully! You are now signed in.');
                    window.location.href = 'messages.html';
                }
            }
        }
    }
*/

        @keyframes toastIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:none; } }
        @keyframes spin { to { transform: rotate(360deg); } }
        .spin { animation: spin .8s linear infinite; }
        .comment-item--new { animation: commentIn .25s ease; }
        @keyframes commentIn { from { opacity:0; transform:translateY(-6px); } to { opacity:1; transform:none; } }
        .comment-item--highlight { background: var(--orange-dim, rgba(241,111,32,.08)); border-radius: .4rem; transition: background .8s; }
        .comment-item--removing { opacity:0; transform:translateX(8px); transition: opacity .3s, transform .3s; }
        .post-card--new { animation: postCardIn .3s ease; }
        @keyframes postCardIn { from { opacity:0; transform:translateY(-10px); } to { opacity:1; transform:none; } }
        .post-card--highlight { outline: 2px solid var(--orange, #f16f20); outline-offset: 2px; border-radius: .5rem; transition: outline .9s; }
        .provider-tag { display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;font-size:.75rem;font-weight:700;text-transform:capitalize;margin-left:6px; }
        .provider-tag--google { background:#e8f0fe; color:#1a73e8; }
        .provider-tag--github { background:#f0f0f0; color:#24292e; }

        /* ── Reply button ─────────────────────────────────────── */
        .reply-toggle-btn {
            display:inline-flex; align-items:center; gap:.3rem;
            background:none; border:none; padding:.2rem .5rem .2rem 0;
            font-size:.78rem; font-weight:600; color:var(--text-muted,#888);
            cursor:pointer; margin-top:.3rem; border-radius:.3rem;
            transition:color .15s;
        }
        .reply-toggle-btn:hover { color:var(--orange,#f16f20); }

        /* ── Reply form ───────────────────────────────────────── */
        .reply-form { margin:.6rem 0 .4rem 1.4rem; }
        .reply-input-row { display:flex; gap:.4rem; }
        .reply-input {
            flex:1; padding:.45rem .75rem; border-radius:.5rem;
            border:1.5px solid var(--border,#e8e8e8); font-size:.84rem;
            outline:none; background:var(--surface,#f8f8f8);
            transition:border-color .15s;
        }
        .reply-input:focus { border-color:var(--orange,#f16f20); background:#fff; }
        .send-reply-btn {
            padding:.45rem .75rem; background:var(--orange,#f16f20); color:#fff;
            border:none; border-radius:.5rem; cursor:pointer; display:flex;
            align-items:center; justify-content:center;
            transition:opacity .15s;
        }
        .send-reply-btn:hover { opacity:.85; }

        /* ── Replies wrap ─────────────────────────────────────── */
        .replies-wrap { margin:.6rem 0 0 1.4rem; display:flex; flex-direction:column; gap:.5rem; }
        .reply-item {
            background:var(--surface,#f8f8f8); border-left:2.5px solid var(--orange,#f16f20);
            border-radius:0 .5rem .5rem 0; padding:.55rem .75rem; font-size:.84rem;
        }
        .reply-header { display:flex; align-items:center; gap:.5rem; flex-wrap:wrap; }
        .reply-author { font-weight:700; font-size:.82rem; }
        .reply-del-btn {
            margin-left:auto; background:none; border:none; cursor:pointer;
            color:var(--text-muted,#aaa); padding:.1rem .3rem; border-radius:.3rem;
            opacity:.6; transition:opacity .15s, color .15s;
        }
        .reply-del-btn:hover { opacity:1; color:#c0392b; }
        .reply-text { margin:.3rem 0 0; line-height:1.45; }

        /* ── Emoji reaction bar ───────────────────────────────── */
        .reaction-bar {
            display:flex; align-items:center; gap:.5rem; flex-wrap:wrap;
            padding:.5rem 0 .2rem; margin-bottom:.4rem;
        }
        .reaction-pills { display:flex; flex-wrap:wrap; gap:.35rem; }
        .emoji-btn {
            display:inline-flex; align-items:center; gap:.25rem;
            padding:.28rem .6rem; border-radius:999px; border:1.5px solid var(--border,#e8e8e8);
            background:var(--surface,#f8f8f8); cursor:pointer; font-size:.88rem;
            transition:border-color .15s, background .15s, transform .1s;
            line-height:1;
        }
        .emoji-btn:hover { border-color:var(--orange,#f16f20); background:var(--orange-dim,rgba(241,111,32,.07)); transform:scale(1.08); }
        .emoji-btn--active { border-color:var(--orange,#f16f20); background:var(--orange-dim,rgba(241,111,32,.12)); }
        .emoji-count { font-size:.72rem; font-weight:700; color:var(--text-muted,#888); }
        .emoji-btn--active .emoji-count { color:var(--orange,#f16f20); }

        /* ── Emoji picker wrap & picker ───────────────────────── */
        .emoji-picker-wrap { position:relative; display:inline-flex; }
        .emoji-add-btn {
            display:inline-flex; align-items:center; justify-content:center;
            width:30px; height:30px; border-radius:50%; border:1.5px dashed var(--border,#ddd);
            background:none; cursor:pointer; color:var(--text-muted,#aaa);
            transition:border-color .15s, color .15s;
        }
        .emoji-add-btn:hover { border-color:var(--orange,#f16f20); color:var(--orange,#f16f20); }
        .emoji-picker {
            position:absolute; bottom:calc(100% + 8px); left:0;
            background:#fff; border:1px solid var(--border,#e8e8e8); border-radius:.75rem;
            padding:.6rem; box-shadow:0 8px 32px rgba(0,0,0,.12);
            display:flex; flex-wrap:wrap; gap:.3rem; width:220px; z-index:200;
            animation:toastIn .15s ease;
        }
        .emoji-picker-btn {
            font-size:1.25rem; padding:.25rem; border:none; background:none; cursor:pointer;
            border-radius:.4rem; transition:background .12s, transform .1s;
            line-height:1;
        }
        .emoji-picker-btn:hover { background:var(--surface,#f0f0f0); transform:scale(1.2); }
    `;
    document.head.appendChild(style);

    initBurger();
    updateBadge();
    applyDashboardVisibility();
    initOAuth();

    const regForm = document.getElementById('registerForm');
    if (regForm) regForm.addEventListener('submit', e => { e.preventDefault(); handleRegister(regForm); });

    const loginForm = document.getElementById('loginForm');
    if (loginForm) loginForm.addEventListener('submit', e => { e.preventDefault(); handleLogin(loginForm); });

    const contactForm = document.getElementById('contactForm');
    if (contactForm) contactForm.addEventListener('submit', e => { e.preventDefault(); handleContact(contactForm); });

    const newsletterForm = document.getElementById('newsletterForm');
    if (newsletterForm) newsletterForm.addEventListener('submit', e => { e.preventDefault(); handleNewsletter(newsletterForm); });

    const logoutBtn = document.getElementById('logoutButton');
    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

    loadDashboard();
    initNewsPage();
}); // FIX: closing brace for DOMContentLoaded was missing in original


async function handleForgotPassword(form) {
    const email = form.querySelector('#forgotEmail').value.trim();
    if (!email) return setStatus(form, 'Please enter your email address.', false);

    setStatus(form, 'Sending reset link…');

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: window.location.origin + '/auth.html?reset=1',
    });

    if (error) {
        return setStatus(form, error.message, false);
    }

    // Generic success message — don't confirm whether the email exists (prevents enumeration)
    setStatus(form, 'If that email is registered, a reset link has been sent. Check your inbox.');
    form.reset();
}