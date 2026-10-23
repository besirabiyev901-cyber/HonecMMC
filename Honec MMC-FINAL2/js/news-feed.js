// ══════════════════════════════════════════════════════════
    //  news-feed.js  — Instagram-style post system
    // ══════════════════════════════════════════════════════════
    import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm';

    const supabase = createClient(window.SUPABASE_URL, window.SUPABASE_ANON, {
        realtime: { params: { eventsPerSecond: 10 } }
    });

    // ── State ──────────────────────────────────────────────────
    let currentUser = null;
    let currentRole = 'user';
    let allPosts    = [];
    let filterMode  = 'all';
    let searchQuery = '';
    let pendingFiles = [];

    const EMOJIS_REACT = ['❤️','🔥','👏','😮','😂','🙌','💯','🚀'];
    const EMOJIS_PICK  = ['😀','😂','🥲','😍','🤩','😎','🤔','😮','😢','😡','🔥','❤️','👍','👏','🙌','🚀','💯','✨','🎉','💪','👀','🫡','😴','🤯','🥳','💡','🛠️','📋','📦','🏗️','🌟','⚡'];

    // ── File name helpers ──────────────────────────────────────
    /**
     * Build a clean, human-readable storage path for an uploaded file.
     * Format:  posts/{postId}/{authorSlug}_{originalName}
     * e.g.     posts/abc123/karim-huseynov_app-release.apk
     * Falls back to  posts/{postId}/{originalName}  if no user is logged in.
     */
    function buildStoragePath(postId, file) {
        const rawName   = currentUser?.user_metadata?.full_name
                        || currentUser?.email?.split('@')[0]
                        || 'user';
        const authorSlug = rawName
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')   // spaces/special chars → hyphens
            .replace(/^-+|-+$/g, '');       // trim leading/trailing hyphens
        const safeFile = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
        return `posts/${postId}/${authorSlug}_${safeFile}`;
    }

    /**
     * Map a MIME type (or extension) to a short label used for display badges.
     */
    function fileKind(mime = '', name = '') {
        const m = mime.toLowerCase();
        const ext = (name.split('.').pop() || '').toLowerCase();
        if (m === 'application/vnd.android.package-archive' || ext === 'apk') return 'apk';
        if (m === 'application/x-msdownload' || ext === 'exe') return 'exe';
        if (m === 'application/pdf' || ext === 'pdf') return 'pdf';
        if (/zip|rar|7z|tar|gz/.test(m) || /zip|rar|7z|tar|gz/.test(ext)) return 'zip';
        if (/^image\//.test(m)) return 'img';
        if (/^video\//.test(m)) return 'video';
        if (/^audio\//.test(m)) return 'audio';
        if (/word|doc/.test(m) || /docx?/.test(ext)) return 'doc';
        if (/sheet|excel/.test(m) || /xlsx?/.test(ext)) return 'xls';
        if (/presentation|powerpoint/.test(m) || /pptx?/.test(ext)) return 'ppt';
        if (/text\/|json|xml|csv/.test(m)) return 'txt';
        return 'file';
    }

    const KIND_ICONS = {
        apk:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="5" y="2" width="14" height="20" rx="3"/><path d="M9 9h6M9 13h4"/><circle cx="15" cy="17" r="1" fill="currentColor" stroke="none"/></svg>`,
        exe:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M8 12h8M12 8l4 4-4 4"/></svg>`,
        pdf:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M9 13h6M9 17h4"/></svg>`,
        zip:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M12 11v6M10 13h4"/></svg>`,
        img:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`,
        video: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2"/></svg>`,
        audio: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>`,
        doc:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M8 13h8M8 17h5"/></svg>`,
        xls:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M8 12l8 5M16 12l-8 5"/></svg>`,
        ppt:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M8 12h4a2 2 0 0 0 0-4H8v8"/></svg>`,
        txt:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M8 13h8M8 17h8"/></svg>`,
        file:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>`,
        link:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
    };

    function kindIcon(kind) { return KIND_ICONS[kind] || KIND_ICONS.file; }

    // ── Helpers ────────────────────────────────────────────────
    function esc(str = '') {
        return String(str)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
    function relTime(iso) {
        const d = Date.now() - new Date(iso).getTime(), s = Math.floor(d/1000);
        if (s < 10)  return 'just now';
        if (s < 60)  return `${s}s`;
        const m = Math.floor(s/60);
        if (m < 60)  return `${m}m`;
        const h = Math.floor(m/60);
        if (h < 24)  return `${h}h`;
        return new Date(iso).toLocaleDateString('en-GB',{day:'2-digit',month:'short'});
    }
    function fmtBytes(b) {
        if (b < 1024) return b + ' B';
        if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
        return (b/1048576).toFixed(1) + ' MB';
    }
    function isYT(url) { return /youtube\.com|youtu\.be/.test(url); }
    function ytEmbed(url) {
        const m = url.match(/(?:v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
        return m ? `https://www.youtube.com/embed/${m[1]}` : url;
    }
    function avatarInitials(name = '') {
        return name.trim().split(/\s+/).slice(0,2).map(w=>w[0]||'').join('').toUpperCase() || '?';
    }

    function toast(msg, err = false) {
        const c = document.getElementById('toastContainer');
        const t = document.createElement('div');
        t.className = 'toast' + (err ? ' err' : '');
        t.textContent = msg;
        c.appendChild(t);
        setTimeout(() => t.remove(), 2900);
    }

    // ── Bookmarks (localStorage) ───────────────────────────────
    function getSavedPosts() {
        try { return JSON.parse(localStorage.getItem('honec_saved_posts') || '[]'); } catch { return []; }
    }
    function setSavedPosts(ids) {
        try { localStorage.setItem('honec_saved_posts', JSON.stringify(ids)); } catch {}
    }
    function toggleBookmark(postId, btn) {
        let saved = getSavedPosts();
        const isBookmarked = saved.includes(postId);
        if (isBookmarked) {
            saved = saved.filter(id => id !== postId);
            btn.classList.remove('bookmark-active');
            toast('Removed from saved');
        } else {
            saved.push(postId);
            btn.classList.add('bookmark-active');
            toast('Post saved! ✓');
        }
        setSavedPosts(saved);
        updateSavedBanner();
    }
    function updateSavedBanner() {
        const saved = getSavedPosts();
        const banner = document.getElementById('savedBanner');
        const text   = document.getElementById('savedBannerText');
        if (!banner) return;
        if (saved.length > 0) {
            banner.classList.add('visible');
            text.textContent = `${saved.length} saved post${saved.length>1?'s':''} — click to filter`;
        } else {
            banner.classList.remove('visible');
        }
    }

    // ── Deep-link to a post (?post=ID) ─────────────────────────
    function handleDeepLink() {
        const params = new URLSearchParams(window.location.search);
        const postId = params.get('post');
        if (!postId) return;
        setTimeout(() => {
            const card = document.querySelector(`.post-card[data-post-id="${postId}"]`);
            if (card) {
                card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                card.classList.add('highlighted');
                setTimeout(() => card.classList.remove('highlighted'), 2500);
            }
        }, 600);
    }

    // ── Auth ───────────────────────────────────────────────────
    async function initAuth() {
        const { data: { session } } = await supabase.auth.getSession();
        if (session) await setUser(session.user);
        supabase.auth.onAuthStateChange(async (_e, sess) => {
            if (sess) { await setUser(sess.user); }
            else { currentUser = null; currentRole = 'user'; refreshUI(); }
        });
    }
    async function setUser(user) {
        currentUser = user;
        const { data } = await supabase.from('profiles').select('role').eq('id', user.id).single();
        currentRole = data?.role || 'user';
        refreshUI();
    }
    function isAdmin() { return currentRole === 'admin' || currentRole === 'moderator'; }

    function refreshUI() {
        const fab = document.getElementById('openCreatorBtn');
        if (fab) fab.style.display = isAdmin() ? '' : 'none';
        const adminNavItem = document.getElementById('adminNavItem');
        if (adminNavItem) adminNavItem.style.display = isAdmin() ? '' : 'none';
        // re-render post menus
        document.querySelectorAll('.pc-menu-wrap').forEach(w => {
            const postId = w.closest('.post-card')?.dataset.postId;
            if (!postId) return;
            w.style.display = isAdmin() ? '' : 'none';
        });
        // re-render compose sections
        document.querySelectorAll('.cmt-compose-wrap').forEach(w => {
            const logged = !!currentUser;
            w.querySelectorAll('.cmt-compose').forEach(c => c.style.display = logged ? '' : 'none');
            w.querySelectorAll('.sign-note').forEach(s => s.style.display = logged ? 'none' : '');
        });
        renderStories();
    }

    // ── Stories bar ────────────────────────────────────────────
    function renderStories() {
        const bar = document.getElementById('storiesBar');
        if (!bar) return;

        // Build from recent posts — one "story" per recent post
        const recent = [...allPosts].sort((a,b)=> new Date(b.created_at)-new Date(a.created_at)).slice(0,8);

        let html = '';
        if (isAdmin()) {
            html += `<div class="story-item" id="addStoryBtn">
                <div class="story-ring seen story-add">
                    <div class="story-inner">+</div>
                </div>
                <span class="story-name">New post</span>
            </div>`;
        }
        recent.forEach(p => {
            const initials = avatarInitials(p.author_name || 'Honec');
            const thumb = p.image_url ? `<img src="${esc(p.image_url)}" alt="">` : initials;
            html += `<div class="story-item" data-post-id="${esc(p.id)}" title="${esc(p.title)}">
                <div class="story-ring">
                    <div class="story-inner">${thumb}</div>
                </div>
                <span class="story-name">${esc((p.title||'').slice(0,10))}</span>
            </div>`;
        });
        bar.innerHTML = html;

        bar.querySelectorAll('.story-item[data-post-id]').forEach(s => {
            s.addEventListener('click', () => {
                const card = document.querySelector(`.post-card[data-post-id="${s.dataset.postId}"]`);
                if (card) card.scrollIntoView({ behavior:'smooth', block:'center' });
            });
        });
        const addBtn = document.getElementById('addStoryBtn');
        if (addBtn) addBtn.addEventListener('click', openCreator);
    }

    // ── Load posts ─────────────────────────────────────────────
    async function loadPosts() {
        const feed = document.getElementById('newsFeed');
        feed.innerHTML = '<div class="feed-state">Loading…</div>';

        let query = isAdmin()
            ? supabase.from('posts').select('*, post_files(*), post_likes(user_id), post_reactions(emoji,user_id), post_comments(id)')
            : supabase.from('v_public_posts').select('*, post_files(*), post_likes(user_id), post_reactions(emoji,user_id), post_comments(id)');

        const { data, error } = await query.order('created_at', { ascending: false });
        if (error) { feed.innerHTML = `<div class="feed-state">Error loading posts.</div>`; return; }

        // Get author profiles
        const authorIds = [...new Set((data||[]).map(p=>p.author_id).filter(Boolean))];
        let profiles = {};
        if (authorIds.length) {
            const { data: pd } = await supabase.from('profiles').select('id,name').in('id', authorIds);
            (pd||[]).forEach(p => { profiles[p.id] = p.name; });
        }

        allPosts = (data||[]).map(p => ({
            ...p,
            author_name: profiles[p.author_id] || 'Honec Team'
        }));

        renderFeed();
        renderStories();
        subscribeRealtime();
    }

    // ── Render feed ────────────────────────────────────────────
    function renderFeed() {
        const feed = document.getElementById('newsFeed');
        let posts = [...allPosts];

        // Filter
        if (filterMode === 'recent') {
            const ago7 = Date.now() - 7*24*60*60*1000;
            posts = posts.filter(p => new Date(p.created_at).getTime() > ago7);
        } else if (filterMode === 'popular') {
            posts = posts.sort((a,b) => (b.post_likes?.length||0) - (a.post_likes?.length||0));
        }

        // Search
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            posts = posts.filter(p =>
                (p.title||'').toLowerCase().includes(q) ||
                (p.description||'').toLowerCase().includes(q)
            );
        }

        if (!posts.length) {
            feed.innerHTML = `<div class="feed-state">${searchQuery ? 'No posts match your search.' : 'No posts yet.'}</div>`;
            return;
        }

        feed.innerHTML = posts.map(p => renderPostCard(p)).join('');
        attachPostListeners(feed);
    }

    function renderPostCard(p) {
        const likes     = p.post_likes || [];
        const reactions = p.post_reactions || [];
        const comments  = p.post_comments || [];
        const files     = p.post_files || [];
        const myLike    = currentUser && likes.some(l => l.user_id === currentUser.id);
        const isDraft   = p.published === false;

        // Reaction aggregation
        const reactMap = {};
        reactions.forEach(r => {
            if (!reactMap[r.emoji]) reactMap[r.emoji] = { count:0, mine:false };
            reactMap[r.emoji].count++;
            if (currentUser && r.user_id === currentUser.id) reactMap[r.emoji].mine = true;
        });
        const reactHtml = Object.entries(reactMap).map(([emoji, d]) =>
            `<button class="react-chip ${d.mine?'mine':''}" data-emoji="${esc(emoji)}" title="${esc(emoji)}">${emoji} <span class="react-count">${d.count}</span></button>`
        ).join('');

        // Attachments — rich chips with file-kind badges
        const attHtml = files.map(f => {
            const kind  = fileKind(f.type || '', f.name || '');
            const label = f.name || 'Attachment';
            const isDownload = f.type !== 'link';
            return `<a class="pc-att-chip pc-att-kind-${kind}" href="${esc(f.url)}" target="_blank" rel="noopener"${isDownload ? ` download="${esc(f.name || '')}"` : ''}>
                <span class="pc-att-icon">${kindIcon(kind)}</span>
                <span class="pc-att-info">
                    <span class="pc-att-label">${esc(label)}</span>
                </span>
                <span class="pc-att-dl">
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 5v14M5 12l7 7 7-7"/></svg>
                </span>
            </a>`;
        }).join('');

        const initials = avatarInitials(p.author_name);
        const bodyText = (p.description||'').trim();
        const longBody = bodyText.length > 280;

        return `
        <article class="post-card" data-post-id="${esc(p.id)}">
            <div style="padding:0">

            <!-- Header -->
            <div class="pc-header">
                <div class="pc-avatar">${initials}</div>
                <div class="pc-author-block">
                    <div class="pc-author">${esc(p.author_name)}</div>
                    <div class="pc-meta">
                        <span class="pc-time">${relTime(p.created_at)}</span>
                        ${isDraft ? '<span class="pc-draft-badge">Draft</span>' : ''}
                    </div>
                </div>
                <div class="pc-menu-wrap" style="display:${isAdmin()?'':'none'}">
                    <button class="pc-menu-btn" aria-label="Post options">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>
                    </button>
                    <div class="pc-dropdown" role="menu">
                        <button class="edit-btn" data-id="${esc(p.id)}">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                            Edit post
                        </button>
                        <button class="delete-btn danger" data-id="${esc(p.id)}">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                            Delete post
                        </button>
                    </div>
                </div>
            </div>

            <!-- Image -->
            ${p.image_url ? `
            <div class="pc-image-wrap" data-img="${esc(p.image_url)}">
                <img src="${esc(p.image_url)}" alt="${esc(p.title)}" loading="lazy">
            </div>` : ''}

            <!-- Video -->
            ${p.video_url ? `
            <div class="pc-video-wrap">
                ${isYT(p.video_url)
                    ? `<iframe src="${esc(ytEmbed(p.video_url))}" allowfullscreen loading="lazy" title="${esc(p.title)}"></iframe>`
                    : `<video controls src="${esc(p.video_url)}" preload="none"></video>`
                }
            </div>` : ''}

            <!-- Body -->
            <h2 class="pc-title">${esc(p.title)}</h2>
            <p class="pc-body-text${longBody?' collapsed':''}" id="body-${esc(p.id)}">${esc(bodyText)}</p>
            ${longBody ? `<button class="pc-expand-btn" id="expand-${esc(p.id)}" style="display:block" data-expanded="false">Show more</button>` : ''}

            <!-- Link -->
            ${p.link_url ? `
            <a class="pc-link-btn" href="${esc(p.link_url)}" target="_blank" rel="noopener">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                ${esc(p.link_label || 'Read more')}
            </a>` : ''}

            <!-- Attachments -->
            ${attHtml ? `<div class="pc-attachments">${attHtml}</div>` : ''}

            <!-- Reactions strip -->
            <div class="pc-reactions" id="reactions-${esc(p.id)}">${reactHtml}</div>

            <!-- Action bar -->
            <div class="pc-actions">
                <div class="like-btn-wrap">
                    <button class="pc-act like-btn ${myLike?'like-active':''}" data-id="${esc(p.id)}" aria-label="Like">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="${myLike?'currentColor':'none'}" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
                        <span class="pc-act-count like-count" id="likecount-${esc(p.id)}">${likes.length}</span>
                    </button>
                    <!-- Reaction popover -->
                    <div class="reactions-popover" id="rpop-${esc(p.id)}" style="display:none">
                        ${EMOJIS_REACT.map(e=>`<button class="rp-btn" data-emoji="${e}" data-post-id="${esc(p.id)}" title="${e}">${e}</button>`).join('')}
                    </div>
                </div>
                <button class="pc-act comment-toggle-btn" data-id="${esc(p.id)}" aria-label="Comment">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                    <span class="pc-act-count" id="cmtcount-${esc(p.id)}">${comments.length}</span>
                </button>
                <button class="pc-act react-open-btn" data-id="${esc(p.id)}" aria-label="React">
                    😊
                </button>
                <button class="pc-act bookmark-btn" data-id="${esc(p.id)}" aria-label="Bookmark" title="Save post">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>
                </button>
                <button class="pc-act pc-share-btn share-btn" data-id="${esc(p.id)}" aria-label="Share">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
                </button>
            </div>

            <!-- Comments section -->
            <div class="pc-comments-wrap" id="cmtwrap-${esc(p.id)}">
                <div class="pc-comments-inner">
                    <div class="cmt-list" id="cmtlist-${esc(p.id)}">
                        <div style="font-size:.82rem;color:var(--text-light)">Loading…</div>
                    </div>
                    <div class="cmt-compose-wrap">
                        <div class="cmt-compose" style="display:${currentUser?'':'none'}">
                            <div class="compose-av">${currentUser ? avatarInitials(currentUser.user_metadata?.full_name || currentUser.email) : '?'}</div>
                            <div class="compose-wrap">
                                <textarea class="compose-textarea" placeholder="Add a comment…" rows="1"></textarea>
                                <button class="compose-emoji-btn" type="button" title="Emoji">😊</button>
                                <div class="emoji-picker-pop" style="display:none"></div>
                            </div>
                            <button class="compose-send" type="button">
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                            </button>
                        </div>
                        <p class="sign-note" style="display:${currentUser?'none':''}">
                            <a href="auth.html">Sign in</a> to comment.
                        </p>
                    </div>
                </div>
            </div>

            </div>
        </article>`;
    }

    function attachPostListeners(root) {
        // Expand body
        root.querySelectorAll('.pc-expand-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const postId = btn.id.replace('expand-','');
                const body = document.getElementById('body-' + postId);
                const expanded = btn.dataset.expanded === 'true';
                if (expanded) {
                    body.classList.add('collapsed');
                    btn.textContent = 'Show more';
                    btn.dataset.expanded = 'false';
                } else {
                    body.classList.remove('collapsed');
                    btn.textContent = 'Show less';
                    btn.dataset.expanded = 'true';
                }
            });
        });

        // Image lightbox
        root.querySelectorAll('.pc-image-wrap[data-img]').forEach(w => {
            w.addEventListener('click', () => {
                const lb = document.getElementById('lightbox');
                const img = document.getElementById('lightboxImg');
                img.src = w.dataset.img;
                lb.classList.add('open');
            });
        });

        // 3-dot menu
        root.querySelectorAll('.pc-menu-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const dd = btn.nextElementSibling;
                const wasOpen = dd.classList.contains('open');
                document.querySelectorAll('.pc-dropdown.open').forEach(d => d.classList.remove('open'));
                if (!wasOpen) dd.classList.add('open');
            });
        });
        document.addEventListener('click', () => {
            document.querySelectorAll('.pc-dropdown.open').forEach(d => d.classList.remove('open'));
        });

        // Edit
        root.querySelectorAll('.edit-btn').forEach(btn => {
            btn.addEventListener('click', () => editPost(btn.dataset.id));
        });
        // Delete
        root.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', () => deletePost(btn.dataset.id));
        });

        // Like button — hold for reactions, click for like
        root.querySelectorAll('.like-btn').forEach(btn => {
            let holdTimer;
            const postId = btn.dataset.id;
            const popover = document.getElementById('rpop-' + postId);

            btn.addEventListener('mousedown', () => {
                holdTimer = setTimeout(() => {
                    if (popover) { popover.style.display = 'flex'; }
                }, 400);
            });
            btn.addEventListener('mouseup', () => clearTimeout(holdTimer));
            btn.addEventListener('mouseleave', () => clearTimeout(holdTimer));

            btn.addEventListener('click', () => toggleLike(postId, btn));
        });

        // Reaction popover — quick emoji
        root.querySelectorAll('.rp-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                const { postId, emoji } = btn.dataset;
                const pop = document.getElementById('rpop-' + postId);
                if (pop) pop.style.display = 'none';
                await toggleReaction(postId, emoji);
            });
        });

        // React open btn
        root.querySelectorAll('.react-open-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const pop = document.getElementById('rpop-' + btn.dataset.id);
                if (!pop) return;
                const isOpen = pop.style.display !== 'none';
                document.querySelectorAll('.reactions-popover').forEach(p => p.style.display = 'none');
                if (!isOpen) pop.style.display = 'flex';
            });
        });
        document.addEventListener('click', () => {
            document.querySelectorAll('.reactions-popover').forEach(p => p.style.display = 'none');
        });

        // Reaction chips (existing)
        root.querySelectorAll('.react-chip').forEach(chip => {
            const card = chip.closest('.post-card');
            if (card) {
                chip.addEventListener('click', () => toggleReaction(card.dataset.postId, chip.dataset.emoji));
            }
        });

        // Bookmark
        root.querySelectorAll('.bookmark-btn').forEach(btn => {
            const postId = btn.dataset.id;
            const saved = getSavedPosts();
            if (saved.includes(postId)) btn.classList.add('bookmark-active');
            btn.addEventListener('click', () => toggleBookmark(postId, btn));
        });

        // Share
        root.querySelectorAll('.share-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const url = window.location.origin + window.location.pathname + '?post=' + btn.dataset.id;
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(url).then(() => toast('Link copied!'));
                } else { toast('Link: ' + url); }
            });
        });

        // Comment toggle
        root.querySelectorAll('.comment-toggle-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const wrap = document.getElementById('cmtwrap-' + btn.dataset.id);
                if (!wrap) return;
                const isOpen = wrap.classList.contains('open');
                wrap.classList.toggle('open');
                if (!isOpen) loadComments(btn.dataset.id);
            });
        });

        // Compose
        root.querySelectorAll('.cmt-compose').forEach(compose => {
            const card = compose.closest('.post-card');
            const postId = card?.dataset.postId;
            const textarea = compose.querySelector('.compose-textarea');
            const sendBtn  = compose.querySelector('.compose-send');
            const emojiBtn = compose.querySelector('.compose-emoji-btn');
            const emojiPop = compose.querySelector('.emoji-picker-pop');

            if (textarea) {
                textarea.addEventListener('input', () => {
                    textarea.style.height = 'auto';
                    textarea.style.height = Math.min(textarea.scrollHeight, 160) + 'px';
                });
                textarea.addEventListener('keydown', e => {
                    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submitComment(postId, textarea, sendBtn); }
                });
            }
            if (sendBtn) sendBtn.addEventListener('click', () => submitComment(postId, textarea, sendBtn));

            if (emojiBtn && emojiPop) {
                emojiPop.innerHTML = EMOJIS_PICK.map(em =>
                    `<button class="ep-btn" type="button">${em}</button>`
                ).join('');
                emojiPop.querySelectorAll('.ep-btn').forEach(eb => {
                    eb.addEventListener('click', () => {
                        textarea.value += eb.textContent;
                        textarea.focus();
                        emojiPop.style.display = 'none';
                    });
                });
                emojiBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    emojiPop.style.display = emojiPop.style.display === 'none' ? 'flex' : 'none';
                });
                document.addEventListener('click', () => emojiPop.style.display = 'none');
            }
        });
    }

    // ── Like ───────────────────────────────────────────────────
    async function toggleLike(postId, btn) {
        if (!currentUser) { toast('Sign in to like', true); return; }
        const countEl = document.getElementById('likecount-' + postId);
        const active = btn.classList.contains('like-active');

        // Optimistic
        btn.classList.toggle('like-active');
        btn.classList.add('liked-pop');
        setTimeout(() => btn.classList.remove('liked-pop'), 400);
        const svg = btn.querySelector('svg');
        if (svg) svg.setAttribute('fill', active ? 'none' : 'currentColor');
        if (countEl) countEl.textContent = parseInt(countEl.textContent||0) + (active ? -1 : 1);

        if (active) {
            await supabase.from('post_likes').delete().eq('post_id', postId).eq('user_id', currentUser.id);
        } else {
            await supabase.from('post_likes').upsert({ post_id: postId, user_id: currentUser.id });
        }

        // Refresh real count
        const { count } = await supabase.from('post_likes').select('*', { count:'exact', head:true }).eq('post_id', postId);
        if (countEl) countEl.textContent = count || 0;
    }

    // ── Reactions ──────────────────────────────────────────────
    async function toggleReaction(postId, emoji) {
        if (!currentUser) { toast('Sign in to react', true); return; }
        const { data: existing } = await supabase.from('post_reactions')
            .select('id').eq('post_id', postId).eq('user_id', currentUser.id).eq('emoji', emoji).single();

        if (existing) {
            await supabase.from('post_reactions').delete().eq('id', existing.id);
        } else {
            await supabase.from('post_reactions').insert({ post_id: postId, user_id: currentUser.id, emoji });
        }
        await refreshReactions(postId);
    }

    async function refreshReactions(postId) {
        const { data } = await supabase.from('post_reactions').select('emoji,user_id').eq('post_id', postId);
        const reactMap = {};
        (data||[]).forEach(r => {
            if (!reactMap[r.emoji]) reactMap[r.emoji] = { count:0, mine:false };
            reactMap[r.emoji].count++;
            if (currentUser && r.user_id === currentUser.id) reactMap[r.emoji].mine = true;
        });
        const strip = document.getElementById('reactions-' + postId);
        if (strip) {
            strip.innerHTML = Object.entries(reactMap).map(([emoji, d]) =>
                `<button class="react-chip ${d.mine?'mine':''}" data-emoji="${esc(emoji)}">${emoji} <span class="react-count">${d.count}</span></button>`
            ).join('');
            strip.querySelectorAll('.react-chip').forEach(chip => {
                chip.addEventListener('click', () => toggleReaction(postId, chip.dataset.emoji));
            });
        }
    }

    // ── Comments ───────────────────────────────────────────────
    async function loadComments(postId) {
        const list = document.getElementById('cmtlist-' + postId);
        if (!list) return;
        list.innerHTML = '<div style="font-size:.82rem;color:var(--text-light)">Loading…</div>';

        const { data, error } = await supabase
            .from('post_comments')
            .select('*, comment_replies(*), post_reactions:post_comments_reactions(emoji,user_id)')
            .eq('post_id', postId)
            .order('created_at', { ascending: true });

        if (error || !data?.length) {
            list.innerHTML = '<div style="font-size:.82rem;color:var(--text-light);padding:.2rem 0">No comments yet. Be the first!</div>';
            return;
        }

        // Fetch author names
        const uids = [...new Set(data.map(c=>c.user_id).filter(Boolean))];
        let names = {};
        if (uids.length) {
            const { data: pd } = await supabase.from('profiles').select('id,name').in('id', uids);
            (pd||[]).forEach(p => names[p.id] = p.name);
        }

        list.innerHTML = data.map(c => renderComment(c, names, postId)).join('');
        attachCommentListeners(list, postId);
    }

    function renderComment(c, names, postId) {
        const author = names[c.user_id] || 'User';
        const initials = avatarInitials(author);
        const canDel = currentUser && (currentUser.id === c.user_id || isAdmin());
        const replies = c.comment_replies || [];

        return `
        <div class="cmt-item" data-cmt-id="${esc(c.id)}">
            <div class="cmt-avatar">${initials}</div>
            <div class="cmt-body">
                <div class="cmt-bubble">
                    <div class="cmt-author">${esc(author)}</div>
                    <p class="cmt-text">${esc(c.content||'')}</p>
                </div>
                <div class="cmt-actions">
                    <button class="cmt-act reply-cmt-btn" data-cmt-id="${esc(c.id)}" data-author="${esc(author)}">Reply</button>
                    ${canDel ? `<button class="cmt-act del delete-cmt-btn" data-id="${esc(c.id)}" data-post-id="${esc(postId)}">Delete</button>` : ''}
                    <span class="cmt-time">${relTime(c.created_at)}</span>
                </div>
                ${replies.length ? `
                <div class="replies-thread" id="rt-${esc(c.id)}">
                    ${replies.map(r => renderReply(r, names)).join('')}
                </div>` : `<div class="replies-thread" id="rt-${esc(c.id)}" style="display:none"></div>`}
                <div class="reply-form-slot" id="rfs-${esc(c.id)}"></div>
            </div>
        </div>`;
    }

    function renderReply(r, names) {
        const author = names?.[r.user_id] || 'User';
        const initials = avatarInitials(author);
        return `
        <div class="cmt-item" data-reply-id="${esc(r.id)}">
            <div class="cmt-avatar" style="width:26px;height:26px;font-size:.6rem">${initials}</div>
            <div class="cmt-body">
                <div class="cmt-bubble">
                    <div class="cmt-author" style="font-size:.74rem">${esc(author)}</div>
                    <p class="cmt-text" style="font-size:.84rem">${esc(r.content||'')}</p>
                </div>
                <div class="cmt-actions">
                    <span class="cmt-time">${relTime(r.created_at)}</span>
                </div>
            </div>
        </div>`;
    }

    function attachCommentListeners(root, postId) {
        root.querySelectorAll('.reply-cmt-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const cmtId = btn.dataset.cmtId;
                const author = btn.dataset.author;
                const slot = document.getElementById('rfs-' + cmtId);
                if (!slot) return;
                if (slot.innerHTML) { slot.innerHTML = ''; return; }
                slot.innerHTML = `
                <div class="cmt-compose" style="margin-top:.5rem;padding-left:0">
                    <div class="compose-av">${currentUser ? avatarInitials(currentUser.user_metadata?.full_name||currentUser.email) : '?'}</div>
                    <div class="compose-wrap">
                        <textarea class="compose-textarea" placeholder="Reply to ${esc(author)}…" rows="1"></textarea>
                    </div>
                    <button class="compose-send send-reply-btn" data-cmt-id="${esc(cmtId)}" data-post-id="${esc(postId)}" type="button">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                    </button>
                </div>`;
                const ta = slot.querySelector('textarea');
                const sb = slot.querySelector('.send-reply-btn');
                ta.focus();
                ta.addEventListener('keydown', e => {
                    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submitReply(cmtId, postId, ta, sb); }
                });
                sb.addEventListener('click', () => submitReply(cmtId, postId, ta, sb));
            });
        });

        root.querySelectorAll('.delete-cmt-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                if (!confirm('Delete this comment?')) return;
                await supabase.from('post_comments').delete().eq('id', btn.dataset.id);
                const item = btn.closest('.cmt-item');
                if (item) item.remove();
                const count = document.getElementById('cmtcount-' + btn.dataset.postId);
                if (count) count.textContent = Math.max(0, parseInt(count.textContent||0)-1);
                toast('Comment deleted');
            });
        });
    }

    async function submitComment(postId, textarea, sendBtn) {
        const text = (textarea?.value||'').trim();
        if (!text || !currentUser) return;
        if (sendBtn) sendBtn.disabled = true;
        const { data, error } = await supabase.from('post_comments')
            .insert({ post_id: postId, user_id: currentUser.id, content: text })
            .select().single();
        if (sendBtn) sendBtn.disabled = false;
        if (error) { toast('Could not post comment', true); return; }
        textarea.value = '';
        textarea.style.height = 'auto';
        const count = document.getElementById('cmtcount-' + postId);
        if (count) count.textContent = parseInt(count.textContent||0)+1;

        // Inject new comment optimistically
        const list = document.getElementById('cmtlist-' + postId);
        if (list) {
            const name = currentUser.user_metadata?.full_name || currentUser.email || 'You';
            const stub = { ...data, content: text };
            const names = { [currentUser.id]: name };
            const div = document.createElement('div');
            div.innerHTML = renderComment(stub, names, postId);
            list.appendChild(div.firstElementChild);
            attachCommentListeners(list, postId);
        }
    }

    async function submitReply(cmtId, postId, textarea, sendBtn) {
        const text = (textarea?.value||'').trim();
        if (!text || !currentUser) return;
        if (sendBtn) sendBtn.disabled = true;
        const { data, error } = await supabase.from('comment_replies')
            .insert({ comment_id: cmtId, user_id: currentUser.id, content: text })
            .select().single();
        if (sendBtn) sendBtn.disabled = false;
        if (error) { toast('Could not post reply', true); return; }
        textarea.value = '';
        const slot = document.getElementById('rfs-' + cmtId);
        if (slot) slot.innerHTML = '';

        const thread = document.getElementById('rt-' + cmtId);
        if (thread) {
            thread.style.display = '';
            const name = currentUser.user_metadata?.full_name || currentUser.email || 'You';
            const names = { [currentUser.id]: name };
            const div = document.createElement('div');
            div.innerHTML = renderReply({ ...data, content: text }, names);
            thread.appendChild(div.firstElementChild);
        }
        toast('Reply posted!');
    }

    // ── Post CRUD ──────────────────────────────────────────────
    async function deletePost(postId) {
        if (!confirm('Delete this post permanently?')) return;
        const { error } = await supabase.from('posts').delete().eq('id', postId);
        if (error) { toast('Delete failed', true); return; }
        const card = document.querySelector(`.post-card[data-post-id="${postId}"]`);
        if (card) { card.style.opacity='0'; card.style.transition='opacity .3s'; setTimeout(()=>card.remove(),320); }
        allPosts = allPosts.filter(p => p.id !== postId);
        toast('Post deleted');
        renderStories();
    }

    async function editPost(postId) {
        const post = allPosts.find(p => p.id === postId);
        if (!post) return;
        openCreator();
        document.getElementById('editPostId').value = postId;
        document.getElementById('modalTitle').textContent = 'Edit Post';
        document.getElementById('publishBtn').textContent = 'Save Changes';
        document.getElementById('cancelEditBtn').style.display = '';
        document.getElementById('postTitle').value = post.title || '';
        document.getElementById('postDesc').value = post.description || '';
        document.getElementById('postImage').value = post.image_url || '';
        document.getElementById('postVideo').value = post.video_url || '';
        document.getElementById('postLink').value = post.link_url || '';
        document.getElementById('postLinkLabel').value = post.link_label || '';
        document.getElementById('postPublished').value = post.published !== false ? 'true' : 'false';
        previewImage(post.image_url || '');
    }

    function resetCreator() {
        document.getElementById('editPostId').value = '';
        document.getElementById('modalTitle').textContent = 'New Post';
        document.getElementById('publishBtn').textContent = 'Publish Post';
        document.getElementById('cancelEditBtn').style.display = 'none';
        document.getElementById('postTitle').value = '';
        document.getElementById('postDesc').value = '';
        document.getElementById('postImage').value = '';
        document.getElementById('postVideo').value = '';
        document.getElementById('postLink').value = '';
        document.getElementById('postLinkLabel').value = '';
        document.getElementById('postPublished').value = 'true';
        document.getElementById('modalStatus').textContent = '';
        previewImage('');
        pendingFiles = [];
        document.getElementById('uploadQueue').innerHTML = '';
        pendingFiles = [];
    }

    function openCreator() {
        resetCreator();
        const overlay = document.getElementById('creatorOverlay');
        overlay.classList.add('open');
        document.body.style.overflow = 'hidden';
        document.getElementById('postTitle').focus();
    }
    function closeCreator() {
        document.getElementById('creatorOverlay').classList.remove('open');
        document.body.style.overflow = '';
    }

    async function publishPost() {
        const btn = document.getElementById('publishBtn');
        const status = document.getElementById('modalStatus');
        const editId = document.getElementById('editPostId').value;
        const title = document.getElementById('postTitle').value.trim();
        const desc  = document.getElementById('postDesc').value.trim();
        if (!title || !desc) { status.textContent = 'Title and body are required.'; status.style.color='#e74c3c'; return; }

        btn.disabled = true;
        status.textContent = 'Saving…';
        status.style.color = 'var(--text-muted)';

        const payload = {
            title,
            description: desc,
            image_url:   document.getElementById('postImage').value.trim() || null,
            video_url:   document.getElementById('postVideo').value.trim() || null,
            link_url:    document.getElementById('postLink').value.trim() || null,
            link_label:  document.getElementById('postLinkLabel').value.trim() || null,
            published:   document.getElementById('postPublished').value === 'true',
            author_id:   currentUser?.id,
        };

        let postId = editId;
        if (editId) {
            const { error } = await supabase.from('posts').update(payload).eq('id', editId);
            if (error) { status.textContent = 'Error: ' + error.message; status.style.color='#e74c3c'; btn.disabled=false; return; }
        } else {
            const { data, error } = await supabase.from('posts').insert(payload).select().single();
            if (error) { status.textContent = 'Error: ' + error.message; status.style.color='#e74c3c'; btn.disabled=false; return; }
            postId = data.id;
        }

        // Upload files
        if (pendingFiles.length && postId) {
            status.textContent = 'Uploading files…';
            for (const f of pendingFiles) {
                const path = buildStoragePath(postId, f);
                const { data: up, error: upErr } = await supabase.storage.from('post-media').upload(path, f, { upsert: true });
                if (upErr) { toast('Upload failed: ' + upErr.message, true); continue; }
                const { data: pub } = supabase.storage.from('post-media').getPublicUrl(path);
                const { error: dbErr } = await supabase.from('post_files').insert({
                    post_id: postId,
                    name:    f.name,
                    url:     pub.publicUrl,
                    type:    'file'
                });
                if (dbErr) toast('File record failed: ' + dbErr.message, true);
            }
        }

        // URL attachments
        document.querySelectorAll('.att-row').forEach(row => {
            const inputs = row.querySelectorAll('input');
            const sel = row.querySelector('select');
            const label = inputs[0]?.value.trim();
            const url   = inputs[1]?.value.trim();
            if (label && url && postId) {
                supabase.from('post_files').insert({
                    post_id: postId,
                    name:    label,
                    url:     url,
                    type:    sel?.value === 'link' ? 'link' : 'file'
                });
            }
        });

        btn.disabled = false;
        status.textContent = editId ? '✓ Saved!' : '✓ Published!';
        status.style.color = 'var(--orange)';
        closeCreator();
        toast(editId ? 'Post updated!' : 'Post published!');
        await loadPosts();
    }

    // ── Image preview ──────────────────────────────────────────
    function previewImage(url) {
        const wrap = document.getElementById('imgPreviewWrap');
        const img  = document.getElementById('imgPreview');
        if (!wrap || !img) return;
        if (url) { img.src = url; wrap.style.display = ''; }
        else { wrap.style.display = 'none'; img.src = ''; }
    }

    // ── File upload queue ──────────────────────────────────────
    function addFilesToQueue(files) {
        [...files].forEach(f => {
            pendingFiles.push(f);
            const queue = document.getElementById('uploadQueue');
            const item = document.createElement('div');
            const kind = fileKind(f.type || '', f.name);
            item.className = 'uq-item uq-kind-' + kind;
            item.dataset.name = f.name;
            item.innerHTML = `
                <span class="uq-kind-icon">${kindIcon(kind)}</span>
                <span class="uq-info">
                    <span class="uq-name">${esc(f.name)}</span>
                    <span class="uq-meta"><span class="uq-badge uq-badge-${kind}">${kind.toUpperCase()}</span> <span class="uq-size">${fmtBytes(f.size)}</span></span>
                </span>
                <button class="uq-remove" type="button" title="Remove" aria-label="Remove file">
                    <svg width="10" height="10" viewBox="0 0 12 12"><path d="M1 1l10 10M11 1L1 11" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>
                </button>`;
            item.querySelector('.uq-remove').addEventListener('click', () => {
                pendingFiles = pendingFiles.filter(pf => pf !== f);
                item.remove();
            });
            queue.appendChild(item);
        });
    }

    // ── Realtime subscriptions ─────────────────────────────────
    let _realtimeSubscribed = false;
    function subscribeRealtime() {
        if (_realtimeSubscribed) return;
        _realtimeSubscribed = true;
        supabase.channel('news-page')
            .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'post_likes' }, async (payload) => {
                const postId = payload.new.post_id;
                const { count } = await supabase.from('post_likes').select('*', { count:'exact', head:true }).eq('post_id', postId);
                const el = document.getElementById('likecount-' + postId);
                if (el) el.textContent = count || 0;
            })
            .on('postgres_changes', { event: 'DELETE', schema: 'public', table: 'post_likes' }, async (payload) => {
                const postId = payload.old.post_id;
                const { count } = await supabase.from('post_likes').select('*', { count:'exact', head:true }).eq('post_id', postId);
                const el = document.getElementById('likecount-' + postId);
                if (el) el.textContent = count || 0;
            })
            .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'post_comments' }, async (payload) => {
                const postId = payload.new.post_id;
                const el = document.getElementById('cmtcount-' + postId);
                if (el) el.textContent = parseInt(el.textContent||0)+1;
            })
            .subscribe();
    }

    // ── Stories bar filter ─────────────────────────────────────
    function initBurger() {
        const burger = document.querySelector('.burger');
        const nav = document.querySelector('.site-nav');
        if (!burger || !nav || burger._burgerInit) return;
        burger._burgerInit = true;

        burger.addEventListener('click', (e) => {
            e.stopPropagation();
            const exp = burger.getAttribute('aria-expanded') === 'true';
            burger.setAttribute('aria-expanded', String(!exp));
            nav.classList.toggle('open', !exp);
        });

        // Close menu when a nav link is tapped on mobile
        nav.querySelectorAll('a').forEach(a => {
            a.addEventListener('click', () => {
                nav.classList.remove('open');
                burger.setAttribute('aria-expanded', 'false');
            });
        });

        // Close menu when tapping outside — registered once, on document
        document.addEventListener('click', (e) => {
            if (nav.classList.contains('open') && !nav.contains(e.target) && !burger.contains(e.target)) {
                nav.classList.remove('open');
                burger.setAttribute('aria-expanded', 'false');
            }
        });
    }

    // ── Init ───────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', async () => {
        initBurger(); // run first — before any async calls so burger works immediately on mobile
        await initAuth();
        await loadPosts();
        updateSavedBanner();
        handleDeepLink();

        // Saved banner toggle — filter to saved posts
        let showingSaved = false;
        document.getElementById('savedBanner')?.addEventListener('click', () => {
            showingSaved = !showingSaved;
            if (showingSaved) {
                const saved = getSavedPosts();
                const feed = document.getElementById('newsFeed');
                const filteredPosts = allPosts.filter(p => saved.includes(p.id));
                if (!filteredPosts.length) { toast('No saved posts found'); showingSaved = false; return; }
                feed.innerHTML = `<div style="font-size:.78rem;font-weight:800;color:var(--text-muted);padding:.5rem 0 1rem;letter-spacing:.08em;text-transform:uppercase">Saved posts</div>` +
                    filteredPosts.map(p => renderPostCard(p)).join('');
                attachPostListeners(feed);
                document.getElementById('savedBannerText').textContent = 'Back to all posts';
            } else {
                showingSaved = false;
                document.getElementById('savedBannerText').textContent = `${getSavedPosts().length} saved post${getSavedPosts().length>1?'s':''} — click to filter`;
                renderFeed();
            }
        });
        document.querySelectorAll('.feed-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.feed-tab').forEach(t=>t.classList.remove('active'));
                tab.classList.add('active');
                filterMode = tab.dataset.filter;
                renderFeed();
            });
        });

        // Search
        const searchInput = document.getElementById('feedSearch');
        if (searchInput) {
            let searchTimer;
            searchInput.addEventListener('input', () => {
                clearTimeout(searchTimer);
                searchTimer = setTimeout(() => { searchQuery = searchInput.value; renderFeed(); }, 250);
            });
        }

        // Creator open/close
        document.getElementById('openCreatorBtn')?.addEventListener('click', openCreator);
        document.getElementById('closeCreatorBtn')?.addEventListener('click', closeCreator);
        document.getElementById('cancelEditBtn')?.addEventListener('click', () => { closeCreator(); resetCreator(); });
        document.getElementById('creatorOverlay')?.addEventListener('click', (e) => {
            if (e.target === e.currentTarget) closeCreator();
        });

        // Publish
        document.getElementById('publishBtn')?.addEventListener('click', publishPost);

        // Modal tabs
        document.querySelectorAll('.modal-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.modal-tab').forEach(t=>t.classList.remove('active'));
                document.querySelectorAll('.modal-section').forEach(s=>s.classList.remove('active'));
                tab.classList.add('active');
                const target = tab.dataset.tab;
                document.querySelector(`.modal-section[data-section="${target}"]`)?.classList.add('active');
            });
        });

        // Image preview live
        document.getElementById('postImage')?.addEventListener('input', (e) => previewImage(e.target.value));

        // File drop
        const dropZone = document.getElementById('fileDropZone');
        const filePicker = document.getElementById('filePickerInput');
        if (dropZone && filePicker) {
            dropZone.addEventListener('click', () => filePicker.click());
            filePicker.addEventListener('change', () => addFilesToQueue(filePicker.files));
            dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
            dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
            dropZone.addEventListener('drop', e => {
                e.preventDefault();
                dropZone.classList.remove('dragover');
                addFilesToQueue(e.dataTransfer.files);
            });
        }

        // Add attachment row
        document.getElementById('addAttachmentRowBtn')?.addEventListener('click', () => {
            const rows = document.getElementById('attachmentRows');
            const row = document.createElement('div');
            row.className = 'att-row';
            row.innerHTML = `
                <input class="modal-input" type="text" placeholder="Label">
                <input class="modal-input" type="url" placeholder="https://…">
                <select class="modal-select"><option value="file">File</option><option value="link">Link</option></select>
                <button type="button" class="row-rm" title="Remove"><svg width="11" height="11" viewBox="0 0 12 12"><path d="M1 1l10 10M11 1L1 11" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></button>`;
            row.querySelector('.row-rm').addEventListener('click', () => row.remove());
            rows.appendChild(row);
        });

        // Lightbox close
        document.getElementById('lightboxClose')?.addEventListener('click', () => document.getElementById('lightbox').classList.remove('open'));
        document.getElementById('lightbox')?.addEventListener('click', (e) => {
            if (e.target === e.currentTarget) document.getElementById('lightbox').classList.remove('open');
        });
        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') {
                document.getElementById('lightbox').classList.remove('open');
                closeCreator();
            }
        });
    });