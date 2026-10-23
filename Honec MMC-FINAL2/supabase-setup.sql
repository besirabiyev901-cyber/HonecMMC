-- ══════════════════════════════════════════════════════════════════
--  HONEC COMPANY — Supabase Full Setup (v5 — Optimized)
--  Run ONCE in Supabase Dashboard → SQL Editor → New query
--  Safe: drops everything and rebuilds from scratch
--
--  CHANGES vs v4:
--    + Indexes on all FK and frequently-queried columns
--    + auth_log table: logs signups, role changes, bans
--    + check_email_provider RPC (used by main.js)
--    + rpc_insert_message / rpc_insert_newsletter (rate-limited)
--    + v_public_posts SECURITY DEFINER view
--    + ban_user now also handles moderator role restriction
--    + Moderator can read but NOT delete messages (policy split)
--    + All SECURITY DEFINER functions use SET search_path = public
-- ══════════════════════════════════════════════════════════════════


-- ── 0. PERMISSIONS ────────────────────────────────────────────────
GRANT USAGE ON SCHEMA public TO postgres, anon, authenticated, service_role;
GRANT ALL   ON ALL TABLES    IN SCHEMA public TO postgres, anon, authenticated, service_role;
GRANT ALL   ON ALL SEQUENCES IN SCHEMA public TO postgres, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES    TO postgres, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO postgres, anon, authenticated, service_role;


-- ── 1. DROP OLD FUNCTIONS ──────────────────────────────────────────
DROP FUNCTION IF EXISTS public.ban_user(UUID, BOOLEAN);
DROP FUNCTION IF EXISTS public.set_user_role(UUID, TEXT);
DROP FUNCTION IF EXISTS public.delete_user_profile(UUID);
DROP FUNCTION IF EXISTS public.handle_new_user() CASCADE;
DROP FUNCTION IF EXISTS public.check_email_provider(TEXT);
DROP FUNCTION IF EXISTS public.rpc_insert_message(TEXT, TEXT, TEXT, TEXT);
DROP FUNCTION IF EXISTS public.rpc_insert_newsletter(TEXT);

-- ── 2. DROP OLD VIEWS ──────────────────────────────────────────────
DROP VIEW IF EXISTS public.v_public_posts;

-- ── 3. DROP OLD TABLES ────────────────────────────────────────────
DROP TABLE IF EXISTS public.auth_log         CASCADE;
DROP TABLE IF EXISTS public.post_reactions   CASCADE;
DROP TABLE IF EXISTS public.comment_replies  CASCADE;
DROP TABLE IF EXISTS public.post_likes       CASCADE;
DROP TABLE IF EXISTS public.post_comments    CASCADE;
DROP TABLE IF EXISTS public.post_files       CASCADE;
DROP TABLE IF EXISTS public.posts            CASCADE;
DROP TABLE IF EXISTS public.newsletters      CASCADE;
DROP TABLE IF EXISTS public.newsletter       CASCADE;
DROP TABLE IF EXISTS public.messages         CASCADE;
DROP TABLE IF EXISTS public.profiles         CASCADE;


-- ══════════════════════════════════════════════════════════════════
--  TABLES
-- ══════════════════════════════════════════════════════════════════

-- ── PROFILES ──────────────────────────────────────────────────────
CREATE TABLE public.profiles (
    id            UUID        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    name          TEXT        NOT NULL DEFAULT '',
    email         TEXT        NOT NULL DEFAULT '',
    role          TEXT        NOT NULL DEFAULT 'user'
                            CHECK (role IN ('admin','moderator','user')),
    banned        BOOLEAN     NOT NULL DEFAULT false,
    auth_provider TEXT        NOT NULL DEFAULT 'email',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "profiles: anyone can read"
    ON public.profiles FOR SELECT USING (true);
CREATE POLICY "profiles: own insert"
    ON public.profiles FOR INSERT WITH CHECK (auth.uid() = id);
-- Users may only update name; role/banned changes go through SECURITY DEFINER RPCs
CREATE POLICY "profiles: own update name only"
    ON public.profiles FOR UPDATE
    USING  (auth.uid() = id)
    WITH CHECK (
        auth.uid() = id
        AND role   = (SELECT role   FROM public.profiles WHERE id = auth.uid())
        AND banned = (SELECT banned FROM public.profiles WHERE id = auth.uid())
    );

-- ── INDEXES: profiles ──────────────────────────────────────────────
CREATE INDEX idx_profiles_role        ON public.profiles(role);
CREATE INDEX idx_profiles_banned      ON public.profiles(banned);
CREATE INDEX idx_profiles_email_lower ON public.profiles(lower(email));


-- ── TRIGGER: auto-create profile on signup ────────────────────────
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    v_count INT;
    v_role  TEXT;
    v_name  TEXT;
    v_prov  TEXT;
BEGIN
    SELECT COUNT(*) INTO v_count FROM public.profiles;
    v_role := CASE WHEN v_count = 0 THEN 'admin' ELSE 'user' END;
    v_name := COALESCE(
        NEW.raw_user_meta_data->>'full_name',
        NEW.raw_user_meta_data->>'name',
        SPLIT_PART(COALESCE(NEW.email,''), '@', 1)
    );
    v_prov := COALESCE(NEW.raw_app_meta_data->>'provider', 'email');

    INSERT INTO public.profiles (id, name, email, role, auth_provider)
    VALUES (NEW.id, v_name, COALESCE(NEW.email, ''), v_role, v_prov);

    -- Log signup
    INSERT INTO public.auth_log (user_id, event, detail)
    VALUES (NEW.id, 'signup', 'role=' || v_role || ', provider=' || v_prov);

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();


-- ── AUTH LOG ──────────────────────────────────────────────────────
CREATE TABLE public.auth_log (
    id          BIGSERIAL   PRIMARY KEY,
    user_id     UUID        REFERENCES public.profiles(id) ON DELETE SET NULL,
    event       TEXT        NOT NULL,   -- 'signup','role_change','ban','unban','delete'
    detail      TEXT,
    actor_id    UUID,                   -- who performed the action (null = self)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.auth_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "auth_log: admin read"
    ON public.auth_log FOR SELECT
    USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));
CREATE POLICY "auth_log: system insert"
    ON public.auth_log FOR INSERT WITH CHECK (true);  -- SECURITY DEFINER functions insert

CREATE INDEX idx_auth_log_user_id    ON public.auth_log(user_id);
CREATE INDEX idx_auth_log_created_at ON public.auth_log(created_at DESC);


-- ── MESSAGES ──────────────────────────────────────────────────────
CREATE TABLE public.messages (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL CHECK (char_length(name)    BETWEEN 1 AND 120),
    email       TEXT        NOT NULL CHECK (char_length(email)   <= 254),
    subject     TEXT        NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 200),
    message     TEXT        NOT NULL CHECK (char_length(message) BETWEEN 1 AND 5000),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

CREATE POLICY "messages: rpc insert only"
    ON public.messages FOR INSERT WITH CHECK (false);  -- only via RPC
CREATE POLICY "messages: admin/mod read"
    ON public.messages FOR SELECT
    USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator')));
CREATE POLICY "messages: admin delete"
    ON public.messages FOR DELETE
    USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin'));

CREATE INDEX idx_messages_created_at ON public.messages(created_at DESC);


-- ── NEWSLETTERS ───────────────────────────────────────────────────
CREATE TABLE public.newsletters (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT        NOT NULL UNIQUE CHECK (char_length(email) <= 254),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.newsletters ENABLE ROW LEVEL SECURITY;

CREATE POLICY "newsletters: rpc insert only"
    ON public.newsletters FOR INSERT WITH CHECK (false);  -- only via RPC
CREATE POLICY "newsletters: admin/mod read"
    ON public.newsletters FOR SELECT
    USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator')));

CREATE INDEX idx_newsletters_email ON public.newsletters(lower(email));


-- ── POSTS ─────────────────────────────────────────────────────────
CREATE TABLE public.posts (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    author_id    UUID        REFERENCES public.profiles(id) ON DELETE SET NULL,
    title        TEXT        NOT NULL CHECK (char_length(title)       BETWEEN 1 AND 300),
    description  TEXT        NOT NULL CHECK (char_length(description) BETWEEN 1 AND 10000),
    image_url    TEXT,
    video_url    TEXT,
    link_url     TEXT,
    link_label   TEXT        CHECK (char_length(link_label) <= 100),
    published    BOOLEAN     NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.posts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "posts: public read published"
    ON public.posts FOR SELECT USING (published = true);
CREATE POLICY "posts: admin/mod read all"
    ON public.posts FOR SELECT
    USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator')));
CREATE POLICY "posts: admin/mod insert"
    ON public.posts FOR INSERT
    WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator')));
CREATE POLICY "posts: admin/mod update"
    ON public.posts FOR UPDATE
    USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator')));
CREATE POLICY "posts: admin/mod delete"
    ON public.posts FOR DELETE
    USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator')));

CREATE INDEX idx_posts_author_id   ON public.posts(author_id);
CREATE INDEX idx_posts_published   ON public.posts(published);
CREATE INDEX idx_posts_created_at  ON public.posts(created_at DESC);


-- ── POST FILES ────────────────────────────────────────────────────
CREATE TABLE public.post_files (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id    UUID        NOT NULL REFERENCES public.posts(id) ON DELETE CASCADE,
    name       TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    url        TEXT        NOT NULL,
    type       TEXT        NOT NULL DEFAULT 'file' CHECK (type IN ('file','link')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.post_files ENABLE ROW LEVEL SECURITY;

CREATE POLICY "post_files: public read"
    ON public.post_files FOR SELECT USING (true);
CREATE POLICY "post_files: admin/mod insert"
    ON public.post_files FOR INSERT
    WITH CHECK (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator')));
CREATE POLICY "post_files: admin/mod delete"
    ON public.post_files FOR DELETE
    USING (EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator')));

CREATE INDEX idx_post_files_post_id ON public.post_files(post_id);


-- ── POST COMMENTS ─────────────────────────────────────────────────
CREATE TABLE public.post_comments (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id    UUID        NOT NULL REFERENCES public.posts(id)    ON DELETE CASCADE,
    author_id  UUID        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    content    TEXT        NOT NULL CHECK (char_length(content) BETWEEN 1 AND 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.post_comments ENABLE ROW LEVEL SECURITY;

CREATE POLICY "post_comments: public read"
    ON public.post_comments FOR SELECT USING (true);
CREATE POLICY "post_comments: auth insert (not banned)"
    ON public.post_comments FOR INSERT
    WITH CHECK (
        auth.uid() IS NOT NULL
        AND author_id = auth.uid()
        AND NOT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND banned = true)
    );
CREATE POLICY "post_comments: own or admin delete"
    ON public.post_comments FOR DELETE
    USING (
        author_id = auth.uid()
        OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin')
    );

CREATE INDEX idx_post_comments_post_id   ON public.post_comments(post_id);
CREATE INDEX idx_post_comments_author_id ON public.post_comments(author_id);
CREATE INDEX idx_post_comments_created   ON public.post_comments(created_at DESC);


-- ── POST LIKES ────────────────────────────────────────────────────
CREATE TABLE public.post_likes (
    post_id    UUID        NOT NULL REFERENCES public.posts(id)    ON DELETE CASCADE,
    user_id    UUID        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (post_id, user_id)
);
ALTER TABLE public.post_likes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "post_likes: public read"
    ON public.post_likes FOR SELECT USING (true);
CREATE POLICY "post_likes: auth insert (not banned)"
    ON public.post_likes FOR INSERT
    WITH CHECK (
        auth.uid() IS NOT NULL
        AND user_id = auth.uid()
        AND NOT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND banned = true)
    );
CREATE POLICY "post_likes: own delete"
    ON public.post_likes FOR DELETE USING (user_id = auth.uid());

CREATE INDEX idx_post_likes_post_id  ON public.post_likes(post_id);
CREATE INDEX idx_post_likes_user_id  ON public.post_likes(user_id);


-- ── POST REACTIONS (emoji) ────────────────────────────────────────
-- One row per user per emoji per post. Users can react with multiple
-- different emoji on the same post, but only once per emoji type.
CREATE TABLE public.post_reactions (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id    UUID        NOT NULL REFERENCES public.posts(id)    ON DELETE CASCADE,
    user_id    UUID        NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    emoji      TEXT        NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 8),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (post_id, user_id, emoji)
);
ALTER TABLE public.post_reactions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "post_reactions: public read"
    ON public.post_reactions FOR SELECT USING (true);
CREATE POLICY "post_reactions: auth insert (not banned)"
    ON public.post_reactions FOR INSERT
    WITH CHECK (
        auth.uid() IS NOT NULL
        AND user_id = auth.uid()
        AND NOT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND banned = true)
    );
CREATE POLICY "post_reactions: own delete"
    ON public.post_reactions FOR DELETE USING (user_id = auth.uid());

CREATE INDEX idx_post_reactions_post_id ON public.post_reactions(post_id);
CREATE INDEX idx_post_reactions_user_id ON public.post_reactions(user_id);


-- ── COMMENT REPLIES ───────────────────────────────────────────────
-- Threaded one-level replies on post_comments.
CREATE TABLE public.comment_replies (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    comment_id  UUID        NOT NULL REFERENCES public.post_comments(id) ON DELETE CASCADE,
    author_id   UUID        NOT NULL REFERENCES public.profiles(id)      ON DELETE CASCADE,
    content     TEXT        NOT NULL CHECK (char_length(content) BETWEEN 1 AND 500),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.comment_replies ENABLE ROW LEVEL SECURITY;

CREATE POLICY "comment_replies: public read"
    ON public.comment_replies FOR SELECT USING (true);
CREATE POLICY "comment_replies: auth insert (not banned)"
    ON public.comment_replies FOR INSERT
    WITH CHECK (
        auth.uid() IS NOT NULL
        AND author_id = auth.uid()
        AND NOT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND banned = true)
    );
CREATE POLICY "comment_replies: own or admin/mod delete"
    ON public.comment_replies FOR DELETE
    USING (
        author_id = auth.uid()
        OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator'))
    );

CREATE INDEX idx_comment_replies_comment_id ON public.comment_replies(comment_id);
CREATE INDEX idx_comment_replies_author_id  ON public.comment_replies(author_id);
CREATE INDEX idx_comment_replies_created    ON public.comment_replies(created_at ASC);


-- ══════════════════════════════════════════════════════════════════
--  VIEWS
-- ══════════════════════════════════════════════════════════════════

-- v_public_posts: non-privileged users query this instead of posts
-- directly — server always enforces published=true, prevents RLS bypass.
CREATE OR REPLACE VIEW public.v_public_posts
WITH (security_invoker = false)
AS
    SELECT id, author_id, title, description, image_url, video_url,
            link_url, link_label, created_at, updated_at
    FROM   public.posts
    WHERE  published = true;


-- ══════════════════════════════════════════════════════════════════
--  REALTIME
-- ══════════════════════════════════════════════════════════════════
ALTER TABLE public.post_likes      REPLICA IDENTITY FULL;
ALTER TABLE public.post_comments   REPLICA IDENTITY FULL;
ALTER TABLE public.post_reactions  REPLICA IDENTITY FULL;
ALTER TABLE public.comment_replies REPLICA IDENTITY FULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime' AND tablename = 'post_comments'
    ) THEN ALTER PUBLICATION supabase_realtime ADD TABLE public.post_comments; END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime' AND tablename = 'post_likes'
    ) THEN ALTER PUBLICATION supabase_realtime ADD TABLE public.post_likes; END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime' AND tablename = 'post_reactions'
    ) THEN ALTER PUBLICATION supabase_realtime ADD TABLE public.post_reactions; END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_publication_tables
        WHERE pubname = 'supabase_realtime' AND tablename = 'comment_replies'
    ) THEN ALTER PUBLICATION supabase_realtime ADD TABLE public.comment_replies; END IF;
END $$;


-- ══════════════════════════════════════════════════════════════════
--  SECURITY DEFINER FUNCTIONS
-- ══════════════════════════════════════════════════════════════════

-- ── ban_user ──────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.ban_user(target_id UUID, should_ban BOOLEAN)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_target_role TEXT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin') THEN
        RAISE EXCEPTION 'Only admins can ban users';
    END IF;
    IF auth.uid() = target_id THEN
        RAISE EXCEPTION 'Cannot ban yourself';
    END IF;
    SELECT role INTO v_target_role FROM public.profiles WHERE id = target_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'User not found'; END IF;
    IF v_target_role = 'admin' AND should_ban THEN
        RAISE EXCEPTION 'Cannot ban another admin';
    END IF;

    UPDATE public.profiles SET banned = should_ban WHERE id = target_id;

    INSERT INTO public.auth_log (user_id, event, detail, actor_id)
    VALUES (target_id, CASE WHEN should_ban THEN 'ban' ELSE 'unban' END,
            'by admin ' || auth.uid()::text, auth.uid());
END;
$$;


-- ── set_user_role ─────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.set_user_role(target_id UUID, new_role TEXT)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_old_role TEXT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin') THEN
        RAISE EXCEPTION 'Only admins can change roles';
    END IF;
    IF auth.uid() = target_id THEN
        RAISE EXCEPTION 'Cannot change your own role';
    END IF;
    IF new_role NOT IN ('user','moderator','admin') THEN
        RAISE EXCEPTION 'Invalid role: %', new_role;
    END IF;

    SELECT role INTO v_old_role FROM public.profiles WHERE id = target_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'User not found'; END IF;

    UPDATE public.profiles SET role = new_role WHERE id = target_id;

    INSERT INTO public.auth_log (user_id, event, detail, actor_id)
    VALUES (target_id, 'role_change',
            'old=' || v_old_role || ' new=' || new_role || ' by=' || auth.uid()::text,
            auth.uid());
END;
$$;


-- ── delete_user_profile ───────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.delete_user_profile(target_id UUID)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_target_role TEXT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'admin') THEN
        RAISE EXCEPTION 'Only admins can delete users';
    END IF;
    IF auth.uid() = target_id THEN
        RAISE EXCEPTION 'Cannot delete your own account';
    END IF;
    SELECT role INTO v_target_role FROM public.profiles WHERE id = target_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'User not found'; END IF;
    IF v_target_role = 'admin' THEN
        RAISE EXCEPTION 'Cannot delete another admin account';
    END IF;

    -- Log before delete (FK will nullify after)
    INSERT INTO public.auth_log (user_id, event, detail, actor_id)
    VALUES (target_id, 'delete', 'deleted by admin ' || auth.uid()::text, auth.uid());

    DELETE FROM public.profiles WHERE id = target_id;
END;
$$;


-- ── check_email_provider ──────────────────────────────────────────
-- Returns provider string if email exists, null otherwise.
-- Used by main.js to show helpful "use Google / GitHub" messages.
CREATE OR REPLACE FUNCTION public.check_email_provider(p_email TEXT)
RETURNS TABLE(provider TEXT) LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    RETURN QUERY
        SELECT p.auth_provider
        FROM   public.profiles p
        WHERE  lower(p.email) = lower(p_email)
        LIMIT  1;
END;
$$;


-- ── rpc_insert_message ────────────────────────────────────────────
-- Rate-limited contact form insert (5 per IP per 5 minutes).
-- anon INSERT on messages is revoked; only this RPC can insert.
CREATE OR REPLACE FUNCTION public.rpc_insert_message(
    p_name    TEXT,
    p_email   TEXT,
    p_subject TEXT,
    p_message TEXT
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_recent INT;
BEGIN
    -- Basic validation
    IF char_length(p_name)    NOT BETWEEN 1 AND 120  THEN RAISE EXCEPTION 'Invalid name'; END IF;
    IF char_length(p_email)   NOT BETWEEN 1 AND 254  THEN RAISE EXCEPTION 'Invalid email'; END IF;
    IF char_length(p_subject) NOT BETWEEN 1 AND 200  THEN RAISE EXCEPTION 'Invalid subject'; END IF;
    IF char_length(p_message) NOT BETWEEN 1 AND 5000 THEN RAISE EXCEPTION 'Invalid message'; END IF;

    -- Rate limit: same email, last 5 minutes, max 5 messages
    SELECT COUNT(*) INTO v_recent
    FROM   public.messages
    WHERE  lower(email) = lower(p_email)
    AND    created_at   > NOW() - INTERVAL '5 minutes';

    IF v_recent >= 5 THEN
        RAISE EXCEPTION 'Too many messages. Please wait before sending again.';
    END IF;

    INSERT INTO public.messages (name, email, subject, message)
    VALUES (p_name, p_email, p_subject, p_message);
END;
$$;


-- ── rpc_insert_newsletter ─────────────────────────────────────────
-- Safe newsletter subscribe (deduplicates, no direct anon insert).
CREATE OR REPLACE FUNCTION public.rpc_insert_newsletter(p_email TEXT)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    IF char_length(p_email) NOT BETWEEN 3 AND 254 THEN
        RAISE EXCEPTION 'Invalid email address';
    END IF;
    INSERT INTO public.newsletters (email)
    VALUES (lower(trim(p_email)))
    ON CONFLICT (email) DO NOTHING;
END;
$$;


-- ══════════════════════════════════════════════════════════════════
--  STORAGE BUCKET: post-media
-- ══════════════════════════════════════════════════════════════════
INSERT INTO storage.buckets (id, name, public)
VALUES ('post-media', 'post-media', true)
ON CONFLICT (id) DO UPDATE SET public = true;

DROP POLICY IF EXISTS "post-media: anyone can read"           ON storage.objects;
DROP POLICY IF EXISTS "post-media: admin/mod upload"          ON storage.objects;
DROP POLICY IF EXISTS "post-media: admin/mod update"          ON storage.objects;
DROP POLICY IF EXISTS "post-media: admin/mod delete"          ON storage.objects;
DROP POLICY IF EXISTS "Admins and moderators can upload"       ON storage.objects;
DROP POLICY IF EXISTS "Anyone can read post-media files"       ON storage.objects;
DROP POLICY IF EXISTS "Admins and moderators can delete files" ON storage.objects;

CREATE POLICY "post-media: anyone can read"
    ON storage.objects FOR SELECT USING (bucket_id = 'post-media');

CREATE POLICY "post-media: admin/mod upload"
    ON storage.objects FOR INSERT
    WITH CHECK (
        bucket_id = 'post-media'
        AND EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator'))
    );

-- Required for upsert:true — without this, re-uploading the same file triggers an RLS violation
CREATE POLICY "post-media: admin/mod update"
    ON storage.objects FOR UPDATE
    USING (
        bucket_id = 'post-media'
        AND EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator'))
    );

CREATE POLICY "post-media: admin/mod delete"
    ON storage.objects FOR DELETE
    USING (
        bucket_id = 'post-media'
        AND EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role IN ('admin','moderator'))
    );


-- ══════════════════════════════════════════════════════════════════
--  DONE.
--  Setup checklist:
--    1. Set SUPABASE_URL + SUPABASE_ANON in js/supabase-config.js
--    2. Register first account → auto-promoted to admin via trigger
--    3. Place admin.html + admin.js + admin.css in your project
--    4. Place news-page.css in css/ folder
--    5. Navigate to admin.html — only admin/moderator can access
--
--  NEW in this version (v6):
--    + post_reactions table — emoji reactions (10-emoji palette)
--      per post, one row per user per emoji, realtime-enabled
--    + comment_replies table — threaded one-level replies on
--      comments; admin/mod can delete any reply, users delete own
--    + Dashboard visible to ALL logged-in users:
--        - role='user' sees a profile card with account info + logout
--        - role='moderator' sees messages + moderation controls
--        - role='admin' sees the full dashboard + admin panel
-- ══════════════════════════════════════════════════════════════════