# Honec Company — Supabase + Netlify

Static site. No Node.js needed. Deploy free to Netlify.

---

## Quick Deploy Steps

### 1. Supabase is already configured
Your project URL and anon key are set in `js/supabase-config.js`.

### 2. Run database setup (if not done yet)
- Go to https://supabase.com → your project → **SQL Editor**
- Paste the contents of `supabase-setup.sql` and click **Run**

### 3. (Optional) Disable email confirmation for testing
- Supabase → **Authentication** → **Email** → turn off "Confirm email"

### 4. Deploy to Netlify
1. Go to https://netlify.com → sign up free
2. Click **Add new site** → **Deploy manually**
3. Drag and drop the entire `honec` folder into the browser
4. Done — your site is live!

---

## How auth works
- First registered account becomes **admin** automatically
- Admin can view all messages, users, and newsletter subscribers in the Dashboard
- Regular users cannot access the Dashboard

---

## File structure
```
honec/
├── index.html
├── aboutus.html
├── auth.html           ← register & login
├── contacts.html       ← contact form
├── messages.html       ← admin dashboard
├── news.html
├── services.html
├── supabase-setup.sql  ← run once in Supabase SQL editor
├── css/
│   └── style.css
├── icons/
│   └── HonecLogo (2).svg
├── images/
│   └── Sited-1..5.svg
└── js/
    ├── supabase-config.js  ← your keys are here
    └── main.js
```
