// ══════════════════════════════════════════════════════════════════
//  public/csrf.js  –  Client-side CSRF token helper
//
//  Reads the __csrf cookie (set by the server on every HTML page
//  load) and exports an apiPost() wrapper that automatically
//  attaches the X-CSRF-Token header to every state-mutating request.
//
//  Usage (ES module, import in main.js or inline scripts with
//  the correct nonce):
//
//    import { apiPost, apiDelete } from './csrf.js';
//
//    // Replace:
//    //   fetch('/api/login', { method: 'POST', body: ... })
//    // With:
//    //   apiPost('/api/login', body)
//
//  The Supabase client talks directly to Supabase (not our Node
//  backend), so it is NOT affected by our CSRF middleware. Only
//  calls to /api/* endpoints need this token.
// ══════════════════════════════════════════════════════════════════

/**
 * Read a cookie by name.
 * @param {string} name
 * @returns {string|null}
 */
function getCookie(name) {
    const match = document.cookie.match(
        new RegExp('(?:^|;\\s*)' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)')
    );
    return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Get the current CSRF token.
 * Returns null if the cookie hasn't been set yet (shouldn't happen
 * after the first page load, but guard just in case).
 */
export function getCsrfToken() {
    return getCookie('__csrf');
}

/**
 * Build headers for a state-mutating API request.
 * Merges CSRF token with any caller-supplied headers.
 */
function csrfHeaders(extra = {}) {
    const token = getCsrfToken();
    return {
        'Content-Type': 'application/json',
        ...(token ? { 'X-CSRF-Token': token } : {}),
        ...extra,
    };
}

/**
 * POST to a /api/* endpoint with automatic CSRF token.
 * @param {string} path  – e.g. '/api/login'
 * @param {object} body  – will be JSON-serialised
 * @param {object} [opts] – extra fetch options (headers, signal, …)
 * @returns {Promise<Response>}
 */
export async function apiPost(path, body = {}, opts = {}) {
    const { headers: extraHeaders, ...restOpts } = opts;
    return fetch(path, {
        method: 'POST',
        headers: csrfHeaders(extraHeaders),
        body: JSON.stringify(body),
        ...restOpts,
    });
}

/**
 * DELETE to a /api/* endpoint with automatic CSRF token.
 */
export async function apiDelete(path, opts = {}) {
    const { headers: extraHeaders, ...restOpts } = opts;
    return fetch(path, {
        method: 'DELETE',
        headers: csrfHeaders(extraHeaders),
        ...restOpts,
    });
}

/**
 * Generic authenticated API call.
 * Accepts an optional JWT token for the Authorization header.
 */
export async function apiCall(method, path, { body, token, ...opts } = {}) {
    const headers = csrfHeaders({
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
    });
    return fetch(path, {
        method: method.toUpperCase(),
        headers,
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        ...opts,
    });
}