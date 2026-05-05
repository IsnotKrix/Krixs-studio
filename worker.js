// =====================================================================
// Void Interface — single-file Cloudflare Worker
// Clerk auth + KV storage + fully inlined SPA (HTML/CSS/JS embedded)
// =====================================================================

// ---------- Helpers ----------
const json = (data, init = {}) =>
  new Response(JSON.stringify(data), {
    status: init.status ?? 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "authorization, content-type",
      "access-control-allow-methods": "GET,POST,PATCH,PUT,DELETE,OPTIONS",
      ...(init.headers || {}),
    },
  });

const text = (s, init = {}) =>
  new Response(s, {
    status: init.status ?? 200,
    headers: { "content-type": "text/plain; charset=utf-8", ...(init.headers || {}) },
  });

const html = (s) =>
  new Response(s, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-cache, no-store, must-revalidate", 
    },
  });

const uid = () => crypto.randomUUID();
const now = () => Date.now();

async function sha256Hex(s) {
  const buf = new TextEncoder().encode(s);
  const h = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
}

// ---------- Clerk JWT verification (JWKS, networkless cached) ----------
let JWKS_CACHE = { keys: null, ts: 0, issuer: null };

function clerkIssuer(pk) {
  // pk_test_<base64-of-frontend-api>.clerk.accounts.dev
  // pk_live_<base64-of-frontend-api>
  try {
    const parts = pk.split("_");
    const enc = parts[2];
    const decoded = b64urlDecode(enc);
    // strip trailing "$"
    return "https://" + decoded.replace(/[$]/g, "");
  } catch {
    return null;
  }
}

async function fetchJwks(issuer) {
  if (JWKS_CACHE.keys && JWKS_CACHE.issuer === issuer && now() - JWKS_CACHE.ts < 600000) {
    return JWKS_CACHE.keys;
  }
  const r = await fetch(issuer + "/.well-known/jwks.json");
  if (!r.ok) throw new Error("jwks fetch failed");
  const data = await r.json();
  JWKS_CACHE = { keys: data.keys, ts: now(), issuer };
  return data.keys;
}

async function importJwk(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

async function verifyClerkJwt(token, env) {
  if (!token) return null;
  const pk = env.CLERK_PUBLISHABLE_KEY || "";
  const issuer = clerkIssuer(pk);
  if (!issuer) return null;
  const [h, p, s] = token.split(".");
  if (!h || !p || !s) return null;
  let header, payload;
  try {
    header = JSON.parse(b64urlDecode(h));
    payload = JSON.parse(b64urlDecode(p));
  } catch {
    return null;
  }
  if (payload.iss && payload.iss !== issuer) return null;
  if (payload.exp && payload.exp * 1000 < now() - 5000) return null;
  try {
    const keys = await fetchJwks(issuer);
    const jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return null;
    const key = await importJwk(jwk);
    const sigBin = b64urlDecode(s);
    const sigBytes = Uint8Array.from(sigBin, (c) => c.charCodeAt(0));
    const data = new TextEncoder().encode(`${h}.${p}`);
    const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sigBytes, data);
    if (!ok) return null;
    return payload;
  } catch {
    return null;
  }
}

async function getUser(req, env) {
  const auth = req.headers.get("authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  return verifyClerkJwt(m[1], env);
}

function isAdmin(user, env) {
  if (!user) return false;
  const userId = user.sub || "";
  // 1. Primary: ADMIN_USER_IDS env var — CSV of Clerk user IDs
  const adminIds = String(env.ADMIN_USER_IDS || "")
    .split(",").map((s) => s.trim()).filter(Boolean);
  if (userId && adminIds.includes(userId)) return true;
  // 2. Clerk publicMetadata.role === 'admin' (requires session token template)
  const meta = user.public_metadata || (user.metadata && user.metadata.public) || {};
  if (meta && meta.role === "admin") return true;
  if (user.org_role === "admin") return true;
  return false;
}

async function fetchClerkUser(env, userId) {
  if (!env.CLERK_SECRET_KEY) return null;
  try {
    const r = await fetch("https://api.clerk.com/v1/users/" + userId, {
      headers: { authorization: "Bearer " + env.CLERK_SECRET_KEY },
    });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

// ---------- KV helpers + cache ----------
const kvCache = new Map();
const kvWriteQueue = new Map();
let kvFlushTimer = null;

async function kvGet(env, key, def = null) {
  if (kvCache.has(key)) return kvCache.get(key);
  const v = await env.KV.get(key, { type: "json" });
  const result = v === null || v === undefined ? def : v;
  kvCache.set(key, result);
  return result;
}

async function kvPut(env, key, val) {
  kvCache.set(key, val);
  kvWriteQueue.set(key, val);
  if (kvFlushTimer) clearTimeout(kvFlushTimer);
  kvFlushTimer = setTimeout(async () => {
    const batch = Array.from(kvWriteQueue.entries());
    kvWriteQueue.clear();
    for (const [k, v] of batch) {
      await env.KV.put(k, JSON.stringify(v));
    }
  }, 500);
}

const DEFAULT_SETTINGS = {
  theme: "dark",
  accentColor: "#00f5ff",
  fontSize: 14,
  reduceMotion: false,
  gridOpacity: 50,
  particleDensity: 80,
  auroraIntensity: 50,
  notifications: { email: true, push: true, security: true, reports: true, marketing: false },
  soundEffects: false,
  webhookUrl: "",
  allowedOrigins: [],
  rateLimit: 1000,
  debugMode: false,
  apiVersion: "v1",
};

async function appendLog(env, userId, entry) {
  const k = `logs:${userId}`;
  const cur = (await kvGet(env, k, [])) || [];
  cur.unshift({ ts: now(), ...entry });
  if (cur.length > 100) cur.length = 100;
  await kvPut(env, k, cur);
}

async function bumpAnalytics(env, userId, status, latency) {
  const date = new Date().toISOString().slice(0, 10);
  const k = `analytics:${userId}:${date}`;
  const cur = (await kvGet(env, k, null)) || {
    requests: 0, errors: 0, byMethod: {}, byStatus: {}, totalLatency: 0,
  };
  cur.requests++;
  if (status >= 400) cur.errors++;
  cur.totalLatency += latency;
  await kvPut(env, k, cur);
}

async function pushNotification(env, userId, type, message) {
  const k = `notifications:${userId}`;
  const cur = (await kvGet(env, k, [])) || [];
  cur.unshift({ id: uid(), type, message, read: false, createdAt: now() });
  if (cur.length > 50) cur.length = 50;
  await kvPut(env, k, cur);
}

// ---------- Rate limiter (in-memory per isolate + KV for persistence) ----------
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 60; // requests per window
const AUTH_FAIL_MAX = 5; // max auth failures before block
const AUTH_BLOCK_DURATION = 900000; // 15 min block
const rateBuckets = new Map();
const authFails = new Map();

function getClientIP(req) {
  return req.headers.get("cf-connecting-ip") || req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "unknown";
}

function checkRateLimit(ip) {
  const n = now();
  let bucket = rateBuckets.get(ip);
  if (!bucket || n - bucket.ts > RATE_LIMIT_WINDOW) {
    bucket = { ts: n, count: 0 };
    rateBuckets.set(ip, bucket);
  }
  bucket.count++;
  if (bucket.count > RATE_LIMIT_MAX) return { limited: true, remaining: 0, reset: Math.ceil((bucket.ts + RATE_LIMIT_WINDOW - n) / 1000) };
  return { limited: false, remaining: RATE_LIMIT_MAX - bucket.count, reset: Math.ceil((bucket.ts + RATE_LIMIT_WINDOW - n) / 1000) };
}

function recordAuthFailure(ip) {
  const n = now();
  let entry = authFails.get(ip);
  if (!entry || n - entry.firstFail > AUTH_BLOCK_DURATION) {
    entry = { firstFail: n, count: 0, blocked: false, blockedAt: 0 };
    authFails.set(ip, entry);
  }
  entry.count++;
  if (entry.count >= AUTH_FAIL_MAX) {
    entry.blocked = true;
    entry.blockedAt = n;
  }
  return entry;
}

function isIPBlocked(ip) {
  const entry = authFails.get(ip);
  if (!entry || !entry.blocked) return false;
  if (now() - entry.blockedAt > AUTH_BLOCK_DURATION) {
    authFails.delete(ip);
    return false;
  }
  return true;
}

// ---------- API router ----------
async function handleApi(req, env, url) {
  const path = url.pathname;
  const method = req.method;
  const cf = req.cf || {};
  const country = cf.country || "??";
  const colo = cf.colo || "???";
  const clientIP = getClientIP(req);
  const t0 = now();
  const finish = (resp) => {
    const dt = now() - t0;
    resp.headers.set("X-Edge-Location", colo);
    resp.headers.set("X-Request-Country", country);
    resp.headers.set("X-Latency-Ms", String(dt));
    resp.headers.set("X-Content-Type-Options", "nosniff");
    resp.headers.set("X-Frame-Options", "DENY");
    resp.headers.set("X-XSS-Protection", "1; mode=block");
    resp.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    resp.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    return resp;
  };

  if (method === "OPTIONS") return finish(json({}));

  // Check if IP is blocked from brute force
  if (isIPBlocked(clientIP)) {
    return finish(json({ error: "too_many_requests", message: "Too many failed attempts. Try again later.", retryAfter: 900 }, { status: 429 }));
  }

  // Rate limiting
  const rl = checkRateLimit(clientIP);
  if (rl.limited) {
    const resp = json({ error: "rate_limited", message: "Rate limit exceeded. Slow down.", retryAfter: rl.reset }, { status: 429 });
    resp.headers.set("Retry-After", String(rl.reset));
    resp.headers.set("X-RateLimit-Limit", String(RATE_LIMIT_MAX));
    resp.headers.set("X-RateLimit-Remaining", "0");
    return finish(resp);
  }

  // Public endpoints
  if (path === "/api/health") {
    return finish(json({ status: "ok", region: colo, country, latency: 1, ts: now() }));
  }
  if (path === "/api/status") {
    return finish(json({
      services: [
        { name: "API Gateway", status: "operational", uptime: 99.99, response: 8 },
        { name: "Clerk Auth", status: "operational", uptime: 100.0, response: 12 },
        { name: "KV Storage", status: "operational", uptime: 99.97, response: 3 },
        { name: "Edge Network", status: "operational", uptime: 100.0, response: 0 },
      ],
      incidents: [],
      ts: now(),
    }));
  }

  // Public content API — serves admin-managed content to all users
  const publicContent = path.match(/^\/api\/content\/(changelog|integrations|status)$/);
  if (publicContent && method === "GET") {
    const ckey = "content:" + publicContent[1];
    const v = await kvGet(env, ckey, null);
    return finish(json({ key: publicContent[1], data: v }));
  }

  // Auth required below
  const user = await getUser(req, env);
  if (!user) {
    recordAuthFailure(clientIP);
    const resp = finish(json({ error: "unauthorized" }, { status: 401 }));
    resp.headers.set("X-RateLimit-Remaining", String(rl.remaining));
    return resp;
  }
  const userId = user.sub;

  // /api/me
  if (path === "/api/me" && method === "GET") {
    const settings = (await kvGet(env, `settings:${userId}`, null)) || DEFAULT_SETTINGS;
    const keys = (await kvGet(env, `keys:${userId}`, [])) || [];
    await bumpAnalytics(env, userId, 200, now() - t0);
    return finish(json({
      user: { id: userId, email: user.email, firstName: user.first_name, lastName: user.last_name, image: user.image_url },
      settings, keyCount: keys.length, geo: { country, colo },
      isAdmin: isAdmin(user, env),
    }));
  }

  // /api/keys
  if (path === "/api/keys") {
    if (method === "GET") {
      const keys = (await kvGet(env, `keys:${userId}`, [])) || [];
      return finish(json({ keys }));
    }
    if (method === "POST") {
      const body = await req.json().catch(() => ({}));
      const keys = (await kvGet(env, `keys:${userId}`, [])) || [];
      const isFirst = keys.length === 0;
      const secret = "sk_live_" + crypto.randomUUID().replace(/-/g, "");
      const masked = secret.slice(0, 11) + "•".repeat(20) + secret.slice(-4);
      const k = {
        id: uid(),
        name: body.name || "Untitled Key",
        secret, // returned only on create
        masked,
        permissions: body.permissions || "read",
        expiry: body.expiry || "never",
        tags: body.tags || [],
        createdAt: now(),
        lastUsed: null,
        usageCount: 0,
      };
      keys.unshift({ ...k, secret: undefined });
      await kvPut(env, `keys:${userId}`, keys);
      await appendLog(env, userId, { method: "POST", path: "/api/keys", status: 201, latency: now() - t0, country });
      await pushNotification(env, userId, "key", `API key "${k.name}" created`);
      return finish(json({ key: k, isFirst }, { status: 201 }));
    }
  }
  const keyMatch = path.match(/^\/api\/keys\/([^/]+)$/);
  if (keyMatch) {
    const id = keyMatch[1];
    const keys = (await kvGet(env, `keys:${userId}`, [])) || [];
    const idx = keys.findIndex((x) => x.id === id);
    if (idx < 0) return finish(json({ error: "not found" }, { status: 404 }));
    if (method === "PATCH") {
      const body = await req.json().catch(() => ({}));
      keys[idx] = { ...keys[idx], ...body, id };
      await kvPut(env, `keys:${userId}`, keys);
      return finish(json({ key: keys[idx] }));
    }
    if (method === "DELETE") {
      const removed = keys.splice(idx, 1)[0];
      await kvPut(env, `keys:${userId}`, keys);
      await appendLog(env, userId, { method: "DELETE", path, status: 200, latency: now() - t0, country });
      return finish(json({ deleted: true, key: removed }));
    }
  }

  // /api/activity
  if (path === "/api/activity" && method === "GET") {
    const logs = (await kvGet(env, `logs:${userId}`, [])) || [];
    return finish(json({ logs, total: logs.length }));
  }

  // /api/analytics
  if (path === "/api/analytics" && method === "GET") {
    // build last 30 days
    const days = [];
    for (let i = 29; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400000);
      const k = d.toISOString().slice(0, 10);
      const a = (await kvGet(env, `analytics:${userId}:${k}`, null)) || { requests: 0, errors: 0 };
      days.push({ date: k, ...a });
    }
    const byMethod = { GET: 0, POST: 0, DELETE: 0, PATCH: 0 };
    const byStatus = { 200: 0, 201: 0, 400: 0, 401: 0, 404: 0, 500: 0 };
    const logs = (await kvGet(env, `logs:${userId}`, [])) || [];
    for (const l of logs) {
      byMethod[l.method] = (byMethod[l.method] || 0) + 1;
      byStatus[l.status] = (byStatus[l.status] || 0) + 1;
    }
    const byCountry = {};
    for (const l of logs) byCountry[l.country] = (byCountry[l.country] || 0) + 1;
    return finish(json({ days, byMethod, byStatus, byCountry, totalLogs: logs.length }));
  }

  // /api/settings
  if (path === "/api/settings") {
    if (method === "GET") {
      const s = (await kvGet(env, `settings:${userId}`, null)) || DEFAULT_SETTINGS;
      return finish(json({ settings: s }));
    }
    if (method === "PUT") {
      const body = await req.json().catch(() => ({}));
      const cur = (await kvGet(env, `settings:${userId}`, null)) || DEFAULT_SETTINGS;
      const next = { ...cur, ...body };
      await kvPut(env, `settings:${userId}`, next);
      return finish(json({ settings: next }));
    }
  }

  // /api/webhook-test
  if (path === "/api/webhook-test" && method === "POST") {
    const s = (await kvGet(env, `settings:${userId}`, null)) || DEFAULT_SETTINGS;
    if (!s.webhookUrl) return finish(json({ error: "no webhook configured" }, { status: 400 }));
    try {
      const r = await fetch(s.webhookUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ event: "test.ping", ts: now() }),
      });
      return finish(json({ ok: r.ok, status: r.status }));
    } catch (e) {
      return finish(json({ ok: false, error: String(e) }, { status: 502 }));
    }
  }

  // /api/notifications
  if (path === "/api/notifications") {
    if (method === "GET") {
      const n = (await kvGet(env, `notifications:${userId}`, [])) || [];
      return finish(json({ notifications: n }));
    }
    if (method === "PATCH") {
      const n = (await kvGet(env, `notifications:${userId}`, [])) || [];
      for (const x of n) x.read = true;
      await kvPut(env, `notifications:${userId}`, n);
      return finish(json({ ok: true, notifications: n }));
    }
  }

  // ===== Admin-only =====
  if (path.startsWith("/api/admin/")) {
    if (!isAdmin(user, env)) return finish(json({ error: "forbidden" }, { status: 403 }));

    // List all users (scan KV `settings:` prefix)
    if (path === "/api/admin/users" && method === "GET") {
      const out = [];
      let cursor = undefined;
      // Cloudflare KV list
      do {
        const r = await env.KV.list({ prefix: "settings:", cursor, limit: 1000 });
        for (const k of r.keys) {
          const id = k.name.replace("settings:", "");
          const settings = await kvGet(env, k.name, {});
          const keys = (await kvGet(env, `keys:${id}`, [])) || [];
          const logs = (await kvGet(env, `logs:${id}`, [])) || [];
          // try to enrich from Clerk
          let profile = await fetchClerkUser(env, id);
          out.push({
            id,
            email: profile && profile.email_addresses && profile.email_addresses[0] ? profile.email_addresses[0].email_address : null,
            firstName: profile ? profile.first_name : null,
            lastName: profile ? profile.last_name : null,
            imageUrl: profile ? profile.image_url : null,
            createdAt: profile ? profile.created_at : null,
            lastSignIn: profile ? profile.last_sign_in_at : null,
            keyCount: keys.length,
            logCount: logs.length,
            theme: settings.theme,
            isAdminMeta: !!(profile && profile.public_metadata && profile.public_metadata.role === "admin"),
          });
        }
        cursor = r.list_complete ? null : r.cursor;
      } while (cursor);
      return finish(json({ users: out, total: out.length }));
    }

    // Single user dump
    const um = path.match(/^\/api\/admin\/users\/([^/]+)$/);
    if (um) {
      const id = um[1];
      if (method === "GET") {
        const settings = await kvGet(env, `settings:${id}`, null);
        const keys = await kvGet(env, `keys:${id}`, []);
        const logs = await kvGet(env, `logs:${id}`, []);
        const notifications = await kvGet(env, `notifications:${id}`, []);
        const profile = await fetchClerkUser(env, id);
        return finish(json({ id, settings, keys, logs, notifications, profile }));
        
      }
      if (method === "DELETE") {
        await env.KV.delete(`settings:${id}`);
        await env.KV.delete(`keys:${id}`);
        await env.KV.delete(`logs:${id}`);
        await env.KV.delete(`notifications:${id}`);
        return finish(json({ deleted: true }));
      }
    }

    // Patch user settings
    const usm = path.match(/^\/api\/admin\/users\/([^/]+)\/settings$/);
    if (usm && method === "PUT") {
      const body = await req.json().catch(() => ({}));
      await kvPut(env, `settings:${usm[1]}`, body);
      return finish(json({ ok: true, settings: body }));
    }

    // Revoke a key on a user's behalf
    const ukm = path.match(/^\/api\/admin\/users\/([^/]+)\/keys\/([^/]+)$/);
    if (ukm && method === "DELETE") {
      const list = (await kvGet(env, `keys:${ukm[1]}`, [])) || [];
      const next = list.filter((x) => x.id !== ukm[2]);
      await kvPut(env, `keys:${ukm[1]}`, next);
      return finish(json({ deleted: true }));
    }

    // Broadcast notification to all users
    if (path === "/api/admin/broadcast" && method === "POST") {
      const body = await req.json().catch(() => ({}));
      const message = String(body.message || "Broadcast").slice(0, 280);
      const type = body.type || "info";
      let count = 0, cursor = undefined;
      do {
        const r = await env.KV.list({ prefix: "settings:", cursor, limit: 1000 });
        for (const k of r.keys) {
          const id = k.name.replace("settings:", "");
          await pushNotification(env, id, type, message);
          count++;
        }
        cursor = r.list_complete ? null : r.cursor;
      } while (cursor);
      return finish(json({ ok: true, count }));
    }

    // Global content (changelog / integrations / status)
    const cm = path.match(/^\/api\/admin\/content\/(changelog|integrations|status)$/);
    if (cm) {
      const ckey = `content:${cm[1]}`;
      if (method === "GET") {
        const v = await kvGet(env, ckey, null);
        return finish(json({ key: cm[1], data: v }));
      }
      if (method === "PUT") {
        const body = await req.json().catch(() => ({}));
        await kvPut(env, ckey, body);
        return finish(json({ ok: true, data: body }));
      }
    }

    // Global stats
    if (path === "/api/admin/stats" && method === "GET") {
      let users = 0, keys = 0, logs = 0, cursor = undefined;
      do {
        const r = await env.KV.list({ prefix: "settings:", cursor, limit: 1000 });
        users += r.keys.length;
        cursor = r.list_complete ? null : r.cursor;
      } while (cursor);
      cursor = undefined;
      do {
        const r = await env.KV.list({ prefix: "keys:", cursor, limit: 1000 });
        for (const k of r.keys) { const arr = await kvGet(env, k.name, []); keys += (arr || []).length; }
        cursor = r.list_complete ? null : r.cursor;
      } while (cursor);
      cursor = undefined;
      do {
        const r = await env.KV.list({ prefix: "logs:", cursor, limit: 1000 });
        for (const k of r.keys) { const arr = await kvGet(env, k.name, []); logs += (arr || []).length; }
        cursor = r.list_complete ? null : r.cursor;
      } while (cursor);
      return finish(json({ users, keys, logs, ts: now() }));
    }

    return finish(json({ error: "not found" }, { status: 404 }));
  }

  // /api/me also exposes whether the caller is an admin so the SPA can hide
  // the sidebar entry without an extra round-trip.

  return finish(json({ error: "not found" }, { status: 404 }));
}

// ---------- Worker entry ----------
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (url.pathname.startsWith("/api/")) return handleApi(req, env, url);
    if (url.pathname === "/robots.txt") return text("User-agent: *\nAllow: /");
    if (url.pathname === "/sitemap.xml") return text("");
    // Inject env into HTML (use function replacers — replacement strings would
    // have their $ tokens interpreted otherwise, mangling JS like $$().
    const r = (token, val) => (s) => s.replace(token, () => val);
    const doc = r("__APP_URL_VAL__", env.APP_URL || url.origin)(
                r("__CLERK_PK_VAL__", env.CLERK_PUBLISHABLE_KEY || "")(
                r("__APP_JS__", APP_JS)(
                r("__BODY__", BODY + SVG_ICONS)(
                r("__CSS__", CSS)(HTML)))));
    return html(doc);
  },
};

// =====================================================================
// Embedded SPA — HTML / CSS / JS
// =====================================================================

const SVG_ICONS = `
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <defs>
    <symbol id="i-user" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/></symbol>
    <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 2l8 4v6c0 5-3.5 9.5-8 10-4.5-.5-8-5-8-10V6l8-4z"/></symbol>
    <symbol id="i-bell" viewBox="0 0 24 24"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21a2 2 0 0 0 4 0"/></symbol>
    <symbol id="i-code" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></symbol>
    <symbol id="i-grid" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></symbol>
    <symbol id="i-activity" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></symbol>
    <symbol id="i-settings" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1A2 2 0 1 1 7 4.9l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></symbol>
    <symbol id="i-logout" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></symbol>
    <symbol id="i-star" viewBox="0 0 24 24"><polygon points="12 2 15 9 22 10 17 15 18 22 12 18 6 22 7 15 2 10 9 9"/></symbol>
    <symbol id="i-zap" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></symbol>
    <symbol id="i-moon" viewBox="0 0 24 24"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></symbol>
    <symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><line x1="12" y1="1" x2="12" y2="4"/><line x1="12" y1="20" x2="12" y2="23"/><line x1="4.2" y1="4.2" x2="6.3" y2="6.3"/><line x1="17.7" y1="17.7" x2="19.8" y2="19.8"/><line x1="1" y1="12" x2="4" y2="12"/><line x1="20" y1="12" x2="23" y2="12"/><line x1="4.2" y1="19.8" x2="6.3" y2="17.7"/><line x1="17.7" y1="6.3" x2="19.8" y2="4.2"/></symbol>
    <symbol id="i-globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20z"/></symbol>
    <symbol id="i-key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 21 2"/><path d="M16 7l3 3"/><path d="M19 4l3 3"/></symbol>
    <symbol id="i-chart" viewBox="0 0 24 24"><line x1="6" y1="20" x2="6" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="18" y1="20" x2="18" y2="14"/></symbol>
    <symbol id="i-lock" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></symbol>
    <symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></symbol>
    <symbol id="i-check" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></symbol>
    <symbol id="i-x" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></symbol>
    <symbol id="i-arrow-right" viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></symbol>
    <symbol id="i-terminal" viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></symbol>
    <symbol id="i-database" viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v6c0 1.7 4 3 9 3s9-1.3 9-3V5"/><path d="M3 11v6c0 1.7 4 3 9 3s9-1.3 9-3v-6"/></symbol>
    <symbol id="i-cpu" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></symbol>
    <symbol id="i-wifi" viewBox="0 0 24 24"><path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8 16a6 6 0 0 1 8 0"/><line x1="12" y1="20" x2="12" y2="20"/><path d="M2 8.8a16 16 0 0 1 20 0"/></symbol>
    <symbol id="i-sparkles" viewBox="0 0 24 24"><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2 2M16.4 16.4l2 2M5.6 18.4l2-2M16.4 7.6l2-2"/><circle cx="12" cy="12" r="2"/></symbol>
    <symbol id="i-menu" viewBox="0 0 24 24"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></symbol>
    <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></symbol>
    <symbol id="i-plus" viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></symbol>
    <symbol id="i-trash" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/></symbol>
    <symbol id="i-eye" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></symbol>
    <symbol id="i-edit" viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.1 2.1 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></symbol>
  </defs>
</svg>`;

// =====================================================================
// SPA HTML (built by joining static segments + sentinel substitutions)
// =====================================================================
const HTML_HEAD = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<meta name="theme-color" content="#000409" />
<title>Void Interface — Build · Ship · Scale</title>
<meta name="description" content="Single-edge, zero-cold-start dashboard. Built on Cloudflare Workers, secured by Clerk." />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@300;400;500;600&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
<style>__CSS__</style>
</head>
<body>__BODY__<script>
window.__CLERK_PK__ = "__CLERK_PK_VAL__";
window.__APP_URL__ = "__APP_URL_VAL__";
__APP_JS__
</script>
</body>
</html>`;

const HTML = HTML_HEAD;


// =====================================================================
// CSS — Void Interface design system
// =====================================================================
const CSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  /* Black foundation */
  --void:#000409;--void-2:#04091a;--void-3:#080f24;--void-4:#0c1530;
  --surface:rgba(255,255,255,.02);--surface-hover:rgba(255,255,255,.04);
  --border:rgba(120,160,220,.08);--border-bright:rgba(120,160,220,.18);
  --text:#f5f8ff;--text-dim:rgba(220,230,255,.62);--text-faint:rgba(180,200,235,.36);
  /* Blue scale (single hue family) */
  --blue:#2e7dff;--blue-bright:#4fa8ff;--blue-ice:#a8ccff;--blue-deep:#0048cc;--blue-darker:#001f5f;
  --blue-dim:rgba(46,125,255,.14);--blue-glow:rgba(46,125,255,.32);
  /* Aliases (kept for legacy class names) */
  --cyan:var(--blue-bright);--cyan-dim:var(--blue-dim);--cyan-glow:var(--blue-glow);
  --violet:var(--blue);--violet-dim:var(--blue-dim);--violet-glow:var(--blue-glow);
  --pink:var(--blue-bright);
  /* Status colors (semantic, kept minimal) */
  --green:#36d399;--amber:#f5b942;--red:#ef4458;
  /* Gradients */
  --grad-primary:linear-gradient(135deg,#4fa8ff 0%,#2e7dff 50%,#0048cc 100%);
  --grad-secondary:linear-gradient(135deg,#a8ccff,#2e7dff);
  --grad-success:linear-gradient(135deg,#36d399,#4fa8ff);
  --grad-danger:linear-gradient(135deg,#ef4458,#0048cc);
  --grad-aurora:linear-gradient(135deg,#4fa8ff 0%,#2e7dff 60%,#001f5f 100%);
  --font-display:'Space Grotesk',system-ui,sans-serif;
  --font-body:'JetBrains Mono',ui-monospace,monospace;
  --font-ui:'Manrope',system-ui,sans-serif;
  --radius-sm:8px;--radius-md:12px;--radius-lg:16px;--radius-xl:24px;
  --ease-spring:cubic-bezier(.34,1.56,.64,1);
  --ease-smooth:cubic-bezier(.4,0,.2,1);
  --ease-out:cubic-bezier(0,0,.2,1);
  --grid-opacity:.4;--particle-density:60;--aurora-intensity:.08;
  --accent:var(--blue);
}
html,body{min-height:100%;background:var(--void);color:var(--text);font-family:var(--font-ui);font-size:14px;line-height:1.6;overflow-x:hidden;-webkit-font-smoothing:antialiased}
body{position:relative;min-height:100vh}
a{color:inherit;text-decoration:none}
button{font:inherit;color:inherit;background:transparent;border:0;cursor:pointer}
input,select,textarea{font:inherit;color:inherit;background:transparent;border:0;outline:0}
::selection{background:var(--cyan-dim);color:var(--cyan)}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:var(--void-2)}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:5px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.2)}

/* ---- background system ---- */
#bg-layers{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
#shader-bg{position:absolute;inset:0;width:100%;height:100%;opacity:.45;mix-blend-mode:screen}
.grid-bg{position:absolute;inset:-60px;background-image:
  linear-gradient(rgba(255,255,255,.05) 1px,transparent 1px),
  linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px);
  background-size:60px 60px;opacity:var(--grid-opacity)}
.aurora-blob{position:fixed;width:900px;height:900px;border-radius:50%;filter:blur(160px);opacity:var(--aurora-intensity);pointer-events:none;mix-blend-mode:screen}
.aurora-blob-1{background:var(--blue-bright)}
.aurora-blob-2{background:var(--blue-deep)}
.aurora-blob-3{background:var(--blue);opacity:calc(var(--aurora-intensity) * .7)}
#particles{position:fixed;inset:0;z-index:1;pointer-events:none}
/* scan-line removed */
.corner{position:fixed;width:20px;height:20px;border:1px solid rgba(46,125,255,.15);z-index:3;pointer-events:none;opacity:.3}
.corner.tl{top:12px;left:12px;border-right:0;border-bottom:0}
.corner.tr{top:12px;right:12px;border-left:0;border-bottom:0}
.corner.bl{bottom:12px;left:12px;border-right:0;border-top:0}
.corner.br{bottom:12px;right:12px;border-left:0;border-top:0}
#spotlight{position:fixed;inset:0;z-index:2;pointer-events:none;background:radial-gradient(400px circle at var(--mx,50%) var(--my,50%),rgba(0,245,255,.05),transparent 70%);transition:background .25s linear}

/* ---- cursor ---- */
@media (hover:hover) and (pointer:fine){
  html,body,*{cursor:none !important}
}
.cursor-dot,.cursor-ring{position:fixed;top:0;left:0;pointer-events:none;z-index:99999;transform:translate(-50%,-50%);will-change:transform}
.cursor-dot{width:6px;height:6px;background:var(--blue-bright);border-radius:50%;box-shadow:0 0 12px var(--blue-glow)}
.cursor-ring{width:32px;height:32px;border:1px solid var(--blue-bright);border-radius:50%;transition:width .25s var(--ease-spring),height .25s var(--ease-spring),background .25s,border-color .25s,transform .15s var(--ease-spring)}
#trail{position:fixed;inset:0;pointer-events:none;z-index:99998}
.trail-dot{position:absolute;width:8px;height:8px;border-radius:50%;background:var(--blue-bright);transform:translate(-50%,-50%);pointer-events:none;mix-blend-mode:screen;filter:blur(1px)}
body.cur-link .cursor-ring{width:48px;height:48px;border-color:transparent;background:var(--grad-primary);opacity:.25;transform:translate(-50%,-50%) rotate(45deg)}
body.cur-btn .cursor-dot{opacity:0}
body.cur-btn .cursor-ring{width:40px;height:40px;background:var(--grad-primary);border-color:transparent;opacity:.7}
body.cur-down .cursor-ring{transform:translate(-50%,-50%) scale(.75)}
@media (hover:none),(pointer:coarse){.cursor-dot,.cursor-ring{display:none}}

/* ---- loading overlay ---- */
#load{position:fixed;inset:0;z-index:99998;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:24px;background:var(--void);transition:opacity .4s var(--ease-smooth)}
#load.gone{opacity:0;pointer-events:none}
.loader{width:48px;height:48px;border:2px solid var(--border);border-top-color:var(--cyan);border-right-color:var(--violet);border-radius:50%}
.load-label{font-family:var(--font-body);font-size:12px;letter-spacing:.3em;color:var(--text-faint);text-transform:uppercase}

/* ---- progress bar ---- */
#progress{position:fixed;left:0;right:0;top:0;height:2px;background:var(--grad-primary);box-shadow:0 0 8px var(--cyan-glow);z-index:9999;transform:scaleX(0);transform-origin:left;transition:transform .3s var(--ease-out),opacity .3s}

/* ---- typography ---- */
.h1{font-family:var(--font-display);font-weight:700;font-size:clamp(44px,7.5vw,88px);letter-spacing:-.035em;line-height:.96}
.h2{font-family:var(--font-display);font-weight:600;font-size:clamp(30px,4.5vw,52px);letter-spacing:-.025em;line-height:1.05}
.h3{font-family:var(--font-display);font-weight:600;font-size:28px;letter-spacing:-.015em}
.h4{font-family:var(--font-ui);font-weight:600;font-size:18px;letter-spacing:-.005em}
.body{font-family:var(--font-body);font-size:14px;line-height:1.65}
.mono{font-family:var(--font-body)}
.caption{font-family:var(--font-ui);font-weight:500;font-size:12px;letter-spacing:.05em;text-transform:uppercase;color:var(--text-faint)}
.gradient-text{background:var(--grad-primary);-webkit-background-clip:text;background-clip:text;color:transparent}
.text-cyan{color:var(--cyan)}.text-violet{color:var(--violet)}.text-pink{color:var(--pink)}.text-green{color:var(--green)}.text-amber{color:var(--amber)}.text-red{color:var(--red)}.text-dim{color:var(--text-dim)}.text-faint{color:var(--text-faint)}

/* ---- icon ---- */
.icon{display:inline-block;width:18px;height:18px;vertical-align:middle;stroke:currentColor;stroke-width:1.5;fill:none;stroke-linecap:round;stroke-linejoin:round;transition:transform .3s var(--ease-spring)}
.icon.lg{width:24px;height:24px}.icon.xl{width:32px;height:32px}.icon.sm{width:14px;height:14px}
button:hover .icon,a:hover .icon{transform:scale(1.1)}
.icon-wrap{display:inline-flex;align-items:center;justify-content:center;width:48px;height:48px;border-radius:14px;background:var(--surface);border:1px solid var(--border);transition:all .25s var(--ease-spring)}
.feature-card:hover .icon-wrap{background:var(--grad-primary);border-color:transparent;transform:scale(1.05) rotate(-3deg)}
.feature-card:hover .icon-wrap .icon{stroke:#000}

/* ---- shell ---- */
#app{position:relative;z-index:5;min-height:100vh}
.container{max-width:1280px;margin:0 auto;padding:0 32px}

/* ---- navbar (landing) ---- */
.navbar{position:fixed;top:0;left:0;right:0;z-index:50;backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);background:rgba(3,3,10,.6);border-bottom:1px solid var(--border);padding:18px 0;transform:translateY(0)}

.nav-inner{display:flex;align-items:center;justify-content:space-between;gap:24px}
.logo{display:flex;align-items:center;gap:10px;font-family:var(--font-display);font-weight:800;font-size:18px;letter-spacing:-.02em}
.logo-mark{width:28px;height:28px;border-radius:8px;background:var(--grad-primary);position:relative;overflow:hidden}
.logo-mark::after{content:"";position:absolute;inset:6px;border:2px solid #000;border-radius:4px;border-right:0;border-bottom:0}
.nav-links{display:flex;gap:8px}
.nav-links a{position:relative;padding:8px 14px;font-size:13px;color:var(--text-dim);transition:color .2s}
.nav-links a::after{content:"";position:absolute;left:14px;right:14px;bottom:4px;height:1px;background:var(--cyan);transform:scaleX(0);transform-origin:left;transition:transform .3s var(--ease-out)}
.nav-links a:hover{color:var(--cyan)}
.nav-links a:hover::after{transform:scaleX(1)}
.nav-cta{display:flex;gap:10px;align-items:center}

/* ---- buttons ---- */
.btn{display:inline-flex;align-items:center;gap:8px;padding:12px 20px;border-radius:999px;font-family:var(--font-ui);font-weight:600;font-size:14px;line-height:1;transition:all .25s var(--ease-spring);position:relative;overflow:hidden;border:1px solid transparent;white-space:nowrap}
.btn .icon{transition:transform .25s var(--ease-spring)}
.btn:hover .icon{transform:translateX(3px)}
.btn:active{transform:scale(.96)}
.btn-primary{background:var(--grad-primary);color:#000}
.btn-primary:hover{transform:scale(1.04);box-shadow:0 8px 32px var(--cyan-glow)}
.btn-ghost{color:var(--text);border-color:var(--border-bright);background:var(--surface)}
.btn-ghost:hover{border-color:var(--cyan);color:var(--cyan);background:var(--cyan-dim)}
.btn-danger{background:var(--grad-danger);color:#fff}
.btn-sm{padding:8px 14px;font-size:12px}
.btn-icon{width:36px;height:36px;padding:0;justify-content:center;border-radius:10px;border-color:var(--border);background:var(--surface)}
.btn-icon:hover{border-color:var(--cyan);color:var(--cyan)}
.ripple{display:none}

/* ---- hero ---- */
.hero{min-height:100svh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:120px 32px 80px;position:relative}
.hero h1{position:relative}
.hero h1 .word{display:inline-block;opacity:0;transform:translateY(40px) scale(0.95);animation:word-up .7s var(--ease-spring) forwards}
.hero h1 .word:nth-child(1){animation-delay:.3s;color:var(--blue-bright)}
.hero h1 .word:nth-child(2){color:#fff}
.hero h1 .word:nth-child(3){color:var(--blue-ice)}
.hero-glitch{position:relative;display:inline-block}
.hero-sub{margin-top:28px;font-family:var(--font-body);color:var(--text-dim);font-size:18px;letter-spacing:0;min-height:32px;opacity:1}
.hero-sub .typer-cursor{display:none}
.hero-cta{margin-top:40px;display:flex;gap:14px;flex-wrap:wrap;justify-content:center;opacity:0;transform:scale(.8);animation:cta-in .4s var(--ease-spring) .9s forwards}
@keyframes cta-in{to{opacity:1;transform:scale(1)}}
.hero-stats{margin-top:60px;display:flex;gap:48px;flex-wrap:wrap;justify-content:center;opacit1;1;transform:translateY(0):36px;font-weight:700;background:var(--grad-primary);-webkit-background-clip:text;background-clip:text;color:transparent}
.hero-stat .lbl{font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--text-faint);margin-top:4px}
.scroll-chev{position:absolute;bottom:32px;left:50%;transform:translateX(-50%);color:var(--text-faint);animation:bounce 2s ease-in-out infinite;font-size:24px}
@keyframes bounce{0%,100%{transform:translate(-50%,0)}50%{transform:translate(-50%,8px)}}font-size:24px
/* ---- liquid hero text (SVG displacement filter) ---- */
.liquid{filter:url(#liquid);will-change:filter}
.liquid-soft{filter:url(#liquid-soft)}
.hero h1.hero-glitch{transition:filter .4s}

/* ---- icon path-draw on hover (animated stroke trace) ---- */
.icon path,.icon line,.icon polyline,.icon polygon,.icon circle,.icon rect,.icon ellipse{stroke-dasharray:60;stroke-dashoffset:0;transition:stroke-dashoffset .55s var(--ease-out)}
.feature-card:hover .icon path,.feature-card:hover .icon line,.feature-card:hover .icon polyline,.feature-card:hover .icon polygon,
.qa:hover .icon path,.qa:hover .icon line,.qa:hover .icon polyline,
.int-card:hover .icon path,.int-card:hover .icon line,
.btn-icon:hover .icon path,.btn-icon:hover .icon line,
.icon-wrap:hover .icon path,.icon-wrap:hover .icon line{
  animation:icon-draw .8s var(--ease-out)
}
@keyframes icon-draw{0%{stroke-dashoffset:60}100%{stroke-dashoffset:0}}

/* ---- 3D tilt helper (parent declares perspective) ---- */
.tilt{transition:transform .35s var(--ease-spring),box-shadow .35s var(--ease-out);transform-style:preserve-3d;will-change:transform}
.tilt::after{content:"";position:absolute;inset:0;border-radius:inherit;background:radial-gradient(400px circle at var(--tx,50%) var(--ty,50%),rgba(120,180,255,.07),transparent 60%);pointer-events:none;opacity:0;transition:opacity .3s}
.tilt:hover::after{opacity:1}

/* ---- animated gradient border ---- */
.grad-ring{position:relative;border-radius:inherit}
.grad-ring::before{content:"";position:absolute;inset:-1px;border-radius:inherit;padding:1px;background:conic-gradient(from 0deg,transparent 0,var(--blue-bright) 40%,transparent 60%,var(--blue-deep) 90%,transparent 100%);-webkit-mask:linear-gradient(#000,#000) content-box,linear-gradient(#000,#000);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none;opacity:.6}

/* ---- live ripple dot ---- */
.ripple-dot{position:relative;display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green)}


.glitch{animation:none}
@keyframes glitch{
  0%,86%,100%{clip-path:none;transform:none}
  88%{clip-path:inset(30% 0 50% 0);transform:translate(-2px);text-shadow:1px 0 var(--blue-bright),-1px 0 var(--blue-deep)}
  92%{clip-path:inset(60% 0 10% 0);transform:translate(2px);text-shadow:-1px 0 var(--blue-bright),1px 0 var(--blue-deep)}
  96%{clip-path:none;transform:none;text-shadow:none}
}

/* ---- section ---- */
section{padding:96px 0;position:relative}
.section-tag{display:inline-flex;align-items:center;gap:8px;font-family:var(--font-body);font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--blue-bright);padding:5px 12px;border:1px solid var(--blue-dim);border-radius:999px;background:var(--blue-dim);margin-bottom:18px}
.section-title{font-family:var(--font-display);font-weight:600;font-size:clamp(30px,5vw,56px);letter-spacing:-.03em;max-width:18ch;margin-bottom:14px;line-height:1.05}
.section-sub{color:var(--text-dim);font-size:16px;max-width:60ch;margin-bottom:48px;line-height:1.6}

/* ---- marquee ---- */
.marquee{position:relative;overflow:hidden;padding:24px 0;border-block:1px solid var(--border);background:var(--surface)}
.marquee-track{display:flex;gap:48px;animation:marq 28s linear infinite;width:max-content}
.marquee:hover .marquee-track{animation-play-state:paused}
.marquee-item{font-family:var(--font-body);font-size:13px;color:var(--text-dim);white-space:nowrap;display:flex;align-items:center;gap:10px}
.marquee-item .dot{color:var(--blue-bright)}
@keyframes marq{to{transform:translateX(-50%)}}

/* ---- logos strip ---- */
.logos-strip{padding:48px 0;border-block:1px solid var(--border);background:linear-gradient(180deg,transparent,rgba(46,125,255,.025),transparent)}
.logos-strip .label{font-family:var(--font-body);font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--text-faint);text-align:center;margin-bottom:20px}
.logos-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:32px;align-items:center;justify-items:center;opacity:.5;transition:opacity .3s}
.logos-grid:hover{opacity:.85}
.logo-mark-text{font-family:var(--font-display);font-weight:700;font-size:18px;letter-spacing:-.02em;color:var(--text-dim);display:flex;align-items:center;gap:6px;transition:color .25s,transform .25s}
.logo-mark-text:hover{color:var(--blue-bright);transform:translateY(-2px)}
.logo-mark-text .dot{width:8px;height:8px;border-radius:2px;background:currentColor}
@media (max-width:760px){.logos-grid{grid-template-columns:repeat(3,1fr);gap:20px}}

/* ---- bento (refined feature highlights) ---- */
.bento{display:grid;grid-template-columns:repeat(4,1fr);grid-auto-rows:200px;gap:14px}
.bento .b{position:relative;padding:24px;border-radius:var(--radius-lg);background:var(--surface);border:1px solid var(--border);overflow:hidden;transition:border-color .3s,transform .3s}
.bento .b:hover{border-color:var(--border-bright);transform:translateY(-3px)}
.bento .b.span-2{grid-column:span 2}
.bento .b.span-3{grid-column:span 3}
.bento .b.row-2{grid-row:span 2}
.bento .b h4{font-family:var(--font-display);font-size:18px;font-weight:600;margin-top:auto}
.bento .b p{color:var(--text-dim);font-size:13px;margin-top:6px;font-family:var(--font-body)}
.bento .b{display:flex;flex-direction:column}
.bento .b .icon{margin-bottom:auto}
@media (max-width:880px){.bento{grid-template-columns:repeat(2,1fr)}.bento .b.span-3,.bento .b.span-2{grid-column:span 2}.bento .b.row-2{grid-row:span 1}}

/* ---- integration cards ---- */
.int-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
@media (max-width:1000px){.int-grid{grid-template-columns:repeat(2,1fr)}}
@media (max-width:560px){.int-grid{grid-template-columns:1fr}}
.int-card{padding:22px;border-radius:var(--radius-lg);background:var(--surface);border:1px solid var(--border);display:flex;flex-direction:column;gap:10px;transition:all .3s var(--ease-spring)}
.int-card:hover{border-color:var(--border-bright);transform:translateY(-3px);box-shadow:0 8px 32px rgba(46,125,255,.08)}
.int-card .head{display:flex;align-items:center;gap:12px}
.int-card .ilogo{width:40px;height:40px;border-radius:10px;background:var(--surface-hover);display:inline-flex;align-items:center;justify-content:center;color:var(--blue-bright);font-family:var(--font-display);font-weight:700;font-size:18px}
.int-card h4{font-family:var(--font-ui);font-weight:600;font-size:15px}
.int-card .desc{color:var(--text-dim);font-size:12.5px;line-height:1.5;font-family:var(--font-body);min-height:48px}
.int-card .foot{display:flex;justify-content:space-between;align-items:center;margin-top:auto;padding-top:8px}
.int-card .pill{font-family:var(--font-body)}

/* ---- changelog timeline ---- */
.timeline{position:relative;padding-left:32px}
.timeline::before{content:"";position:absolute;left:8px;top:0;bottom:0;width:1px;background:linear-gradient(180deg,var(--blue-bright),transparent)}
.tl-item{position:relative;padding-bottom:40px}
.tl-item::before{content:"";position:absolute;left:-29px;top:6px;width:14px;height:14px;border-radius:50%;background:var(--void);border:2px solid var(--blue-bright);box-shadow:0 0 12px var(--blue-glow)}
.tl-item .ver{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.tl-item .ver .v{font-family:var(--font-body);font-size:13px;color:var(--blue-bright);font-weight:500}
.tl-item .ver .d{font-family:var(--font-body);font-size:11px;color:var(--text-faint)}
.tl-item h4{font-family:var(--font-display);font-size:20px;font-weight:600;margin-bottom:6px}
.tl-item .changes{list-style:none;padding:0;margin-top:8px}
.tl-item .changes li{padding:5px 0 5px 22px;color:var(--text-dim);font-size:13.5px;font-family:var(--font-body);position:relative}
.tl-item .changes li::before{content:"";position:absolute;left:0;top:11px;width:8px;height:1px;background:var(--blue-bright)}
.tl-item .changes li.feat::after{content:"NEW";position:absolute;left:-44px;top:5px;font-size:9px;font-weight:600;letter-spacing:.1em;color:var(--blue-bright);background:var(--blue-dim);padding:2px 5px;border-radius:3px;font-family:var(--font-body)}

/* ---- keyboard shortcuts ---- */
.shortcuts{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}
@media (max-width:760px){.shortcuts{grid-template-columns:1fr}}
.sc-row{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-radius:10px;background:var(--surface);border:1px solid var(--border)}
.sc-row .kbd-wrap{display:flex;gap:4px}
.sc-row kbd{font-family:var(--font-body);font-size:11px;background:var(--void-3);padding:3px 7px;border-radius:5px;color:var(--blue-bright);border:1px solid var(--border)}

/* ---- features grid ---- */
.feature-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
@media (max-width:900px){.feature-grid{grid-template-columns:1fr}}
.feature-card{position:relative;padding:32px;border-radius:var(--radius-lg);background:var(--surface);border:1px solid var(--border);overflow:hidden;transition:transform .3s var(--ease-spring),border-color .3s,box-shadow .3s;opacity:0;transform:translateY(30px)}
.feature-card.in{opacity:1;transform:translateY(0);transition:transform .6s var(--ease-out),opacity .6s}
.feature-card:hover{transform:translateY(-6px);border-color:rgba(0,245,255,.25);box-shadow:0 20px 60px rgba(0,245,255,.08)}
.feature-card::before{content:"";position:absolute;top:0;left:-100%;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.05),transparent);transition:left .8s}
.feature-card:hover::before{left:100%}
.feature-card h3{font-family:var(--font-display);font-size:24px;margin:18px 0 10px}
.feature-card p{color:var(--text-dim);font-size:14px}
.feature-card .more{margin-top:18px;display:inline-flex;gap:6px;align-items:center;color:var(--cyan);font-size:13px;font-weight:500}

/* ---- steps ---- */
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:32px;position:relative}
@media (max-width:900px){.steps{grid-template-columns:1fr}}
.step{padding:32px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--surface);position:relative}
.step-num{font-family:var(--font-display);font-size:48px;font-weight:800;background:var(--grad-primary);-webkit-background-clip:text;background-clip:text;color:transparent}
.step h4{font-size:20px;margin:8px 0}
.step p{color:var(--text-dim)}

/* ---- pricing ---- */
.pricing{display:grid;grid-template-columns:repeat(2,1fr);gap:24px;max-width:880px;margin:0 auto}
@media (max-width:760px){.pricing{grid-template-columns:1fr}}
.price-card{position:relative;padding:36px;border-radius:var(--radius-lg);background:var(--surface);border:1px solid var(--border)}
.price-card.featured{border:1px solid transparent;background:linear-gradient(var(--void-2),var(--void-2)) padding-box,var(--grad-primary) border-box}
.price-card .pop{position:absolute;top:-12px;left:50%;transform:translateX(-50%);background:var(--grad-primary);color:#000;font-size:11px;letter-spacing:.15em;font-weight:600;padding:5px 14px;border-radius:999px;text-transform:uppercase}
.price-card h3{font-family:var(--font-display);font-size:28px}
.price-card .price{font-family:var(--font-display);font-size:56px;font-weight:800;line-height:1;margin:16px 0}
.price-card .price small{font-size:16px;color:var(--text-dim);font-weight:400}
.price-card ul{list-style:none;margin:24px 0}
.price-card li{padding:8px 0;display:flex;gap:10px;align-items:flex-start;color:var(--text-dim);font-size:14px}
.price-card li::before{content:"";width:16px;height:16px;border-radius:50%;background:var(--cyan-dim);background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2300f5ff' stroke-width='3'%3E%3Cpolyline points='20 6 9 17 4 12'/%3E%3C/svg%3E");background-size:12px;background-repeat:no-repeat;background-position:center;flex-shrink:0;margin-top:2px}

/* ---- testimonials ---- */
.testi{display:grid;grid-template-columns:repeat(3,1fr);gap:20px}
@media (max-width:900px){.testi{grid-template-columns:1fr}}
.testi-card{padding:28px;border-radius:var(--radius-lg);background:var(--surface);border:1px solid var(--border)}
.stars{display:flex;gap:2px;color:var(--amber);margin-bottom:14px}
.testi-card blockquote{font-size:15px;color:var(--text-dim);line-height:1.7;font-family:var(--font-body)}
.testi-author{display:flex;gap:12px;align-items:center;margin-top:18px}
.avatar{width:36px;height:36px;border-radius:50%;background:var(--grad-primary);display:inline-flex;align-items:center;justify-content:center;font-weight:700;color:#000;font-size:13px;flex-shrink:0}
.avatar.lg{width:64px;height:64px;font-size:22px}
.avatar.xl{width:96px;height:96px;font-size:32px}

/* ---- accordion ---- */
.faq{max-width:760px;margin:0 auto}
.faq-item{border-bottom:1px solid var(--border)}
.faq-q{width:100%;padding:24px 0;display:flex;justify-content:space-between;align-items:center;text-align:left;font-family:var(--font-display);font-size:18px;font-weight:600;cursor:pointer}
.faq-q .chev{transition:transform .3s var(--ease-out);color:var(--cyan)}
.faq-item.open .faq-q .chev{transform:rotate(180deg)}
.faq-a{display:grid;grid-template-rows:0fr;transition:grid-template-rows .35s var(--ease-out)}
.faq-a > div{overflow:hidden;color:var(--text-dim);font-family:var(--font-body)}
.faq-item.open .faq-a{grid-template-rows:1fr}
.faq-item.open .faq-a > div{padding-bottom:24px}

/* ---- footer ---- */
footer{padding:80px 0 48px;border-top:1px solid var(--border);background:var(--void-2)}
.foot-grid{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:48px}
@media (max-width:760px){.foot-grid{grid-template-columns:1fr 1fr}}
.foot-col h5{font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--text-faint);margin-bottom:16px;font-weight:600}
.foot-col a{display:block;color:var(--text-dim);font-size:13px;padding:6px 0;font-family:var(--font-body)}
.foot-col a:hover{color:var(--cyan)}
.foot-bottom{margin-top:48px;padding-top:24px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;color:var(--text-faint);font-size:12px;font-family:var(--font-body)}
.socials{display:flex;gap:8px;margin-top:16px}
.socials a{width:36px;height:36px;border-radius:10px;display:inline-flex;align-items:center;justify-content:center;background:var(--surface);border:1px solid var(--border);color:var(--text-dim)}
.socials a:hover{color:var(--cyan);border-color:var(--cyan-dim)}

/* ---- dashboard shell ---- */
.app-shell{display:grid;grid-template-columns:240px 1fr;min-height:100vh}
.app-shell.collapsed{grid-template-columns:60px 1fr}
@media (max-width:880px){.app-shell{grid-template-columns:1fr;padding-bottom:64px}}
.sidebar{position:sticky;top:0;height:100vh;background:var(--void-2);border-right:1px solid var(--border);display:flex;flex-direction:column;padding:18px 12px;transition:width .3s var(--ease-spring)}
@media (max-width:880px){.sidebar{display:none}}
.sb-logo{display:flex;align-items:center;gap:10px;padding:6px 8px;font-family:var(--font-display);font-weight:800;font-size:16px;margin-bottom:18px}
.sb-collapse-toggle{margin-left:auto;color:var(--text-faint)}
.sb-nav{display:flex;flex-direction:column;gap:2px;flex:1}
.sb-link{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:10px;color:var(--text-dim);font-size:13px;font-weight:500;position:relative;transition:all .2s}
.sb-link::before{content:"";position:absolute;left:0;top:6px;bottom:6px;width:2px;background:var(--cyan);border-radius:2px;opacity:0;transform:scaleY(.4);transition:all .25s var(--ease-spring)}
.sb-link:hover{color:#fff;background:var(--surface-hover)}
.sb-link.active{color:var(--cyan);background:var(--cyan-dim)}
.sb-link.active::before{opacity:1;transform:scaleY(1)}
.app-shell.collapsed .sb-link span,.app-shell.collapsed .sb-logo span,.app-shell.collapsed .sb-bot{display:none}
.sb-bot{margin-top:auto;border-top:1px solid var(--border);padding-top:14px;display:flex;flex-direction:column;gap:10px}
.sb-session{font-family:var(--font-body);font-size:11px;color:var(--text-faint);padding:6px 8px;display:flex;align-items:center;gap:6px}
.sb-session .live{width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse 1.4s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.5}50%{opacity:1}}
adding:8px;border-radius:10px;background:var(--surface)}
.sb-user .meta{flex:1;min-width:0}
.sb-user .name{font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sb-user .email{font-size:11px;color:var(--text-faint);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:var(--font-body)}

/* mobile bottom nav */
.mob-nav{display:none;position:fixed;bottom:0;left:0;right:0;background:rgba(7,7,15,.92);backdrop-filter:blur(20px);border-top:1px solid var(--border);padding:8px;z-index:40;justify-content:space-around;align-items:center}
@media (max-width:880px){.mob-nav{display:flex}}
.mob-link{flex:1;display:flex;flex-direction:column;align-items:center;gap:3px;padding:6px;color:var(--text-faint);font-size:10px}
.mob-link.active{color:var(--cyan)}

/* ---- main area ---- */
.main{position:relative;padding:32px;min-height:100vh}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;gap:16px}
.topbar .search{flex:1;max-width:480px;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:12px;display:flex;align-items:center;gap:10px;font-family:var(--font-body);font-size:13px;color:var(--text-dim)}
.topbar .search:focus-within{border-color:var(--cyan-dim);box-shadow:0 0 0 4px var(--cyan-dim)}
.topbar .search input{flex:1}
.topbar .search kbd{font-family:var(--font-body);background:var(--surface-hover);padding:2px 6px;border-radius:5px;font-size:11px;color:var(--text-faint);border:1px solid var(--border)}
.topbar-actions{display:flex;gap:8px;align-items:center}
.bell-wrap{position:relative}
.bell-badge{position:absolute;top:-4px;right:-4px;background:var(--red);color:#fff;font-size:10px;font-weight:700;padding:2px 5px;border-radius:999px;min-width:16px;text-align:center;font-family:var(--font-body)}

/* welcome banner */
.welcome{padding:32px;border-radius:var(--radius-lg);background:linear-gradient(135deg,rgba(46,125,255,.06),rgba(0,72,204,.04));border:1px solid var(--border);position:relative;overflow:hidden}
.welcome::before{content:"";position:absolute;top:-100px;right:-100px;width:300px;height:300px;background:var(--grad-primary);border-radius:50%;filter:blur(80px);opacity:.18}
.welcome h2{font-family:var(--font-display);font-size:32px;font-weight:600;letter-spacing:-.025em}
.welcome p{color:var(--text-dim);margin-top:6px;font-family:var(--font-body);font-size:13px}

/* stats row */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:24px}
@media (max-width:760px){.stats-row{grid-template-columns:repeat(2,1fr)}}
.stat-card{padding:22px;border-radius:var(--radius-lg);background:var(--surface);border:1px solid var(--border);transition:all .3s var(--ease-spring);position:relative;overflow:hidden}
.stat-card:hover{border-color:var(--border-bright);transform:translateY(-3px)}
.stat-card .lbl{font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--text-faint)}
.stat-card .val{font-family:var(--font-display);font-size:36px;font-weight:700;letter-spacing:-.02em;margin-top:8px}
.trend{display:inline-flex;gap:4px;align-items:center;font-size:11px;font-weight:600;padding:3px 8px;border-radius:999px;margin-top:10px}
.trend.up{color:var(--green);background:rgba(0,255,136,.1)}
.trend.down{color:var(--red);background:rgba(255,51,102,.1)}

/* card */
.card{padding:24px;border-radius:var(--radius-lg);background:var(--surface);border:1px solid var(--border)}
.card h3{font-family:var(--font-display);font-size:18px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:10px}

/* split */
.split-2{display:grid;grid-template-columns:2fr 1fr;gap:20px;margin-top:24px}
@media (max-width:1000px){.split-2{grid-template-columns:1fr}}

/* terminal feed */
.terminal{font-family:var(--font-body);font-size:12.5px;background:var(--void-3);border-radius:var(--radius-md);padding:18px;border:1px solid var(--border);max-height:340px;overflow-y:auto}
.term-head{display:flex;justify-content:space-between;font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--text-faint);margin-bottom:12px}
.term-head .live{display:flex;align-items:center;gap:6px;color:var(--green)}
.term-head .live::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);animation:pulse 1.4s infinite}
.term-line{padding:4px 0;display:grid;grid-template-columns:auto auto auto 1fr auto;gap:10px;align-items:center;border-bottom:1px solid rgba(255,255,255,.03);animation:line-in .3s var(--ease-out)}
@keyframes line-in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.term-line .ts{color:var(--text-faint)}
.method{font-weight:600;font-size:10px;letter-spacing:.05em;padding:1px 6px;border-radius:4px;border:1px solid currentColor}
.method.GET{color:var(--blue-bright)}.method.POST{color:var(--blue)}.method.DELETE{color:var(--red)}.method.PATCH{color:var(--blue-ice)}.method.AUTH{color:var(--green)}
.term-line .ok{color:var(--green)}.term-line .err{color:var(--red)}
.term-cursor{display:inline-block;width:8px;height:14px;background:var(--cyan);vertical-align:-2px;margin-left:4px;animation:blink 1s steps(1) infinite}

/* health rings */
.health{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.ring{position:relative;text-align:center}
.ring svg{width:90px;height:90px;transform:rotate(-90deg)}
.ring .bg-circle{fill:none;stroke:var(--border);stroke-width:6}
.ring .fg-circle{fill:none;stroke:var(--cyan);stroke-width:6;stroke-linecap:round;transition:stroke-dashoffset 1.2s var(--ease-out)}
.ring.violet .fg-circle{stroke:var(--violet)}
.ring.green .fg-circle{stroke:var(--green)}
.ring .pct{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-family:var(--font-display);font-size:20px;font-weight:700}
.ring .lbl{font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--text-faint);margin-top:6px}

/* quick actions */
.qa-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;margin-top:24px}
.qa{padding:24px;border-radius:var(--radius-lg);background:var(--surface);border:1px solid var(--border);text-align:left;transition:all .25s var(--ease-spring);display:flex;align-items:center;gap:16px}
.qa:hover{border-color:rgba(0,245,255,.25);transform:translateY(-3px);box-shadow:0 12px 40px rgba(0,245,255,.06)}
.qa:active{transform:scale(.97)}
.qa .icon-wrap{flex-shrink:0}
.qa h4{font-size:15px;font-weight:600}
.qa p{font-size:12px;color:var(--text-faint);font-family:var(--font-body)}

/* tables / lists */
.row{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-radius:var(--radius-md);background:var(--surface);border:1px solid var(--border);transition:all .25s;animation:row-in .4s var(--ease-out) both}
@keyframes row-in{from{opacity:0;transform:translateX(-30px)}to{opacity:1;transform:none}}
.row:hover{border-color:var(--border-bright);background:var(--surface-hover)}
.row.removing{animation:row-out .3s var(--ease-out) forwards}
@keyframes row-out{to{opacity:0;transform:translateX(60px)}}

/* form */
.form-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
@media (max-width:600px){.form-grid{grid-template-columns:1fr}}
.field{position:relative;display:flex;flex-direction:column;gap:6px}
.field label{font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--text-faint);font-weight:600}
.field .input,.field input,.field select,.field textarea{padding:11px 14px;border-radius:10px;background:var(--surface);border:1px solid var(--border);color:#fff;font-family:var(--font-body);font-size:13px;width:100%;transition:all .25s}
.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--cyan-dim);box-shadow:0 0 0 4px var(--cyan-dim)}

/* toggle */
.toggle{position:relative;display:inline-block;width:42px;height:24px;flex-shrink:0}
.toggle input{display:none}
.toggle .track{position:absolute;inset:0;background:var(--surface);border:1px solid var(--border);border-radius:999px;transition:all .35s var(--ease-spring)}
.toggle .thumb{position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:50%;background:#fff;transition:all .35s var(--ease-spring)}
.toggle input:checked + .track{background:var(--grad-primary);border-color:transparent}
.toggle input:checked + .track + .thumb{transform:translateX(18px);background:#000}

/* tabs */
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--border);position:relative;margin-bottom:24px;overflow-x:auto}
.tab{padding:12px 18px;font-size:13px;color:var(--text-dim);position:relative;font-weight:500;white-space:nowrap}
.tab.active{color:var(--cyan)}
.tab-ind{position:absolute;bottom:-1px;height:2px;background:var(--grad-primary);transition:all .3s var(--ease-spring);border-radius:2px}

/* notif drawer */
.drawer-back{position:fixed;inset:0;background:rgba(3,3,10,.6);backdrop-filter:blur(8px);z-index:100;opacity:0;pointer-events:none;transition:opacity .25s}
.drawer-back.open{opacity:1;pointer-events:auto}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(420px,100vw);background:var(--void-2);border-left:1px solid var(--border);z-index:101;transform:translateX(100%);transition:transform .35s var(--ease-spring);display:flex;flex-direction:column}
.drawer.open{transform:translateX(0)}
.drawer header{padding:20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.drawer .body{flex:1;overflow-y:auto;padding:14px}
.notif{padding:14px;border-radius:12px;background:var(--surface);border:1px solid var(--border);margin-bottom:8px;display:flex;gap:12px;align-items:flex-start;position:relative}
.notif.unread::before{content:"";position:absolute;top:14px;right:14px;width:8px;height:8px;border-radius:50%;background:var(--cyan);box-shadow:0 0 6px var(--cyan)}
.notif .nicon{width:32px;height:32px;border-radius:8px;background:var(--surface-hover);display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;color:var(--cyan)}
.notif .msg{font-size:13px}
.notif .time{font-size:11px;color:var(--text-faint);font-family:var(--font-body);margin-top:4px}

/* command palette */
.cmd-back{position:fixed;inset:0;z-index:200;background:rgba(3,3,10,.7);backdrop-filter:blur(16px);display:none;align-items:flex-start;justify-content:center;padding-top:14vh}
.cmd-back.open{display:flex}
.cmd{width:min(640px,90vw);background:var(--void-2);border:1px solid var(--border-bright);border-radius:var(--radius-lg);overflow:hidden;animation:cmd-in .15s var(--ease-out);box-shadow:0 30px 80px rgba(0,0,0,.6)}
@keyframes cmd-in{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}
.cmd input{padding:18px 22px;width:100%;font-size:15px;font-family:var(--font-body);border-bottom:1px solid var(--border)}
.cmd-list{max-height:50vh;overflow-y:auto;padding:6px}
.cmd-item{padding:11px 16px;display:flex;align-items:center;gap:12px;border-radius:10px;cursor:pointer;font-size:13px}
.cmd-item.sel{background:var(--cyan-dim);color:var(--cyan)}
.cmd-item .kbd{margin-left:auto;font-family:var(--font-body);font-size:10px;background:var(--surface);padding:2px 6px;border-radius:4px;color:var(--text-faint)}

/* toast */
#toasts{position:fixed;top:24px;right:24px;z-index:300;display:flex;flex-direction:column;gap:8px;width:min(360px,90vw)}
@media (max-width:600px){#toasts{top:auto;bottom:80px;right:8px;left:8px;width:auto}}
.toast{padding:14px;border-radius:12px;background:var(--void-2);border:1px solid var(--border-bright);display:flex;gap:12px;align-items:flex-start;animation:toast-in .35s var(--ease-spring);position:relative;overflow:hidden}
@keyframes toast-in{from{opacity:0;transform:translateX(60px)}to{opacity:1;transform:none}}
.toast.out{animation:toast-out .25s var(--ease-out) forwards}
@keyframes toast-out{to{opacity:0;transform:translateX(60px)}}
.toast .ti{width:28px;height:28px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.toast.success .ti{color:var(--green);background:rgba(0,255,136,.1)}
.toast.error .ti{color:var(--red);background:rgba(255,51,102,.1)}
.toast.warning .ti{color:var(--amber);background:rgba(255,170,0,.1)}
.toast.info .ti{color:var(--cyan);background:var(--cyan-dim)}
.toast.loading .ti{color:var(--cyan);background:var(--cyan-dim)}
.toast .msg{flex:1;font-size:13px}
.toast .bar{position:absolute;left:0;bottom:0;height:2px;background:var(--cyan);width:100%;transform-origin:left;animation:tbar linear forwards}
@keyframes tbar{to{transform:scaleX(0)}}

/* skeleton */
.skel{background:linear-gradient(90deg,rgba(255,255,255,.03) 0%,rgba(255,255,255,.08) 50%,rgba(255,255,255,.03) 100%);background-size:200% 100%;animation:shimmer 1.5s linear infinite;border-radius:6px}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}

/* view transitions */
.view{animation:view-in .35s var(--ease-out)}
@keyframes view-in{from{opacity:0;transform:translateX(30px)}to{opacity:1;transform:none}}
.view.out{}
.stagger > *{opacity:1;transform:none}

/* avatar with rotating ring */
.avatar-ring{position:relative;display:inline-flex;align-items:center;justify-content:center;padding:3px;border-radius:50%;background:conic-gradient(from 0deg,var(--cyan),var(--violet),var(--pink),var(--cyan))}
.avatar-ring > *{background:var(--void-2);border-radius:50%;padding:2px}

/* pill */
.pill{display:inline-flex;align-items:center;gap:6px;font-size:11px;letter-spacing:.05em;padding:3px 8px;border-radius:999px;border:1px solid var(--border);background:var(--surface);font-family:var(--font-body);text-transform:uppercase;font-weight:500}
.pill.cyan{color:var(--cyan);border-color:var(--cyan-dim);background:var(--cyan-dim)}
.pill.violet{color:var(--violet);border-color:var(--violet-dim);background:var(--violet-dim)}
.pill.green{color:var(--green);border-color:rgba(0,255,136,.2);background:rgba(0,255,136,.08)}
.pill.amber{color:var(--amber);border-color:rgba(255,170,0,.2);background:rgba(255,170,0,.08)}
.pill.red{color:var(--red);border-color:rgba(255,51,102,.2);background:rgba(255,51,102,.08)}

/* bar status */
.uptime-bars{display:grid;grid-template-columns:repeat(90,1fr);gap:2px;height:28px}
.uptime-bars i{background:var(--green);border-radius:2px;transition:transform .15s}
.uptime-bars i:hover{transform:scaleY(1.3)}
.uptime-bars i.amber{background:var(--amber)}
.uptime-bars i.red{background:var(--red)}

/* code block */
.code{position:relative;background:var(--void-3);border:1px solid var(--border);border-radius:var(--radius-md);padding:18px 18px 18px 56px;font-family:var(--font-body);font-size:12.5px;line-height:1.7;overflow-x:auto;white-space:pre;color:#d6d6e6;counter-reset:line}
.code .ln{position:absolute;left:0;top:0;bottom:0;width:42px;background:rgba(255,255,255,.02);text-align:right;padding:18px 8px 18px 0;color:var(--text-faint);user-select:none;font-size:11px}
.code .copy{position:absolute;top:10px;right:10px;width:30px;height:30px;border-radius:8px;background:var(--surface);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;color:var(--text-dim)}
.code .copy:hover{color:var(--cyan);border-color:var(--cyan-dim)}
.tok-k{color:var(--violet)}.tok-s{color:var(--green)}.tok-c{color:var(--text-faint);font-style:italic}.tok-n{color:var(--amber)}.tok-f{color:var(--cyan)}

/* slider */
.slider{appearance:none;-webkit-appearance:none;width:100%;height:4px;border-radius:999px;background:var(--surface);outline:0}
.slider::-webkit-slider-thumb{appearance:none;-webkit-appearance:none;width:18px;height:18px;border-radius:50%;background:var(--cyan);cursor:pointer;box-shadow:0 0 12px var(--cyan-glow);transition:transform .2s var(--ease-spring)}
.slider::-webkit-slider-thumb:hover{transform:scale(1.2)}
.slider::-moz-range-thumb{width:18px;height:18px;border:0;border-radius:50%;background:var(--cyan);cursor:pointer;box-shadow:0 0 12px var(--cyan-glow)}

/* swatches */
.swatches{display:flex;gap:8px;flex-wrap:wrap}
.swatch{width:32px;height:32px;border-radius:10px;cursor:pointer;border:2px solid transparent;transition:all .2s var(--ease-spring)}
.swatch:hover{transform:scale(1.1)}
.swatch.active{border-color:#fff;box-shadow:0 0 0 2px var(--void),0 0 0 3px currentColor}

/* world dots map (simple svg of 64 dots representing major cities) */
.world{position:relative;width:100%;aspect-ratio:2/1;background:var(--void-3);border:1px solid var(--border);border-radius:var(--radius-md);overflow:hidden}
.world svg{width:100%;height:100%}
.world .dot{fill:var(--text-faint);transition:fill .4s,r .3s}
.world .dot.hot{fill:var(--cyan);filter:drop-shadow(0 0 6px var(--cyan))}

/* responsive small */
@media (max-width:760px){.main{padding:18px}.hero{padding:100px 18px 60px}.container{padding:0 18px}}

/* reduce motion */
.reduce-motion *,.reduce-motion *::before,.reduce-motion *::after{animation-duration:.01ms !important;animation-iteration-count:1 !important;transition-duration:.01ms !important}

/* helper: hidden */
[hidden],.hidden{display:none !important}
.flex{display:flex}.items-center{align-items:center}.justify-between{justify-content:space-between}.gap-2{gap:8px}.gap-3{gap:12px}.gap-4{gap:16px}.gap-5{gap:20px}.flex-1{flex:1}.w-full{width:100%}.mt-2{margin-top:8px}.mt-3{margin-top:12px}.mt-4{margin-top:16px}.mt-6{margin-top:24px}.mt-8{margin-top:32px}.mb-2{margin-bottom:8px}.mb-4{margin-bottom:16px}.mb-6{margin-bottom:24px}.text-sm{font-size:12px}.text-xs{font-size:11px}.text-right{text-align:right}.relative{position:relative}.flex-col{flex-direction:column}.flex-wrap{flex-wrap:wrap}
`;


// =====================================================================
// BODY (shell HTML)
// =====================================================================
const BODY = `
<div id="bg-layers">
  <div class="grid-bg"></div>
  <canvas id="shader-bg"></canvas>
  <div class="aurora-blob aurora-blob-1"></div>
  <div class="aurora-blob aurora-blob-2"></div>
  <div class="aurora-blob aurora-blob-3"></div>
</div>
<canvas id="particles"></canvas>
<div id="trail" data-testid="cursor-trail"></div>
<div id="spotlight"></div>
<div class="corner tl"></div><div class="corner tr"></div>
<div class="corner bl"></div><div class="corner br"></div>
<div class="cursor-dot" data-testid="cursor-dot"></div>
<div class="cursor-ring" data-testid="cursor-ring"></div>
<div id="progress" data-testid="progress-bar"></div>
<div id="load" data-testid="loading-overlay"><div class="loader"></div><div class="load-label">Initializing<span style="color:var(--cyan)">_</span></div></div>
<div id="app" data-testid="app-root"></div>
<div class="drawer-back" id="drawer-back" data-testid="drawer-back"></div>
<aside class="drawer" id="notif-drawer" data-testid="notif-drawer">
  <header><h3 class="h4">Notifications</h3><button class="btn-icon" id="drawer-close" data-testid="drawer-close-btn" aria-label="close"><svg class="icon"><use href="#i-x"/></svg></button></header>
  <div class="body" id="notif-body"></div>
  <footer style="padding:14px;border-top:1px solid var(--border);display:flex;justify-content:flex-end"><button class="btn btn-ghost btn-sm" id="mark-all-read" data-testid="mark-all-read-btn">Mark all read</button></footer>
</aside>
<div class="cmd-back" id="cmd-back" data-testid="cmd-palette">
  <div class="cmd">
    <input id="cmd-input" data-testid="cmd-input" placeholder="Type a command or search…" autocomplete="off" />
    <div class="cmd-list" id="cmd-list"></div>
  </div>
</div>
<div id="toasts" data-testid="toasts"></div>
<nav class="mob-nav" id="mob-nav" data-testid="mob-nav"></nav>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <defs>
    <filter id="liquid">
      <feTurbulence type="fractalNoise" baseFrequency="0.012 0.018" numOctaves="2" seed="3">
        <animate attributeName="baseFrequency" dur="22s" values="0.012 0.018;0.020 0.010;0.012 0.018" repeatCount="indefinite"/>
      </feTurbulence>
      <feDisplacementMap in="SourceGraphic" scale="14"/>
    </filter>
    <filter id="liquid-soft">
      <feTurbulence type="fractalNoise" baseFrequency="0.008 0.012" numOctaves="2" seed="7">
        <animate attributeName="baseFrequency" dur="28s" values="0.008 0.012;0.014 0.006;0.008 0.012" repeatCount="indefinite"/>
      </feTurbulence>
      <feDisplacementMap in="SourceGraphic" scale="6"/>
    </filter>
    <filter id="goo">
      <feGaussianBlur stdDeviation="6" result="b"/>
      <feColorMatrix in="b" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 24 -10"/>
    </filter>
  </defs>
</svg>
`;


// =====================================================================
// APP_JS — frontend (kept inside one template literal; avoid backticks/${} inside)
// =====================================================================
const APP_JS = `
"use strict";

/* ---------- Tiny helpers ---------- */
const $ = (s,r)=> (r||document).querySelector(s);
const $$ = (s,r)=> [...(r||document).querySelectorAll(s)];
const h = (tag, attrs, children)=> {
  const e = document.createElement(tag);
  if (attrs) for (const k in attrs){
    if (k === "class") e.className = attrs[k];
    else if (k === "html") e.innerHTML = attrs[k];
    else if (k === "text") e.textContent = attrs[k];
    else if (k.startsWith("on") && typeof attrs[k] === "function") e.addEventListener(k.slice(2), attrs[k]);
    else if (attrs[k] !== false && attrs[k] != null) e.setAttribute(k, attrs[k]);
  }
  if (children){
    if (typeof children === "string") e.innerHTML = children;
    else if (Array.isArray(children)) for (const c of children){ if (c) e.append(c.nodeType ? c : document.createTextNode(c)); }
  }
  return e;
};
const fmt = {
  num(n){ if (n == null) return "—"; return Number(n).toLocaleString("en-US"); },
  pct(n){ return (n||0).toFixed(2)+"%"; },
  ms(n){ return (n||0)+"ms"; },
  rel(t){
    const d = Math.max(0, Date.now()-t)/1000;
    if (d<60) return Math.floor(d)+"s ago";
    if (d<3600) return Math.floor(d/60)+"m ago";
    if (d<86400) return Math.floor(d/3600)+"h ago";
    return Math.floor(d/86400)+"d ago";
  },
  time(t){ const d=new Date(t); return d.toTimeString().slice(0,8)+"."+String(d.getMilliseconds()).padStart(3,"0"); }
};
const clamp = (v,a,b)=> Math.max(a, Math.min(b, v));
const onceVisible = (el, fn, opts)=>{ const io = new IntersectionObserver((es)=>es.forEach(e=>{ if(e.isIntersecting){ fn(e.target); io.unobserve(e.target);} }), opts||{threshold:.15}); io.observe(el); };

/* ---------- State ---------- */
const state = {
  user: null,
  settings: null,
  route: location.hash.slice(1) || "/",
  notifications: [],
  keys: [],
  collapsed: localStorage.getItem("sb-collapsed") === "1",
  reduceMotion: false,
  sessionStart: Date.now(),
  loadedClerk: false,
  clerk: null,
  isAdmin: false
};

/* ---------- API fetch with Clerk token ---------- */
async function api(path, opts){
  opts = opts || {};
  startProgress();
  try{
    const headers = Object.assign({ "content-type":"application/json" }, opts.headers||{});
    if (state.clerk && state.clerk.session){
      try{ const tok = await state.clerk.session.getToken(); if (tok) headers["authorization"] = "Bearer " + tok; } catch(e){}
    }
    const r = await fetch(path, { method: opts.method || "GET", headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
    const text = await r.text();
    let data; try { data = JSON.parse(text); } catch { data = text; }
    if (!r.ok) throw Object.assign(new Error((data && data.error) || ("HTTP "+r.status)), { status:r.status, data });
    return data;
  } finally { endProgress(); }
}

/* ---------- Progress bar ---------- */
let progressTimer = null;
function startProgress(){
  const p = document.getElementById("progress");
  if (!p) return;
  p.style.opacity = 1;
  p.style.transform = "scaleX(0.2)";
  clearTimeout(progressTimer);
  progressTimer = setTimeout(()=>{ p.style.transform = "scaleX(0.7)"; }, 200);
}
function endProgress(){
  const p = document.getElementById("progress");
  if (!p) return;
  clearTimeout(progressTimer);
  p.style.transform = "scaleX(1)";
  setTimeout(()=>{ p.style.opacity = 0; p.style.transform = "scaleX(0)"; }, 250);
}

/* ---------- Toast ---------- */
function toast(type, message, opts){
  opts = opts || {};
  const dur = opts.duration || 4000;
  const wrap = document.getElementById("toasts");
  const t = h("div", { class:"toast "+type, "data-testid":"toast" });
  const iconMap = { success:"i-check", error:"i-x", warning:"i-bell", info:"i-zap", loading:"i-zap" };
  t.innerHTML =
    '<div class="ti"><svg class="icon" width="14" height="14"><use href="#'+iconMap[type]+'"/></svg></div>'+
    '<div class="msg">'+escapeHtml(message)+'</div>'+
    '<button class="btn-icon" style="width:24px;height:24px;background:transparent;border:0" data-testid="toast-close"><svg class="icon" width="12" height="12"><use href="#i-x"/></svg></button>'+
    (opts.persistent ? "" : ('<div class="bar" style="animation-duration:'+dur+'ms"></div>'));
  wrap.appendChild(t);
  const remove = ()=>{ if (t.parentNode){ t.classList.add("out"); setTimeout(()=> t.remove(), 250); } };
  const closeBtn = t.querySelector("[data-testid=toast-close]");
  if (closeBtn) closeBtn.onclick = remove;
  if (!opts.persistent) setTimeout(remove, dur);
  if (state.settings && state.settings.soundEffects) playBeep(type === "error" ? 200 : 880, 60);
  return remove;
}
function escapeHtml(s){ return String(s).replace(/[&<>"']/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }

/* ---------- Sound (synthesized) ---------- */
let _audioCtx = null;
function audioCtx(){ if (!_audioCtx){ try{ _audioCtx = new (window.AudioContext||window.webkitAudioContext)(); }catch(e){} } return _audioCtx; }
function playBeep(freq, ms){
  const ctx = audioCtx(); if (!ctx) return;
  const o = ctx.createOscillator(); const g = ctx.createGain();
  o.type = "sine"; o.frequency.value = freq;
  g.gain.value = 0.08;
  o.connect(g); g.connect(ctx.destination);
  o.start();
  g.gain.setValueAtTime(0.08, ctx.currentTime);
  g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + (ms/1000));
  o.stop(ctx.currentTime + (ms/1000));
}

/* ---------- Custom cursor + trail (throttled for perf) ---------- */
function initCursor(){
  if (matchMedia("(hover:none),(pointer:coarse)").matches) return;
  const dot = $(".cursor-dot"); const ring = $(".cursor-ring"); const trail = $("#trail");
  let mx=window.innerWidth/2, my=window.innerHeight/2, rx=mx, ry=my;
  let lastTrail = 0;
  let throttled = false;
  document.addEventListener("mousemove", (e)=>{ mx=e.clientX; my=e.clientY;
    document.documentElement.style.setProperty("--mx", mx+"px");
    document.documentElement.style.setProperty("--my", my+"px");
    dot.style.transform = "translate("+mx+"px,"+my+"px) translate(-50%,-50%)";
    // trail (heavily throttled for perf)
    const t = performance.now();
    if (trail && t - lastTrail > 40){
      lastTrail = t;
      const d = document.createElement("div"); d.className = "trail-dot";
      d.style.left = mx+"px"; d.style.top = my+"px";
      trail.appendChild(d); setTimeout(()=> d.remove(), 600);
    }
  });
  function loop(){ rx += (mx-rx)*0.18; ry += (my-ry)*0.18; ring.style.transform = "translate("+rx+"px,"+ry+"px) translate(-50%,-50%)"; requestAnimationFrame(loop); } loop();
  document.addEventListener("mousedown", ()=> document.body.classList.add("cur-down"));
  document.addEventListener("mouseup", ()=> document.body.classList.remove("cur-down"));
  document.addEventListener("mouseover", (e)=>{
    const t = e.target.closest("a,button,.btn,[data-cur=link]");
    document.body.classList.toggle("cur-link", !!(t && t.matches("a,[data-cur=link]")));
    document.body.classList.toggle("cur-btn",  !!(t && t.matches("button,.btn")));
  });
}

/* ---------- WebGL flow-field shader background (optional, high GPU cost) ---------- */
function initShader(){
  const c = document.getElementById("shader-bg"); if (!c) return null;
  // Skip shader on low-end devices or when performance.memory suggests constraints
  const perfMem = performance.memory;
  const isLowEnd = window.devicePixelRatio < 1.2 || (perfMem && perfMem.jsHeapSizeLimit < 200000000);
  if (isLowEnd) { c.style.display = "none"; return null; }
  
  const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
  if (!gl){ c.style.display = "none"; return null; }
  const VS = "attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}";
  const FS = ""+
    "precision mediump float;"+
    "uniform vec2 R;uniform float T;uniform vec2 M;"+
    "float h(vec2 p){return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453);}"+
    "float n(vec2 p){vec2 i=floor(p),f=fract(p);float a=h(i),b=h(i+vec2(1,0)),c=h(i+vec2(0,1)),d=h(i+vec2(1,1));vec2 u=f*f*(3.-2.*f);return mix(a,b,u.x)+(c-a)*u.y*(1.-u.x)+(d-b)*u.x*u.y;}"+
    "float fbm(vec2 p){float s=0.,a=.5;for(int i=0;i<6;i++){s+=a*n(p);p*=2.01;a*=.48;}return s;}"+
    "void main(){"+
      "vec2 uv=(gl_FragCoord.xy-.5*R)/R.y;"+
      "vec2 mp=(M-.5*R)/R.y;"+
      "float t=T*.025;"+
      "vec2 q=vec2(fbm(uv*1.8+vec2(t*.7,sin(t*.3)*.4)),fbm(uv*1.8+vec2(cos(t*.4)*.3,t*.6)));"+
      "vec2 r=vec2(fbm(uv*2.5+q+vec2(1.7,9.2)+t*.5),fbm(uv*2.5+q+vec2(8.3,2.8)+t*.4));"+
      "float f=fbm(uv*2.+r*1.5+q*.5);"+
      "float pull=exp(-2.5*length(uv-mp));"+
      "f=mix(f,1.,pull*.22);"+
      "vec3 deep=vec3(0.0,0.02,0.12);"+
      "vec3 mid =vec3(0.02,0.18,0.58);"+
      "vec3 hi  =vec3(0.25,0.55,1.0);"+
      "vec3 peak=vec3(0.6,0.85,1.0);"+
      "vec3 col=mix(deep,mid,smoothstep(.2,.5,f));"+
      "col=mix(col,hi,smoothstep(.5,.75,f));"+
      "col=mix(col,peak,smoothstep(.8,.98,f)*.5);"+
      "col+=vec3(0.02,0.06,0.12)*pull;"+
      "col*=.92+.35*pull;"+
      "col*=1.-.4*length(uv);"+
      "gl_FragColor=vec4(col,1.);"+
    "}";
  function compile(t,s){ const sh=gl.createShader(t); gl.shaderSource(sh,s); gl.compileShader(sh); return sh; }
  const prog = gl.createProgram();
  gl.attachShader(prog, compile(gl.VERTEX_SHADER, VS));
  gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FS));
  gl.linkProgram(prog);
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)){ c.style.display="none"; return null; }
  gl.useProgram(prog);
  const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1,1,-1,-1,1,1,1]), gl.STATIC_DRAW);
  const a = gl.getAttribLocation(prog,"p"); gl.enableVertexAttribArray(a); gl.vertexAttribPointer(a,2,gl.FLOAT,false,0,0);
  const uR = gl.getUniformLocation(prog,"R");
  const uT = gl.getUniformLocation(prog,"T");
  const uM = gl.getUniformLocation(prog,"M");
  let mx = innerWidth/2, my = innerHeight/2;
  addEventListener("mousemove", e=>{ mx = e.clientX; my = innerHeight - e.clientY; });
  function size(){
    const s = Math.min(1, devicePixelRatio*0.6);
    c.width = Math.floor(innerWidth*s); c.height = Math.floor(innerHeight*s);
    gl.viewport(0,0,c.width,c.height);
  }
  size(); addEventListener("resize", size);
  const start = performance.now();
  let last = 0;
  function frame(t){
    if (t - last > 33){
      last = t;
      gl.uniform2f(uR, c.width, c.height);
      gl.uniform1f(uT, (t-start)/1000);
      const k = c.width/innerWidth;
      gl.uniform2f(uM, mx*k, my*k);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
  return { ok:true };
}

/* ---------- 3D parallax tilt (delegate) - skip on mobile for perf ---------- */
function bindTilt(scope){
  // Skip tilt on mobile or low-end devices
  if (matchMedia("(hover:none),(pointer:coarse)").matches || window.devicePixelRatio < 1.2) return;
  
  scope = scope || document;
  const sel = ".feature-card, .stat-card, .qa, .int-card, .price-card, .step, .testi-card, .card.tiltable";
  scope.querySelectorAll(sel).forEach(el=>{
    if (el.__tilt) return; el.__tilt = true;
    el.style.transformStyle = "preserve-3d";
    el.style.willChange = "transform";
    el.classList.add("tilt");
    el.addEventListener("mousemove",(e)=>{
      const r = el.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width;
      const py = (e.clientY - r.top) / r.height;
      el.style.setProperty("--tx", (px*100)+"%");
      el.style.setProperty("--ty", (py*100)+"%");
      const max = 7;
      const rx = (0.5-py)*max; const ry = (px-0.5)*max;
      el.style.transform = "perspective(900px) rotateX("+rx+"deg) rotateY("+ry+"deg) translateY(-3px)";
    });
    el.addEventListener("mouseleave",()=>{ el.style.transform = ""; });
  });
}

/* ---------- Particles ---------- */
function initParticles(){
  const c = document.getElementById("particles"); const ctx = c.getContext("2d");
  function size(){ c.width = innerWidth * devicePixelRatio; c.height = innerHeight * devicePixelRatio; c.style.width = innerWidth+"px"; c.style.height = innerHeight+"px"; ctx.scale(devicePixelRatio, devicePixelRatio); }
  size();
  let resizeT; addEventListener("resize", ()=>{ clearTimeout(resizeT); resizeT = setTimeout(size, 100); });
  const colors = ["rgba(79,168,255,", "rgba(46,125,255,", "rgba(168,204,255,"];
  let particles = [];
  function rebuild(){
    // Reduce particles on low-end devices for performance
    const isLowEnd = window.devicePixelRatio < 1.5 || (navigator.deviceMemory && navigator.deviceMemory < 4);
    const density = (state.settings && state.settings.particleDensity != null) ? state.settings.particleDensity : (isLowEnd ? 30 : 80);
    const n = Math.round(density);
    particles = Array.from({length:n}, ()=>({
      x: Math.random()*innerWidth, y: Math.random()*innerHeight,
      vx:(Math.random()-.5)*0.4, vy:(Math.random()-.5)*0.4,
      r:Math.random()*2+1, c: colors[(Math.random()*colors.length)|0],
      a: Math.random()*Math.PI*2
    }));
  }
  rebuild();
  let mouse = { x:-9999, y:-9999, click:0 };
  addEventListener("mousemove", (e)=>{ mouse.x=e.clientX; mouse.y=e.clientY; });
  addEventListener("click", (e)=>{
  for (let i=0;i<10;i++) particles.push({ x:e.clientX, y:e.clientY, vx:(Math.random()-.5)*6, vy:(Math.random()-.5)*6, r:Math.random()*2+1, c:"rgba(79,168,255,", a:0, life:60 });
  });
  function frame(){
    ctx.fillStyle = "rgba(3,3,10,0.15)"; ctx.fillRect(0,0,innerWidth,innerHeight);
    for (let i=0;i<particles.length;i++){
      const p = particles[i];
      // mouse repulsion
      const dx = p.x - mouse.x, dy = p.y - mouse.y; const d2 = dx*dx + dy*dy;
      if (d2 < 10000){ const f = (10000 - d2)/10000 * 0.4; const dist = Math.sqrt(d2)||1; p.vx += (dx/dist)*f*0.05; p.vy += (dy/dist)*f*0.05; }
      p.x += p.vx; p.y += p.vy; p.a += 0.04;
      if (p.x<0||p.x>innerWidth) p.vx*=-1;
      if (p.y<0||p.y>innerHeight) p.vy*=-1;
      const op = (Math.sin(p.a)*0.25 + 0.55);
      ctx.beginPath(); ctx.fillStyle = p.c+op+")"; ctx.arc(p.x,p.y,p.r,0,Math.PI*2); ctx.fill();
      if (p.life){ p.life--; if (p.life<=0){ particles.splice(i,1); i--; continue; } }
      // constellation
      for (let j=i+1;j<particles.length;j++){
        const q = particles[j]; const ddx=p.x-q.x, ddy=p.y-q.y; const dd=ddx*ddx+ddy*ddy;
        if (dd < 14400){ const o = (1-dd/14400)*0.18; ctx.strokeStyle = "rgba(79,168,255,"+o+")"; ctx.lineWidth=1; ctx.beginPath(); ctx.moveTo(p.x,p.y); ctx.lineTo(q.x,q.y); ctx.stroke(); }
      }
    }
    requestAnimationFrame(frame);
  }
  frame();
  return { rebuild };
}

/* ---------- Clerk auth (with fallback for invalid keys) ---------- */
async function loadClerk(){
  const pk = window.__CLERK_PK__;
  // Skip Clerk loading if key is empty or missing
  if (!pk || pk.trim() === "") { 
    console.log("Clerk disabled (no key configured)"); 
    return null; 
  }
  return new Promise((resolve)=>{
    let frontend;
    try{ 
      frontend = atob(pk.split("_")[2].replace(/-/g,"+").replace(/_/g,"/")).replace(/[$]/g,""); 
      if (!frontend || !frontend.includes("clerk")) throw new Error("Invalid Clerk key format");
    }catch(e){ 
      console.warn("Invalid Clerk key:", e.message, "- proceeding without auth"); 
      resolve(null); 
      return; 
    }
    const s = document.createElement("script");
    s.src = "https://" + frontend + "/npm/@clerk/clerk-js@5/dist/clerk.browser.js";
    s.async = true; s.crossOrigin = "anonymous"; s.setAttribute("data-clerk-publishable-key", pk);
    s.onload = async ()=>{
      try{
        const Clerk = window.Clerk;
        if (!Clerk) throw new Error("Clerk not loaded");
        await Clerk.load({ appearance:{ baseTheme: undefined, variables:{ colorPrimary:"#00f5ff", colorBackground:"#07070f", colorText:"#fff", colorInputBackground:"#0d0d1a", colorInputText:"#fff", borderRadius:"14px", fontFamily:"DM Sans, system-ui, sans-serif" }, elements:{ card:{ background:"#07070f", border:"1px solid rgba(255,255,255,0.1)" } } } });
        resolve(Clerk);
      } catch(e){ console.warn("Clerk failed:", e.message); resolve(null); }
    };
    s.onerror = ()=>{ console.warn("Clerk script failed to load"); resolve(null); };
    document.head.appendChild(s);
  });
}

/* ---------- Router ---------- */
const routes = ["/", "/dashboard", "/profile", "/keys", "/analytics", "/activity", "/settings", "/docs", "/status", "/integrations", "/changelog", "/admin"];
function navigate(p){ if (location.hash !== "#"+p) location.hash = "#"+p; else render(); }
addEventListener("hashchange", ()=>{ state.route = location.hash.slice(1) || "/"; render(); });

const PROTECTED = ["/dashboard","/profile","/keys","/analytics","/activity","/settings","/admin"];
async function render(){
  const app = document.getElementById("app");
  const cur = app.firstElementChild;
  const r = state.route;
  if (PROTECTED.includes(r) && !(state.clerk && state.clerk.user)){
    if (state.clerk) state.clerk.openSignIn({ afterSignInUrl: "#"+r, afterSignUpUrl:"#"+r });
    state.route = "/"; location.hash = "#/";
    return;
  }
  if (r === "/admin" && !state.isAdmin){
    toast("error","Admin access required.");
    state.route = "/dashboard"; location.hash = "#/dashboard";
    return;
  }
  const next = await viewFor(r);
  if (cur){ cur.classList.add("out"); await new Promise(rz=> setTimeout(rz, 180)); cur.remove(); }
  app.appendChild(next);
  setTimeout(()=> next.classList.remove("out"), 0);
  // active nav
  $$("[data-nav]").forEach(a=> a.classList.toggle("active", a.dataset.nav === r));
  // bind 3D tilt + magnetic on whatever was just rendered
  setTimeout(()=>{ bindTilt(next); next.querySelectorAll(".btn-primary").forEach(magnetize); }, 60);
  window.scrollTo({ top:0, behavior:"instant" });
}
async function viewFor(r){
  const wrap = document.createElement("div");
  wrap.className = "view";
  if (r === "/")               wrap.appendChild(await renderLanding());
  else if (r === "/dashboard") wrap.appendChild(await renderDashboard());
  else if (r === "/profile")   wrap.appendChild(await renderProfile());
  else if (r === "/keys")      wrap.appendChild(await renderKeys());
  else if (r === "/analytics") wrap.appendChild(await renderAnalytics());
  else if (r === "/activity")  wrap.appendChild(await renderActivity());
  else if (r === "/settings")  wrap.appendChild(await renderSettings());
  else if (r === "/docs")      wrap.appendChild(await renderDocs());
  else if (r === "/status")    wrap.appendChild(await renderStatus());
  else if (r === "/integrations") wrap.appendChild(await renderIntegrations());
  else if (r === "/changelog") wrap.appendChild(await renderChangelog());
  else if (r === "/admin")     wrap.appendChild(await renderAdmin());
  else                          wrap.appendChild(notFound());
  return wrap;
}
function notFound(){
  const e = h("div",{class:"container",style:"padding:140px 0;text-align:center"});
  e.innerHTML = '<div class="caption">404 / Out of bounds</div><h1 class="h1 gradient-text" style="margin:16px 0">VOID.</h1><p class="text-dim">This route does not exist.</p><div style="margin-top:24px"><a href="#/" class="btn btn-primary" data-testid="404-home">Return Home</a></div>';
  return e;
}

/* ---------- Number counter ---------- */
function counter(el, target, ms, suffix){
  ms = ms || 1100; suffix = suffix || "";
  const start = performance.now(); const v0 = 0;
  function step(t){ const k = clamp((t-start)/ms, 0, 1); const eased = 1 - Math.pow(1-k, 3); const cur = v0 + (target-v0)*eased;
    el.textContent = (Number.isInteger(target) ? Math.round(cur).toLocaleString() : cur.toFixed(2)) + suffix;
    if (k<1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* ---------- Magnetic button ---------- */
function magnetize(el){
  el.addEventListener("mousemove",(e)=>{
    const r = el.getBoundingClientRect();
    const dx = (e.clientX - (r.left+r.width/2)); const dy = (e.clientY - (r.top+r.height/2));
    const d = Math.hypot(dx,dy); if (d>80){ el.style.transform=""; return; }
    el.style.transform = "translate("+(dx*0.18)+"px,"+(dy*0.18)+"px)";
  });
  el.addEventListener("mouseleave", ()=> el.style.transform = "");
}

/* ---------- Sidebar (dashboard shell) ---------- */
function dashShell(content){
  const root = h("div",{ class:"app-shell"+(state.collapsed?" collapsed":""), id:"app-shell" });
  const links = [
    ["/dashboard","i-grid","Dashboard"],
    ["/profile","i-user","Profile"],
    ["/keys","i-key","API Keys"],
    ["/analytics","i-chart","Analytics"],
    ["/activity","i-activity","Activity"],
    ["/integrations","i-zap","Integrations"],
    ["/settings","i-settings","Settings"],
    ["/docs","i-code","Docs"],
    ["/changelog","i-sparkles","Changelog"],
    ["/status","i-cpu","Status"]
  ];
  if (state.isAdmin) links.push(["/admin","i-shield","Admin"]);
  const u = state.user || {};
  const initials = ((u.firstName||u.email||"U").charAt(0) + (u.lastName ? u.lastName.charAt(0):"")).toUpperCase();
  const sb = h("aside",{ class:"sidebar", "data-testid":"sidebar" });
  let html =
    '<div class="sb-logo"><div class="logo-mark"></div><span>VOID</span><button class="btn-icon sb-collapse-toggle" id="sb-toggle" data-testid="sb-toggle" aria-label="collapse"><svg class="icon"><use href="#i-menu"/></svg></button></div>'+
    '<div class="sb-nav">';
  for (const [p,i,l] of links){ html += '<a href="#'+p+'" class="sb-link" data-nav="'+p+'" data-testid="nav-'+p.slice(1)+'"><svg class="icon"><use href="#'+i+'"/></svg><span>'+l+'</span></a>'; }
  html += '</div>'+
    '<div class="sb-bot">'+
      '<div class="sb-session"><span class="live"></span><span id="session-timer">Active 0m</span></div>'+
      '<div class="sb-user"><div class="avatar">'+escapeHtml(initials)+'</div><div class="meta"><div class="name">'+escapeHtml(u.firstName||u.email||"User")+'</div><div class="email">'+escapeHtml(u.email||"")+'</div></div><button class="btn-icon" id="signout-btn" data-testid="signout-btn" aria-label="sign out"><svg class="icon"><use href="#i-logout"/></svg></button></div>'+
    '</div>';
  sb.innerHTML = html;
  const main = h("main",{ class:"main", "data-testid":"main-content" });
  // topbar
  const top = h("div",{ class:"topbar" });
  const unread = state.notifications.filter(n=>!n.read).length;
  top.innerHTML =
    '<div class="search" data-testid="topbar-search"><svg class="icon"><use href="#i-search"/></svg><input id="top-search" placeholder="Search…" /><kbd>Ctrl K</kbd></div>'+
    '<div class="topbar-actions">'+
      '<button class="btn-icon bell-wrap" id="bell-btn" data-testid="bell-btn" aria-label="notifications"><svg class="icon"><use href="#i-bell"/></svg>'+(unread?'<span class="bell-badge">'+unread+'</span>':'')+'</button>'+
      '<button class="btn-icon" id="palette-btn" data-testid="palette-btn" aria-label="command palette"><svg class="icon"><use href="#i-sparkles"/></svg></button>'+
      '<button class="btn-icon" id="quick-help" data-testid="quick-help" aria-label="help"><svg class="icon"><use href="#i-terminal"/></svg></button>'+
    '</div>';
  main.appendChild(top);
  main.appendChild(content);
  root.appendChild(sb);
  root.appendChild(main);

  // wire sidebar
  setTimeout(()=>{
    const sbToggle = sb.querySelector("#sb-toggle");
    if (sbToggle) sbToggle.onclick = ()=>{ state.collapsed = !state.collapsed; localStorage.setItem("sb-collapsed", state.collapsed?"1":"0"); $("#app-shell").classList.toggle("collapsed", state.collapsed); };
    const signoutBtn = sb.querySelector("#signout-btn");
    if (signoutBtn) signoutBtn.onclick = async ()=>{ if (state.clerk) await state.clerk.signOut(); state.user=null; navigate("/"); };
    const bellBtn = top.querySelector("#bell-btn");
    if (bellBtn) bellBtn.onclick = openDrawer;
    const paletteBtn = top.querySelector("#palette-btn");
    if (paletteBtn) paletteBtn.onclick = openPalette;
    const quickHelp = top.querySelector("#quick-help");
    if (quickHelp) quickHelp.onclick = openShortcuts;
    const topSearch = top.querySelector("#top-search");
    if (topSearch) topSearch.addEventListener("focus", openPalette);
  }, 0);
  return root;
}

/* ---------- Page: Landing ---------- */
async function renderLanding(){
  const root = h("div");
  // navbar
  root.appendChild(h("nav",{ class:"navbar", "data-testid":"navbar", html:
    '<div class="container nav-inner">'+
      '<a href="#/" class="logo" data-testid="logo"><div class="logo-mark"></div>Void<span class="text-cyan">/</span>Interface</a>'+
      '<div class="nav-links">'+
        '<a href="#features">Features</a><a href="#how">How it works</a><a href="#/integrations">Integrations</a><a href="#pricing">Pricing</a>'+
        '<a href="#/docs">Docs</a><a href="#/changelog">Changelog</a><a href="#/status">Status</a>'+
      '</div>'+
      '<div class="nav-cta"><button class="btn btn-ghost" data-testid="nav-signin" id="nav-signin">Sign In</button><button class="btn btn-primary" data-testid="nav-signup" id="nav-signup">Get Started <svg class="icon" width="14" height="14"><use href="#i-arrow-right"/></svg></button></div>'+
    '</div>'
  }));

  // hero
  root.appendChild(h("section",{ class:"hero", "data-testid":"hero", html:
    '<div class="caption" style="margin-bottom:18px">krix_ishere stack · v2 · Cloudflare Workers + Clerk + KV</div>'+
    '<h1 class="h1 hero-glitch glitch" data-text="BUILD. SHIP. SCALE."><span class="word">BUILD.</span> <span class="word">SHIP.</span> <span class="word">SCALE.</span></h1>'+
    '<div class="hero-sub" data-testid="hero-typer"><span id="typer"></span><span class="typer-cursor"></span></div>'+
    '<div class="hero-cta">'+
      '<button class="btn btn-primary" data-testid="hero-cta-primary" id="hero-cta-primary">Start Building <svg class="icon" width="14" height="14"><use href="#i-arrow-right"/></svg></button>'+
      '<a href="#/docs" class="btn btn-ghost" data-testid="hero-cta-docs"><svg class="icon" width="14" height="14"><use href="#i-code"/></svg> Read Docs</a>'+
    '</div>'+
    '<div class="hero-stats">'+
      '<div class="hero-stat"><div class="num" data-count="300">0</div><div class="lbl">Edge locations</div></div>'+
      '<div class="hero-stat"><div class="num" data-count="0" data-suffix="ms">0</div><div class="lbl">Cold starts</div></div>'+
      '<div class="hero-stat"><div class="num" data-count="99" data-suffix="%">0</div><div class="lbl">Uptime SLA</div></div>'+
      '<div class="hero-stat"><div class="num" data-count="10" data-suffix="ms">0</div><div class="lbl">Avg latency</div></div>'+
    '</div>'+
    '<div class="scroll-chev" aria-hidden="true">⌄</div>'
  }));

  // marquee
  const items = ["10ms avg latency","300+ edge locations","99.99% uptime","Clerk Auth built-in","Zero config deploys","Single file deploy","Global edge network","Crystalline DX"];
  let mar = '<div class="marquee-track">';
  for (let i=0;i<2;i++) for (const it of items) mar += '<div class="marquee-item">'+it+'<span class="dot">·</span></div>';
  mar += '</div>';
  root.appendChild(h("div",{ class:"marquee", "data-testid":"marquee", html: mar }));

  // customer logos strip
  const logos = ["acme","stellar","obelisk","hyperion","monolith","drift","nimbus","prism","atlas","vortex","quasar","helix"];
  let lg = '<div class="logos-grid">';
  for (const n of logos.slice(0,6)) lg += '<a class="logo-mark-text" href="#"><span class="dot"></span>'+n+'</a>';
  lg += '</div>';
  root.appendChild(h("div",{ class:"logos-strip", "data-testid":"logos-strip", html:
    '<div class="container"><div class="label">Trusted by teams shipping at the edge</div>'+lg+'</div>'
  }));

  // features
  const features = [
    ["i-zap","Zero Cold Start","Workers boot in <5ms because they never sleep. Your APIs feel instant on every continent."],
    ["i-shield","Clerk Auth Built-In","Drop in social login, MFA, and session management. Theme matches the void."],
    ["i-database","Edge KV Storage","Read-replicated key/value across 300+ POPs. Sub-3ms reads from any region."],
    ["i-globe","Global by Default","One deploy, served from the closest edge to every user. No region picking."],
    ["i-cpu","Single File","Your entire app — HTML, CSS, JS, API — embedded in one worker.js. Deploy in seconds."],
    ["i-sparkles","Crafted UX","Custom cursor, particles, glitch text, magnetic buttons. Pixel-precise."],
  ];
  let fg = '';
  for (const [i,t,d] of features){
    fg += '<div class="feature-card" data-testid="feature-card"><div class="icon-wrap"><svg class="icon lg"><use href="#'+i+'"/></svg></div><h3>'+t+'</h3><p>'+d+'</p><div class="more">→ Learn more</div></div>';
  }
  root.appendChild(h("section",{ id:"features", html:
    '<div class="container"><div class="section-tag"><span class="text-cyan">●</span> Capabilities</div><h2 class="section-title">Edge-native by design.</h2><p class="section-sub">Every primitive — auth, KV, analytics — is colocated milliseconds from your users.</p><div class="feature-grid">'+fg+'</div></div>'
  }));

  // how it works
  root.appendChild(h("section",{ id:"how", html:
    '<div class="container"><div class="section-tag"><span class="text-violet">●</span> Workflow</div><h2 class="section-title">Three steps, end to end.</h2><div class="steps">'+
    '<div class="step"><div class="step-num">01</div><h4>Deploy</h4><p>Push one file with <code>wrangler deploy</code>. Live globally in 12 seconds.</p></div>'+
    '<div class="step"><div class="step-num">02</div><h4>Configure</h4><p>Wire your Clerk publishable key + KV namespace. Done.</p></div>'+
    '<div class="step"><div class="step-num">03</div><h4>Ship</h4><p>Iterate live. Hot tail logs. Roll back in one command.</p></div>'+
    '</div></div>'
  }));

  // pricing
  root.appendChild(h("section",{ id:"pricing", html:
    '<div class="container"><div class="section-tag"><span class="text-pink">●</span> Pricing</div><h2 class="section-title">Free until you scale.</h2>'+
    '<div class="pricing">'+
      '<div class="price-card"><h3>Free</h3><div class="price">$0<small> /mo</small></div><ul><li>100k requests / day</li><li>1 GB KV storage</li><li>Clerk auth (5k MAU)</li><li>Community support</li></ul><button class="btn btn-ghost w-full" data-testid="price-free">Start free</button></div>'+
      '<div class="price-card featured"><div class="pop">Most Popular</div><h3>Pro</h3><div class="price">$19<small> /mo</small></div><ul><li>10M requests / day</li><li>50 GB KV storage</li><li>Clerk auth (unlimited)</li><li>Priority support</li><li>Webhook automations</li><li>Advanced analytics</li></ul><button class="btn btn-primary w-full" data-testid="price-pro">Upgrade <svg class="icon" width="14" height="14"><use href="#i-arrow-right"/></svg></button></div>'+
    '</div></div>'
  }));

  // testimonials
  root.appendChild(h("section",{ html:
    '<div class="container"><div class="section-tag"><span class="text-cyan">●</span> Loved by builders</div><h2 class="section-title">Shipping faster than ever.</h2>'+
    '<div class="testi">'+
      tcard("KX","krix_ishere","Founder","One worker.js. Ten pages. Zero compromises. The fastest dev loop I have ever shipped on.")+
      tcard("AT","Ada T.","Staff Eng","I replaced an entire backend with this. Cold starts are not a thing anymore.")+
      tcard("MV","Mira V.","Indie Hacker","The animations. The cursor. The vibe. Customers think we have a 30-person team.")+
    '</div></div>'
  }));

  // FAQ
  const qa = [
    ["What is Void Interface?","A single-file Cloudflare Worker template — auth, KV, ten pages, polished UX, zero build step."],
    ["How do I deploy?","wrangler kv namespace create, wrangler secret put CLERK_SECRET_KEY, wrangler deploy. Done."],
    ["Does it scale?","Cloudflare runs your code on 300+ edge nodes. Scaling is the default."],
    ["Can I customize the design?","Settings → Appearance lets you change accent color, font size, motion, particles, aurora intensity."],
    ["Is data private?","KV is namespaced per user via Clerk JWT subject. Nothing leaves your worker."]
  ];
  let faqHtml = '';
  for (const [q,a] of qa){
    faqHtml += '<div class="faq-item" data-testid="faq-item"><button class="faq-q">'+escapeHtml(q)+'<span class="chev">⌄</span></button><div class="faq-a"><div>'+escapeHtml(a)+'</div></div></div>';
  }
  root.appendChild(h("section",{ id:"faq", html:
    '<div class="container"><div class="section-tag"><span class="text-violet">●</span> Questions</div><h2 class="section-title">FAQ.</h2><div class="faq">'+faqHtml+'</div></div>'
  }));

  // footer
  root.appendChild(h("footer",{ html:
    '<div class="container"><div class="foot-grid">'+
      '<div><div class="logo"><div class="logo-mark"></div>Void Interface</div><p class="text-dim mt-3" style="font-size:13px;max-width:34ch">A single-file edge-native dashboard template. Built on Cloudflare Workers, secured by Clerk.</p>'+
      '<div class="socials"><a href="#" aria-label="GitHub"><svg class="icon"><use href="#i-code"/></svg></a><a href="#" aria-label="X"><svg class="icon"><use href="#i-zap"/></svg></a><a href="#" aria-label="Discord"><svg class="icon"><use href="#i-globe"/></svg></a></div></div>'+
      '<div class="foot-col"><h5>Product</h5><a href="#features">Features</a><a href="#pricing">Pricing</a><a href="#/integrations">Integrations</a><a href="#/docs">Docs</a><a href="#/changelog">Changelog</a><a href="#/status">Status</a></div>'+
      '<div class="foot-col"><h5>Company</h5><a href="#">About</a><a href="#">Blog</a><a href="#">Careers</a><a href="#">Contact</a></div>'+
      '<div class="foot-col"><h5>Legal</h5><a href="#">Privacy</a><a href="#">Terms</a><a href="#">Cookies</a><a href="#">Security</a></div>'+
    '</div><div class="foot-bottom"><div>© 2026 Void Interface · krix_ishere stack</div><div class="text-cyan">All systems operational</div></div></div>'
  }));

  // wire interactions after mount
  setTimeout(()=>{
    // typewriter
    const lines = ["Deploy to 300+ edge locations.","Zero cold starts.","Secured by Clerk.","Built on Cloudflare Workers."];
    const t = document.getElementById("typer");
    let li=0, ci=0, deleting=false;
    function tick(){
      if (!t) return;
      const cur = lines[li];
      if (!deleting){ ci++; t.textContent = cur.slice(0, ci); if (ci===cur.length){ deleting=true; setTimeout(tick, 1600); return; } }
      else { ci--; t.textContent = cur.slice(0, ci); if (ci===0){ deleting=false; li=(li+1)%lines.length; } }
      setTimeout(tick, deleting?30:55);
    }
    setTimeout(tick, 760);

    // counters
    $$("[data-count]").forEach(el=> onceVisible(el, ()=> counter(el, +el.dataset.count, 1100, el.dataset.suffix||"")));
    $$(".feature-card").forEach((el,i)=> onceVisible(el, ()=> { setTimeout(()=> el.classList.add("in"), i*80); }));

    // 3D tilt
    bindTilt();
    
    // FAQ accordion
    $$(".faq-item").forEach(it=> { const q = it.querySelector(".faq-q"); if (q) q.onclick = ()=> it.classList.toggle("open"); });

    // Bezpieczna obsługa logowania/rejestracji za pomocą Hosted Pages
    const handleAuth = (isSignUp = false) => {
      if (!state.clerk) {
        toast("error", "Logowanie niedostępne: sprawdź CLERK_PUBLISHABLE_KEY w konfiguracji.");
        return;
      }
      
      const dashUrl = window.location.href.split('#')[0] + "#/dashboard";
      
      try {
        if (isSignUp) {
          state.clerk.redirectToSignUp({ returnBackUrl: dashUrl });
        } else {
          state.clerk.redirectToSignIn({ returnBackUrl: dashUrl });
        }
      } catch (err) {
        toast("error", "Wystąpił krytyczny błąd uruchamiania Clerka.");
      }
    };

    const navSignin = document.getElementById("nav-signin");
    if (navSignin) navSignin.onclick = () => handleAuth(false);

    const navSignup = document.getElementById("nav-signup");
    if (navSignup) navSignup.onclick = () => handleAuth(true);

    const heroCta = document.getElementById("hero-cta-primary");
    if (heroCta) heroCta.onclick = () => handleAuth(true);

    // ripples + magnetic disabled for performance
    // $$(".btn").forEach(b=> b.addEventListener("click",(e)=>{ const r=b.getBoundingClientRect(); const sp=h("span",{class:"ripple"}); sp.style.left=(e.clientX-r.left)+"px"; sp.style.top=(e.clientY-r.top)+"px"; sp.style.width=sp.style.height="20px"; b.appendChild(sp); setTimeout(()=>sp.remove(),650); }));
    // $$(".btn-primary").forEach(magnetize);
  }, 30);

  return root;
}
function tcard(initials,name,role,quote){
  return '<div class="testi-card"><div class="stars">'+("★".repeat(5))+'</div><blockquote>"'+escapeHtml(quote)+'"</blockquote><div class="testi-author"><div class="avatar">'+escapeHtml(initials)+'</div><div><div style="font-size:13px;font-weight:600">'+escapeHtml(name)+'</div><div class="text-faint" style="font-size:11px">'+escapeHtml(role)+'</div></div></div></div>';
}

/* ---------- Page: Dashboard ---------- */
async function renderDashboard(){
  const inner = h("div");
  // welcome banner
  const u = state.user || {};
  const bn = h("div",{ class:"welcome", "data-testid":"welcome", html:
    '<h2>🌌 Welcome back, <span class="gradient-text">'+escapeHtml(u.firstName||u.email||"friend")+'</span></h2>'+
    '<p>Last seen: <span class="text-cyan">'+fmt.rel(state.sessionStart-7200000)+'</span> · Edge POP <span class="text-violet">'+escapeHtml((state.user&&state.user.geoColo)||"???")+'</span></p>'
  });
  inner.appendChild(bn);

  // stats
  const me = await api("/api/me").catch(()=>null);
  state.user = Object.assign({}, state.user, me ? me.user : {}, { geoColo: me ? me.geo.colo : "???" });
  if (me) state.settings = me.settings;
  const an = await api("/api/analytics").catch(()=>({days:[],byMethod:{},byStatus:{}}));
  const today = an.days.length ? an.days[an.days.length-1] : { requests:0, errors:0 };
  const totalReq = an.days.reduce((a,d)=>a+(d.requests||0),0);
  const stats = h("div",{ class:"stats-row" });
  stats.innerHTML =
    sCard("API Keys", me ? me.keyCount : 0, "↑ 12%", "up", "i-key")+
    sCard("Requests Today", today.requests||0, "↑ 8%", "up", "i-zap")+
    sCard("Plan", "PRO", "Active", "up", "i-star", true)+
    sCard("Avg Response", "8ms", "↓ 2ms", "up", "i-cpu");
  inner.appendChild(stats);

  // split: chart + health rings
  const split = h("div",{ class:"split-2" });
  const chartCard = h("div",{ class:"card" });
  chartCard.innerHTML = '<h3><svg class="icon"><use href="#i-chart"/></svg> Requests · last 7 days</h3><canvas id="spark" height="160" style="width:100%;height:160px"></canvas>';
  const ringsCard = h("div",{ class:"card" });
  ringsCard.innerHTML = '<h3><svg class="icon"><use href="#i-cpu"/></svg> System Health</h3><div class="health" id="rings"></div>';
  split.append(chartCard, ringsCard);
  inner.appendChild(split);

  // quick actions
  const qa = h("div",{ class:"qa-grid", "data-testid":"quick-actions" });
  qa.innerHTML =
    '<button class="qa" data-testid="qa-newkey" onclick="location.hash=\\'#/keys\\'"><div class="icon-wrap"><svg class="icon lg"><use href="#i-plus"/></svg></div><div><h4>New API Key</h4><p>Provision a fresh secret in seconds.</p></div></button>'+
    '<button class="qa" data-testid="qa-analytics" onclick="location.hash=\\'#/analytics\\'"><div class="icon-wrap"><svg class="icon lg"><use href="#i-chart"/></svg></div><div><h4>Open Analytics</h4><p>Drill into requests, errors, geo.</p></div></button>'+
    '<button class="qa" data-testid="qa-activity" onclick="location.hash=\\'#/activity\\'"><div class="icon-wrap"><svg class="icon lg"><use href="#i-terminal"/></svg></div><div><h4>Live Activity</h4><p>Tail every API call, in real time.</p></div></button>'+
    '<button class="qa" data-testid="qa-settings" onclick="location.hash=\\'#/settings\\'"><div class="icon-wrap"><svg class="icon lg"><use href="#i-settings"/></svg></div><div><h4>Customize</h4><p>Tune theme, motion, sound.</p></div></button>';
  inner.appendChild(qa);

  // terminal feed
  const term = h("div",{ class:"card mt-6" });
  term.innerHTML = '<div class="terminal" id="term-feed" data-testid="activity-feed"><div class="term-head"><span>SYSTEM LOG</span><span class="live">LIVE</span></div><div id="term-lines"></div><div class="text-faint"><span class="term-cursor"></span></div></div>';
  inner.appendChild(term);

  // wire
  setTimeout(async ()=>{
    // counters
    $$("[data-stat-num]").forEach(el=>{
      const v = +el.dataset.statNum; const suf = el.dataset.suffix||"";
      if (Number.isFinite(v)) counter(el, v, 1100, suf);
      else el.textContent = el.dataset.statText || "—";
    });
    drawSparkline(document.getElementById("spark"), an.days.map(d=>d.requests||Math.round(Math.random()*30)));
    drawRings(document.getElementById("rings"), [{label:"CPU",val:42,cls:""},{label:"Memory",val:67,cls:"violet"},{label:"KV Ops",val:89,cls:"green"}]);
    const logs = (await api("/api/activity").catch(()=>({logs:[]}))).logs;
    const tl = document.getElementById("term-lines");
    const list = (logs.length ? logs : sampleLogs()).slice(0, 8);
    list.forEach(l=> tl.appendChild(termLine(l)));
  }, 30);

  return dashShell(inner);
}
function sCard(label, val, trend, dir, icon, isText){
  const isStr = typeof val !== "number";
  return '<div class="stat-card" data-testid="stat-card">'+
    '<div class="lbl flex items-center gap-2"><svg class="icon sm"><use href="#'+icon+'"/></svg> '+label+'</div>'+
    '<div class="val" data-stat-num="'+(isStr ? "" : val)+'" data-stat-text="'+(isStr ? escapeHtml(val):"")+'" '+(label==="Avg Response"?'data-suffix="ms"':"")+'>'+(isStr?escapeHtml(val):"0")+'</div>'+
    '<div class="trend '+dir+'">'+escapeHtml(trend)+'</div>'+
  '</div>';
}
function termLine(l){
  const ok = (l.status||200) < 400;
  const e = h("div",{ class:"term-line" });
  e.innerHTML =
    '<span class="ts">['+fmt.time(l.ts||Date.now())+']</span>'+
    '<span class="'+(ok?"ok":"err")+'">'+(ok?"✓":"✗")+'</span>'+
    '<span class="method '+(l.method||"GET")+'">'+(l.method||"GET")+'</span>'+
    '<span>'+escapeHtml(l.path||"/api/me")+'</span>'+
    '<span class="'+(ok?"ok":"err")+'">'+(l.status||200)+' · '+((l.latency||1+Math.random()*15)|0)+'ms · '+(l.country||"PL")+'</span>';
  return e;
}
function sampleLogs(){
  const methods = ["GET","POST","PATCH","DELETE","AUTH"];
  const paths = ["/api/me","/api/keys","/api/activity","/api/settings","/api/analytics","/api/notifications"];
  const out = [];
  for (let i=0;i<8;i++) out.push({ ts:Date.now()-i*40000, method:methods[i%5], path:paths[i%paths.length], status:i===2?404:200, latency:1+(Math.random()*20)|0, country:"PL" });
  return out;
}


/* ---------- Charts ---------- */
function drawSparkline(canvas, data){
  if (!canvas) return;
  const dpr = devicePixelRatio || 1;
  const w = canvas.clientWidth, hh = canvas.clientHeight;
  canvas.width = w*dpr; canvas.height = hh*dpr;
  const ctx = canvas.getContext("2d"); ctx.scale(dpr, dpr);
  if (!data || !data.length) data = Array.from({length:7},()=>Math.round(5+Math.random()*40));
  const max = Math.max(...data, 1);
  const pad = 24;
  const step = (w - pad*2) / Math.max(1, (data.length-1));
  // animated draw
  let frame = 0; const total = 60;
  function tick(){
    ctx.clearRect(0,0,w,hh);
    // grid
    ctx.strokeStyle = "rgba(255,255,255,0.05)"; ctx.lineWidth = 1;
    for (let i=0;i<4;i++){ const y = pad + (hh-pad*2)*i/3; ctx.beginPath(); ctx.moveTo(pad,y); ctx.lineTo(w-pad,y); ctx.stroke(); }
    // path
    const k = clamp(frame/total, 0, 1);
    const pts = data.map((v,i)=>[pad + i*step, hh - pad - (v/max)*(hh - pad*2)]);
    const showCount = Math.max(2, Math.ceil(pts.length * k));
    const visible = pts.slice(0, showCount);
    // area
    const grad = ctx.createLinearGradient(0,0,0,hh); grad.addColorStop(0,"rgba(79,168,255,0.32)"); grad.addColorStop(1,"rgba(46,125,255,0.00)");
    ctx.fillStyle = grad; ctx.beginPath(); ctx.moveTo(visible[0][0], hh-pad);
    visible.forEach(p=> ctx.lineTo(p[0], p[1])); ctx.lineTo(visible[visible.length-1][0], hh-pad); ctx.closePath(); ctx.fill();
    // line
    ctx.strokeStyle = "#4fa8ff"; ctx.lineWidth = 2; ctx.beginPath(); visible.forEach((p,i)=> i ? ctx.lineTo(p[0],p[1]) : ctx.moveTo(p[0],p[1])); ctx.stroke();
    // dots
    ctx.fillStyle = "#2e7dff"; visible.forEach(p=>{ ctx.beginPath(); ctx.arc(p[0],p[1],3,0,Math.PI*2); ctx.fill(); });
    if (k < 1){ frame++; requestAnimationFrame(tick); }
  }
  tick();
}
function drawRings(host, items){
  if (!host) return;
  host.innerHTML = items.map(it=>{
    const c = 2*Math.PI*40;
    return '<div class="ring '+(it.cls||"")+'"><svg viewBox="0 0 100 100"><circle class="bg-circle" cx="50" cy="50" r="40"/><circle class="fg-circle" cx="50" cy="50" r="40" stroke-dasharray="'+c.toFixed(2)+'" stroke-dashoffset="'+c.toFixed(2)+'" data-target="'+(c-(c*it.val/100)).toFixed(2)+'"/></svg><div class="pct" data-pct="'+it.val+'">0%</div><div class="lbl">'+it.label+'</div></div>';
  }).join("");
  setTimeout(()=>{
    $$(".ring .fg-circle", host).forEach(el=> el.style.strokeDashoffset = el.dataset.target);
    $$(".pct", host).forEach(el=> counter(el, +el.dataset.pct, 1200, "%"));
  }, 100);
}
function drawDonut(canvas, segs){
  if (!canvas) return;
  const dpr = devicePixelRatio||1; const w = canvas.clientWidth, hh=canvas.clientHeight;
  canvas.width = w*dpr; canvas.height = hh*dpr;
  const ctx = canvas.getContext("2d"); ctx.scale(dpr,dpr);
  const cx = w/2, cy = hh/2, r = Math.min(w,hh)/2 - 12, rw = 18;
  const total = segs.reduce((a,s)=>a+s.value,0) || 1;
  let start = -Math.PI/2;
  segs.forEach((s,i)=>{
    const ang = (s.value/total) * Math.PI*2;
    setTimeout(()=>{
      let frame=0, totalF=30;
      function tick(){
        const k = clamp(frame/totalF,0,1);
        ctx.beginPath(); ctx.strokeStyle = s.color; ctx.lineWidth = rw; ctx.lineCap = "butt";
        ctx.arc(cx,cy,r,start, start+ang*k); ctx.stroke();
        if (k<1){ frame++; requestAnimationFrame(tick); }
        else start += ang;
      }
      tick();
    }, i*180);
  });
  // center label
  setTimeout(()=>{ ctx.fillStyle = "#fff"; ctx.font = "700 24px Syne"; ctx.textAlign="center"; ctx.textBaseline="middle"; ctx.fillText(fmt.num(total), cx, cy-6); ctx.font = "500 11px DM Sans"; ctx.fillStyle = "rgba(255,255,255,0.5)"; ctx.fillText("REQUESTS", cx, cy+14); }, 800);
}
function drawHistogram(canvas, buckets){
  if (!canvas) return;
  const dpr = devicePixelRatio||1; const w = canvas.clientWidth, hh=canvas.clientHeight;
  canvas.width = w*dpr; canvas.height = hh*dpr;
  const ctx = canvas.getContext("2d"); ctx.scale(dpr,dpr);
  const max = Math.max(...buckets.map(b=>b.v), 1);
  const pad = 36, gap = 10;
  const bw = (w - pad*2 - gap*(buckets.length-1)) / buckets.length;
  buckets.forEach((b,i)=>{
    const targetH = (b.v/max)*(hh - pad*2);
    const x = pad + i*(bw+gap);
    setTimeout(()=>{
      let f=0, T=24;
      function tick(){
        ctx.clearRect(x-2, 0, bw+4, hh);
        const grad = ctx.createLinearGradient(0,hh-pad,0,hh-pad-targetH); grad.addColorStop(0,"rgba(79,168,255,0.85)"); grad.addColorStop(1,"rgba(46,125,255,0.4)");
        ctx.fillStyle = grad; const ch = (targetH * f/T);
        ctx.fillRect(x, hh-pad-ch, bw, ch);
        ctx.fillStyle = "rgba(255,255,255,0.5)"; ctx.font = "500 10px IBM Plex Mono"; ctx.textAlign="center";
        ctx.fillText(b.l, x+bw/2, hh-pad+14);
        ctx.fillText(b.v, x+bw/2, hh-pad-ch-6);
        if (f<T){ f++; requestAnimationFrame(tick); }
      }
      tick();
    }, i*70);
  });
}

/* ---------- World map (dot grid, 64 cities) ---------- */
const CITY_DOTS = [
  [240,180,"NYC"],[260,190,"BOS"],[220,195,"CHI"],[200,210,"DAL"],[180,195,"SFO"],[170,210,"LAX"],
  [310,195,"LON"],[330,200,"PAR"],[345,195,"AMS"],[360,205,"FRA"],[365,215,"WAW"],[370,210,"BER"],
  [385,215,"IST"],[400,225,"DXB"],[420,230,"BLR"],[435,225,"DEL"],[460,235,"BKK"],[475,225,"HKG"],[480,215,"TYO"],
  [495,225,"SIN"],[505,265,"SYD"],[510,245,"AKL"],[260,260,"GRU"],[270,275,"BUE"],[170,260,"LIM"],
  [320,225,"MAD"],[340,230,"ROM"],[355,235,"ATH"],[290,255,"LOS"],[330,260,"NBO"],[345,265,"JNB"],
  [400,200,"MOW"],[420,200,"NSK"],[455,210,"PEK"],[465,220,"SHA"],[460,200,"ICN"],[455,230,"KUL"],
  [225,235,"MIA"],[245,240,"HAV"],[250,225,"ATL"],[200,180,"YVR"],[225,180,"YYZ"],[210,185,"DEN"],
  [195,205,"PHX"],[205,225,"MEX"],[195,245,"BOG"],[290,240,"DAK"],[305,245,"CMN"],[315,250,"ALG"],
  [410,240,"BOM"],[440,250,"CMB"],[450,255,"MAA"],[470,265,"JKT"],[485,255,"MNL"],[490,235,"TPE"],
  [375,225,"CAI"],[390,230,"RUH"],[395,235,"DOH"],[300,210,"DUB"],[315,205,"OSL"],[330,210,"CPH"],
  [350,210,"PRG"],[368,205,"VIE"],[380,210,"BUD"]
];
function renderWorld(host, hits){
  if (!host) return;
  const w = 600, hh = 300;
  const max = Math.max(1, ...Object.values(hits||{}));
  const dots = CITY_DOTS.map((p,i)=>{
    const v = ((hits && hits[p[2]]) || 0); const r = v ? 4 + Math.min(8, (v/max)*8) : 2;
    const cls = v ? "dot hot" : "dot";
    return '<circle class="'+cls+'" cx="'+p[0]+'" cy="'+p[1]+'" r="'+r+'" data-city="'+p[2]+'" data-count="'+v+'" style="opacity:0;animation:fade-in .4s ease '+(i*20)+'ms forwards"><title>'+p[2]+': '+v+' requests</title></circle>';
  }).join("");
  // background — simple latitude dots grid for atmosphere
  let grid = "";
  for (let x=20;x<w-20;x+=14) for (let y=160;y<260;y+=14){
    grid += '<circle cx="'+x+'" cy="'+y+'" r="0.8" fill="rgba(255,255,255,0.06)"/>';
  }
  host.innerHTML = '<div class="world" data-testid="world-map"><svg viewBox="0 0 '+w+' '+hh+'">'+grid+dots+'</svg></div>';
}

/* ---------- Page: Profile ---------- */
async function renderProfile(){
  const u = state.user || {};
  const initials = ((u.firstName||u.email||"U").charAt(0)+(u.lastName?u.lastName.charAt(0):"")).toUpperCase();
  const inner = h("div",{ class:"stagger" });
  inner.innerHTML =
    '<div class="card" style="display:flex;gap:24px;align-items:center;padding:32px"><div class="avatar-ring"><div class="avatar xl">'+escapeHtml(initials)+'</div></div>'+
    '<div style="flex:1"><div class="caption">Profile</div><h2 class="h2 gradient-text" id="profile-name" data-testid="profile-name">'+escapeHtml(u.firstName||u.email||"Anonymous")+'</h2><p class="text-dim mono mt-2">'+escapeHtml(u.email||"")+'</p>'+
    '<div class="flex gap-2 mt-3"><span class="pill cyan">Pro</span><span class="pill green">Verified</span><span class="pill violet">Edge POP '+escapeHtml(u.geoColo||"???")+'</span></div></div></div>'+

    '<div class="split-2 mt-6">'+
      '<div class="card"><h3>Account details</h3>'+
      '<div class="form-grid"><div class="field"><label>Display Name</label><input id="p-name" data-testid="p-name" value="'+escapeHtml(u.firstName||"")+'"/></div>'+
      '<div class="field"><label>Email</label><input value="'+escapeHtml(u.email||"")+'" disabled/></div>'+
      '<div class="field"><label>Website</label><input id="p-web" data-testid="p-web" placeholder="https://"/></div>'+
      '<div class="field"><label>Location</label><input id="p-loc" data-testid="p-loc" placeholder="Warsaw, PL"/></div></div>'+
      '<div class="field mt-4"><label>Bio <span id="bio-count" class="text-faint">0/150</span></label><textarea id="p-bio" data-testid="p-bio" maxlength="150" rows="3"></textarea></div>'+
      '<div class="mt-4"><button class="btn btn-primary" data-testid="save-profile" id="save-profile">Save Changes</button></div></div>'+

      '<div class="card"><h3>Linked accounts</h3>'+
      linkedAcc("Google","i-globe","green")+linkedAcc("GitHub","i-code","cyan")+linkedAcc("Discord","i-zap","violet")+
      '<h3 class="mt-6">Account stats</h3>'+
      '<div class="flex justify-between mt-2"><span class="text-dim">Keys created</span><span class="mono">'+state.keys.length+'</span></div>'+
      '<div class="flex justify-between mt-2"><span class="text-dim">Account age</span><span class="mono">'+Math.floor(Math.random()*180+20)+' days</span></div>'+
      '<div class="flex justify-between mt-2"><span class="text-dim">Sessions</span><span class="mono">3 active</span></div>'+
      '</div>'+
    '</div>'+

    '<div class="card mt-6" style="border-color:rgba(255,51,102,0.3)"><h3 class="text-red"><svg class="icon"><use href="#i-trash"/></svg> Danger zone</h3>'+
    '<p class="text-dim mt-2">Permanently delete this account and all associated KV data.</p>'+
    '<div class="flex gap-3 mt-4"><input id="del-confirm" data-testid="del-confirm" placeholder="Type DELETE to confirm" class="input" style="flex:1;padding:11px 14px;border-radius:10px;background:var(--surface);border:1px solid var(--border);color:#fff;font-family:var(--font-body)"/><button class="btn btn-danger" data-testid="delete-account" id="delete-account" disabled>Delete account</button></div></div>';

  setTimeout(()=>{
    const bio = $("#p-bio"); const bc = $("#bio-count");
    bio.addEventListener("input", ()=> bc.textContent = bio.value.length+"/150");
    const saveProfile = $("#save-profile");
    if (saveProfile) saveProfile.onclick = ()=> toast("success","Profile saved.");
    const dc = $("#del-confirm"); const da = $("#delete-account");
    dc.addEventListener("input", ()=> { da.disabled = dc.value !== "DELETE"; });
    if (da) da.onclick = ()=> toast("warning","Demo mode — deletion disabled.");
  }, 30);

  return dashShell(inner);
}
function linkedAcc(name,icon,clr){
  return '<div class="row mt-2"><div class="flex items-center gap-3"><div class="icon-wrap" style="width:36px;height:36px"><svg class="icon"><use href="#'+icon+'"/></svg></div><div><div style="font-weight:600">'+name+'</div><div class="text-faint text-xs">Not connected</div></div></div><button class="btn btn-ghost btn-sm">Connect</button></div>';
}

/* ---------- Page: API Keys ---------- */
async function renderKeys(){
  const inner = h("div",{ class:"stagger" });
  const data = await api("/api/keys").catch(()=>({keys:[]}));
  state.keys = data.keys;
  const total = state.keys.length;
  inner.innerHTML =
    '<div class="flex justify-between items-center" style="flex-wrap:wrap;gap:16px"><div><div class="caption">Credentials</div><h2 class="h2">API Keys</h2></div><button class="btn btn-primary" data-testid="new-key-btn" id="new-key-btn"><svg class="icon" width="14" height="14"><use href="#i-plus"/></svg> New key</button></div>'+
    '<div class="stats-row mt-6">'+
      sCard("Total", total, "All time", "up", "i-key")+
      sCard("Active", total, "Online", "up", "i-zap")+
      sCard("Expired", 0, "—", "up", "i-x")+
      sCard("Last 24h calls", 247, "↑ 18%", "up", "i-activity")+
    '</div>'+
    '<div class="card mt-6" id="new-key-panel" hidden><h3>Generate new key</h3>'+
    '<div class="form-grid"><div class="field"><label>Name</label><input id="nk-name" data-testid="nk-name" placeholder="Production API"/></div>'+
    '<div class="field"><label>Permissions</label><select id="nk-perm" data-testid="nk-perm"><option value="read">Read</option><option value="write" selected>Read &amp; Write</option><option value="admin">Admin</option></select></div>'+
    '<div class="field"><label>Expiry</label><select id="nk-exp" data-testid="nk-exp"><option value="never">Never</option><option value="30d">30 days</option><option value="90d">90 days</option><option value="1y">1 year</option></select></div>'+
    '<div class="field"><label>Tags</label><input id="nk-tags" data-testid="nk-tags" placeholder="prod, server, edge"/></div></div>'+
    '<div class="flex gap-3 mt-4"><button class="btn btn-primary" data-testid="generate-key" id="generate-key">Generate <svg class="icon" width="14" height="14"><use href="#i-zap"/></svg></button><button class="btn btn-ghost" id="cancel-key">Cancel</button></div></div>'+
    '<div id="key-list" class="mt-6 stagger" style="display:flex;flex-direction:column;gap:10px"></div>';

  setTimeout(()=>{
    const list = $("#key-list");
    if (!state.keys.length){
      list.innerHTML = '<div class="card text-faint" style="text-align:center;padding:60px">No keys yet. Generate your first one.</div>';
    } else {
      state.keys.forEach((k,i)=>{
        const row = h("div",{ class:"row", "data-testid":"key-row", "data-id":k.id, style:"animation-delay:"+(i*60)+"ms" });
        row.innerHTML =
          '<div class="flex items-center gap-3"><div class="icon-wrap" style="width:36px;height:36px;background:var(--cyan-dim)"><svg class="icon" style="stroke:var(--cyan)"><use href="#i-key"/></svg></div>'+
          '<div><div style="font-weight:600">'+escapeHtml(k.name)+'</div><div class="mono text-xs text-faint" data-key-show>'+escapeHtml(k.masked||"sk_live_••••••••••••")+'</div></div></div>'+
          '<div class="flex gap-2 items-center"><span class="pill '+(k.permissions==="admin"?"red":k.permissions==="write"?"violet":"cyan")+'">'+escapeHtml(k.permissions)+'</span>'+
          '<span class="text-faint text-xs">'+fmt.rel(k.createdAt)+'</span>'+
          '<button class="btn-icon" data-act="copy" data-testid="key-copy" aria-label="copy"><svg class="icon"><use href="#i-copy"/></svg></button>'+
          '<button class="btn-icon" data-act="reveal" data-testid="key-reveal" aria-label="reveal"><svg class="icon"><use href="#i-eye"/></svg></button>'+
          '<button class="btn-icon" data-act="delete" data-testid="key-delete" aria-label="delete"><svg class="icon"><use href="#i-trash"/></svg></button></div>';
        list.appendChild(row);
      });
    }

    const newKeyBtn = $("#new-key-btn");
    if (newKeyBtn) newKeyBtn.onclick = ()=> { const p = $("#new-key-panel"); p.hidden = !p.hidden; };
    const cancelKey = $("#cancel-key");
    if (cancelKey) cancelKey.onclick = ()=> $("#new-key-panel").hidden = true;
    const generateKey = $("#generate-key");
    if (generateKey) generateKey.onclick = async ()=>{
      const name = $("#nk-name").value || "Untitled";
      const permissions = $("#nk-perm").value;
      const expiry = $("#nk-exp").value;
      const tags = $("#nk-tags").value.split(",").map(s=>s.trim()).filter(Boolean);
      try{
        const res = await api("/api/keys", { method:"POST", body:{ name, permissions, expiry, tags }});
        toast("success","Key created.");
        if (res.isFirst) confetti();
        showRevealKey(res.key);
        renderKeys().then(v=>{ const a = $("#app"); a.firstChild.replaceWith(v); });
      } catch(e){ toast("error", e.message || "Failed"); }
    };

    list.addEventListener("click", async (e)=>{
      const btn = e.target.closest("[data-act]"); if (!btn) return;
      const row = btn.closest(".row"); const id = row.dataset.id;
      const k = state.keys.find(x=> x.id === id); if (!k) return;
      if (btn.dataset.act === "copy"){
        navigator.clipboard.writeText(k.masked).then(()=> toast("success","Copied masked key (real secret only shown on create)."));
      } else if (btn.dataset.act === "reveal"){
        const el = row.querySelector("[data-key-show]"); el.style.transition="transform .35s"; el.style.transform="rotateX(90deg)";
        setTimeout(()=>{ el.textContent = k.masked||"sk_live_•••••"; el.style.transform="rotateX(0)"; }, 200);
      } else if (btn.dataset.act === "delete"){
        row.classList.add("removing");
        const undo = toast("warning","Key deleted. Undo?", { duration:5000 });
        setTimeout(async ()=>{
          try{ await api("/api/keys/"+id, { method:"DELETE" }); state.keys = state.keys.filter(x=>x.id!==id); row.remove(); }
          catch(e){ toast("error","Delete failed"); row.classList.remove("removing"); }
        }, 300);
      }
    });
  }, 30);
  return dashShell(inner);
}
function showRevealKey(k){
  const back = h("div",{ class:"cmd-back open" });
  back.innerHTML = '<div class="cmd" style="padding:32px;border:1px solid var(--amber);width:min(560px,90vw)"><div class="caption text-amber">⚠ One-time secret — save it now</div><div class="mono mt-3" style="padding:14px;background:var(--void-3);border-radius:10px;font-size:14px;word-break:break-all" data-testid="reveal-secret">'+escapeHtml(k.secret)+'</div><div class="flex gap-3 mt-4"><button class="btn btn-primary" data-testid="copy-secret" id="copy-secret"><svg class="icon" width="14" height="14"><use href="#i-copy"/></svg> Copy</button><button class="btn btn-ghost" id="close-reveal">I have saved it</button></div></div>';
  document.body.appendChild(back);
  const copySecret = back.querySelector("#copy-secret");
  if (copySecret) copySecret.onclick = ()=>{ navigator.clipboard.writeText(k.secret); toast("success","Copied."); };
  const closeReveal = back.querySelector("#close-reveal");
  if (closeReveal) closeReveal.onclick = ()=> back.remove();
}
function confetti(){
  const c = h("canvas",{ style:"position:fixed;inset:0;z-index:1000;pointer-events:none" });
  document.body.appendChild(c);
  const ctx = c.getContext("2d"); c.width = innerWidth; c.height = innerHeight;
  const colors = ["#4fa8ff","#2e7dff","#a8ccff","#0048cc","#36d399"];
  const ps = Array.from({length:60},()=>({ x:innerWidth/2, y:innerHeight/2, vx:(Math.random()-.5)*16, vy:(Math.random()-.5)*16-4, r:4+Math.random()*6, c:colors[(Math.random()*colors.length)|0], rot:Math.random()*Math.PI, vr:(Math.random()-.5)*.4, life:120 }));
  function tick(){
    ctx.clearRect(0,0,c.width,c.height);
    let alive = 0;
    for (const p of ps){
      if (p.life<=0) continue; alive++;
      p.vy += 0.3; p.x += p.vx; p.y += p.vy; p.rot += p.vr; p.life--;
      ctx.save(); ctx.translate(p.x,p.y); ctx.rotate(p.rot); ctx.fillStyle = p.c; ctx.globalAlpha = clamp(p.life/120,0,1);
      ctx.fillRect(-p.r/2, -p.r/2, p.r, p.r); ctx.restore();
    }
    if (alive) requestAnimationFrame(tick); else c.remove();
  }
  tick();
}

/* ---------- Page: Analytics ---------- */
async function renderAnalytics(){
  const inner = h("div",{ class:"stagger" });
  const an = await api("/api/analytics").catch(()=>({days:[],byMethod:{},byStatus:{},byCountry:{}}));
  const totalReq = an.days.reduce((a,d)=>a+(d.requests||0),0);
  const totalErr = an.days.reduce((a,d)=>a+(d.errors||0),0);
  const today = an.days[an.days.length-1] || { requests:0, errors:0 };
  const successRate = totalReq ? ((1-totalErr/Math.max(1,totalReq))*100) : 99.94;
  inner.innerHTML =
    '<div class="caption">Insights</div><h2 class="h2">Analytics</h2>'+
    '<div class="stats-row mt-6">'+
      sCard("Requests", totalReq||1240, "↑ 12%", "up", "i-zap")+
      sCard("Today", today.requests||89, "↑ 4%", "up", "i-activity")+
      sCard("Success", successRate.toFixed(2)+"%", "↑ 0.02%", "up", "i-check")+
      sCard("Errors", totalErr||3, "↓ 1", "up", "i-x")+
    '</div>'+
    '<div class="split-2 mt-6">'+
      '<div class="card"><h3><svg class="icon"><use href="#i-chart"/></svg> Requests · 30 days</h3><canvas id="big-spark" height="280" style="width:100%;height:280px"></canvas></div>'+
      '<div class="card"><h3><svg class="icon"><use href="#i-globe"/></svg> By method</h3><canvas id="donut" height="280" style="width:100%;height:280px"></canvas><div id="donut-legend" class="flex gap-3 flex-wrap mt-3"></div></div>'+
    '</div>'+
    '<div class="card mt-6"><h3><svg class="icon"><use href="#i-globe"/></svg> Geo distribution</h3><div id="world-host"></div></div>'+
    '<div class="split-2 mt-6"><div class="card"><h3><svg class="icon"><use href="#i-cpu"/></svg> Response time</h3><canvas id="hist" height="240" style="width:100%;height:240px"></canvas></div>'+
    '<div class="card"><h3><svg class="icon"><use href="#i-x"/></svg> Recent errors</h3><div class="terminal" style="max-height:240px"><div id="err-list"></div></div></div></div>';

  setTimeout(()=>{
    drawSparkline($("#big-spark"), an.days.map(d=>d.requests||Math.round(20+Math.random()*100)));
    const colors = { GET:"#4fa8ff", POST:"#2e7dff", DELETE:"#ef4458", PATCH:"#a8ccff" };
    const segs = Object.entries(an.byMethod).filter(([k,v])=>v).map(([k,v])=>({ value:v, color:colors[k]||"#888", label:k }));
    if (!segs.length) ["GET","POST","DELETE","PATCH"].forEach(k=> segs.push({ value:Math.floor(Math.random()*40)+5, color:colors[k], label:k }));
    drawDonut($("#donut"), segs);
    $("#donut-legend").innerHTML = segs.map(s=>'<span class="pill" style="border-color:'+s.color+';color:'+s.color+'">●  '+s.label+': '+s.value+'</span>').join("");
    renderWorld($("#world-host"), an.byCountry||{ NYC:80, LON:60, WAW:40, TYO:30, SYD:20 });
    drawHistogram($("#hist"), [{l:"<10ms",v:120},{l:"10-25",v:80},{l:"25-50",v:30},{l:"50-100",v:8},{l:"100+",v:2}]);
    $("#err-list").innerHTML = '<div class="term-line"><span class="ts">[12:31:05]</span><span class="err">✗</span><span class="method GET">GET</span><span>/api/unknown</span><span class="err">404 · 3ms</span></div>'+
      '<div class="term-line text-faint" style="grid-template-columns:1fr">No more errors in last 24h.</div>';
  }, 30);

  return dashShell(inner);
}

/* ---------- Page: Activity ---------- */
async function renderActivity(){
  const inner = h("div",{ class:"stagger" });
  const data = await api("/api/activity").catch(()=>({logs:[]}));
  const logs = data.logs.length ? data.logs : sampleLogs();
  inner.innerHTML =
    '<div class="caption">Telemetry</div><h2 class="h2">Activity Logs</h2>'+
    '<div class="card mt-6"><div class="flex items-center justify-between mb-4 flex-wrap gap-3">'+
      '<div class="flex gap-2 flex-wrap" id="log-filters">'+
        '<button class="pill cyan" data-f="all" data-testid="filter-all">All</button>'+
        '<button class="pill" data-f="AUTH" data-testid="filter-auth">Auth</button>'+
        '<button class="pill" data-f="api" data-testid="filter-api">API</button>'+
        '<button class="pill" data-f="errors" data-testid="filter-errors">Errors</button>'+
      '</div>'+
      '<div class="flex gap-2"><input id="log-search" data-testid="log-search" placeholder="Search…" style="padding:8px 12px;border-radius:10px;background:var(--surface);border:1px solid var(--border);font-family:var(--font-body)"/>'+
      '<button class="btn btn-ghost btn-sm" id="log-pause" data-testid="log-pause">Pause</button>'+
      '<button class="btn btn-ghost btn-sm" id="log-clear" data-testid="log-clear">Clear</button>'+
      '<button class="btn btn-ghost btn-sm" id="log-export" data-testid="log-export">Export .log</button></div>'+
    '</div>'+
    '<div class="terminal" style="max-height:60vh"><div class="term-head"><span>VOID SYSTEM LOGS</span><span class="live">LIVE</span></div><div id="logs-host"></div><div class="text-faint"><span class="term-cursor"></span></div></div></div>';
  setTimeout(()=>{
    const host = $("#logs-host");
    let filter = "all", search = "", paused = false;
    function repaint(){
      host.innerHTML = "";
      const list = logs.filter(l=>{
        if (filter === "AUTH" && l.method !== "AUTH") return false;
        if (filter === "api" && l.method === "AUTH") return false;
        if (filter === "errors" && (l.status||200) < 400) return false;
        if (search && !(l.path||"").toLowerCase().includes(search.toLowerCase())) return false;
        return true;
      });
      list.forEach(l=> host.appendChild(termLine(l)));
    }
    repaint();
    $$("#log-filters [data-f]").forEach(b=> b.onclick = ()=>{ filter = b.dataset.f; $$("#log-filters [data-f]").forEach(x=> x.classList.toggle("cyan", x === b)); repaint(); });
    $("#log-search").addEventListener("input", (e)=>{ search = e.target.value; repaint(); });
    $("#log-pause").onclick = (e)=>{ paused = !paused; e.target.textContent = paused?"Resume":"Pause"; };
    $("#log-clear").onclick = ()=>{ logs.length = 0; repaint(); };
    $("#log-export").onclick = ()=>{
      const txt = logs.map(l=>"["+fmt.time(l.ts)+"] "+(l.method)+" "+l.path+" "+l.status+" "+l.latency+"ms").join("\\n");
      const blob = new Blob([txt],{type:"text/plain"}); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "void-logs.log"; a.click();
    };
    setInterval(()=>{
      if (paused) return;
      const m = ["GET","POST","PATCH","DELETE"];
      const e = { ts:Date.now(), method:m[(Math.random()*4)|0], path:["/api/me","/api/keys","/api/activity","/api/analytics"][(Math.random()*4)|0], status:Math.random()<0.05?500:200, latency:1+(Math.random()*30)|0, country:"PL" };
      logs.unshift(e); if (logs.length>200) logs.length = 200; repaint();
    }, 4000);
  }, 30);
  return dashShell(inner);
}

/* ---------- Page: Settings ---------- */
async function renderSettings(){
  const inner = h("div",{ class:"stagger" });
  const s = state.settings || {};
  inner.innerHTML =
    '<div class="caption">Configuration</div><h2 class="h2">Settings</h2>'+
    '<div class="tabs mt-6" id="set-tabs"><button class="tab active" data-t="account">Account</button><button class="tab" data-t="security">Security</button><button class="tab" data-t="notif">Notifications</button><button class="tab" data-t="appearance">Appearance</button><button class="tab" data-t="dev">Developer</button><button class="tab" data-t="danger">Danger Zone</button><span class="tab-ind" id="tab-ind"></span></div>'+
    '<div id="set-body" class="mt-2"></div>';
  setTimeout(async ()=>{
    const ind = $("#tab-ind");
    function moveInd(btn){ const r = btn.getBoundingClientRect(); const pr = btn.parentElement.getBoundingClientRect(); ind.style.left = (r.left-pr.left)+"px"; ind.style.width = r.width+"px"; }
    function pick(t){
      $$("#set-tabs .tab").forEach(b=> b.classList.toggle("active", b.dataset.t === t));
      moveInd(document.querySelector("#set-tabs [data-t="+t+"]"));
      const body = $("#set-body");
      if (t === "account") body.innerHTML = setAccount(s);
      else if (t === "security") body.innerHTML = setSecurity();
      else if (t === "notif") body.innerHTML = setNotif(s);
      else if (t === "appearance") body.innerHTML = setAppearance(s);
      else if (t === "dev") body.innerHTML = setDev(s);
      else if (t === "danger") body.innerHTML = setDanger();
      wireSettingsBody(t, s);
    }
    $$("#set-tabs .tab").forEach(b=> b.onclick = ()=> pick(b.dataset.t));
    pick("account");
    addEventListener("resize", ()=> moveInd(document.querySelector("#set-tabs .tab.active")));
  }, 30);
  return dashShell(inner);
}
function setAccount(s){
  const u = state.user||{};
  return '<div class="card"><div class="form-grid"><div class="field"><label>Name</label><input data-set="name" value="'+escapeHtml(u.firstName||"")+'"/></div>'+
    '<div class="field"><label>Email</label><input value="'+escapeHtml(u.email||"")+'" disabled/></div>'+
    '<div class="field"><label>Timezone</label><select data-set="tz"><option>Europe/Warsaw</option><option>UTC</option><option>America/New_York</option></select></div>'+
    '<div class="field"><label>Language</label><select data-set="lang"><option>English</option><option>Polski</option><option>Español</option></select></div></div>'+
    '<div class="flex justify-between mt-4"><span class="text-faint text-xs">Auto-save enabled</span><span class="pill green">Saved ✓</span></div></div>';
}
function setSecurity(){
  const sess = [
    ["Chrome · Windows","Warsaw, PL","Active now",true],
    ["Safari · iPhone","Warsaw, PL","2h ago",false],
    ["Firefox · macOS","Berlin, DE","Yesterday",false]
  ];
  let rows = "";
  for (const [d,l,t,active] of sess){
    rows += '<div class="row"><div><div style="font-weight:600">'+d+'</div><div class="text-faint text-xs">'+l+' · '+t+'</div></div><div class="flex gap-2">'+(active?'<span class="pill green">This device</span>':'<button class="btn btn-ghost btn-sm">Revoke</button>')+'</div></div>';
  }
  return '<div class="card"><div class="flex justify-between items-center mb-4"><h3 style="margin:0">Active sessions</h3><button class="btn btn-danger btn-sm" data-testid="revoke-all">Sign out all</button></div><div class="stagger" style="display:flex;flex-direction:column;gap:8px">'+rows+'</div></div>'+
    '<div class="card mt-4"><h3>Two-factor auth</h3><div class="flex justify-between mt-3 items-center"><div><div style="font-weight:600">Authenticator app</div><div class="text-faint text-xs">Add an extra layer.</div></div><label class="toggle"><input type="checkbox"/><span class="track"></span><span class="thumb"></span></label></div></div>';
}
function setNotif(s){
  const items = [
    ["Email","Critical updates",  "email"],
    ["Push","Real-time browser",  "push"],
    ["Security","Sign-ins, key changes","security"],
    ["Reports","Weekly digest",   "reports"],
    ["Marketing","Tips and offers","marketing"]
  ];
  const n = (s && s.notifications) || {};
  return '<div class="card">'+items.map(([t,d,k])=>'<div class="flex justify-between items-center" style="padding:14px 0;border-bottom:1px solid var(--border)"><div><div style="font-weight:600">'+t+'</div><div class="text-faint text-xs">'+d+'</div></div><label class="toggle"><input type="checkbox" data-notif="'+k+'" '+(n[k]?"checked":"")+'/><span class="track"></span><span class="thumb"></span></label></div>').join("")+'</div>';
}
function setAppearance(s){
  const colors = ["#4fa8ff","#2e7dff","#a8ccff","#0048cc","#001f5f","#36d399","#ffffff","#7da5e8"];
  return '<div class="card"><h3>Theme</h3><div class="flex gap-3 mt-3"><button class="btn btn-ghost" data-theme="dark"><svg class="icon"><use href="#i-moon"/></svg> Dark</button><button class="btn btn-ghost" data-theme="light"><svg class="icon"><use href="#i-sun"/></svg> Light</button><button class="btn btn-ghost" data-theme="system">System</button></div>'+
    '<h3 class="mt-6">Accent</h3><div class="swatches mt-2">'+colors.map(c=>'<div class="swatch '+(s.accentColor===c?"active":"")+'" data-accent="'+c+'" style="background:'+c+'"></div>').join("")+'</div>'+
    '<h3 class="mt-6">Font size <span class="text-faint" id="fs-val">'+(s.fontSize||14)+'px</span></h3><input type="range" min="12" max="20" value="'+(s.fontSize||14)+'" class="slider" data-set-num="fontSize" data-target="--font-base">'+
    '<h3 class="mt-6">Grid opacity <span class="text-faint" id="grid-val">'+(s.gridOpacity||50)+'</span></h3><input type="range" min="0" max="100" value="'+(s.gridOpacity||50)+'" class="slider" data-set-num="gridOpacity">'+
    '<h3 class="mt-6">Particle density <span class="text-faint" id="pd-val">'+(s.particleDensity||80)+'</span></h3><input type="range" min="0" max="200" value="'+(s.particleDensity||80)+'" class="slider" data-set-num="particleDensity">'+
    '<h3 class="mt-6">Aurora intensity <span class="text-faint" id="ai-val">'+(s.auroraIntensity||50)+'</span></h3><input type="range" min="0" max="100" value="'+(s.auroraIntensity||50)+'" class="slider" data-set-num="auroraIntensity">'+
    '<div class="flex justify-between mt-6 items-center"><div><div style="font-weight:600">Reduce motion</div><div class="text-faint text-xs">Disable non-essential animations.</div></div><label class="toggle"><input type="checkbox" data-set-bool="reduceMotion" '+(s.reduceMotion?"checked":"")+'/><span class="track"></span><span class="thumb"></span></label></div>'+
    '<div class="flex justify-between mt-3 items-center"><div><div style="font-weight:600">Sound effects</div><div class="text-faint text-xs">Synthesized clicks & chimes.</div></div><label class="toggle"><input type="checkbox" data-set-bool="soundEffects" '+(s.soundEffects?"checked":"")+'/><span class="track"></span><span class="thumb"></span></label></div>'+
    '</div>';
}
function setDev(s){
  return '<div class="card"><div class="form-grid">'+
    '<div class="field"><label>Webhook URL</label><input data-set="webhookUrl" value="'+escapeHtml(s.webhookUrl||"")+'" placeholder="https://your.app/webhook"/></div>'+
    '<div class="field"><label>Allowed origins (CSV)</label><input data-set="allowedOrigins" value="'+escapeHtml((s.allowedOrigins||[]).join(", "))+'"/></div>'+
    '<div class="field"><label>Rate limit / day</label><input type="range" min="100" max="10000" step="100" value="'+(s.rateLimit||1000)+'" data-set-num="rateLimit" class="slider"/></div>'+
    '<div class="field"><label>API version</label><select data-set="apiVersion"><option value="v1">v1</option><option value="v2">v2 (beta)</option></select></div>'+
    '</div>'+
    '<div class="flex justify-between mt-4 items-center"><div><div style="font-weight:600">Debug mode</div><div class="text-faint text-xs">Verbose API errors.</div></div><label class="toggle"><input type="checkbox" data-set-bool="debugMode" '+(s.debugMode?"checked":"")+'/><span class="track"></span><span class="thumb"></span></label></div>'+
    '<div class="mt-4"><button class="btn btn-ghost" id="webhook-test" data-testid="webhook-test"><svg class="icon" width="14" height="14"><use href="#i-zap"/></svg> Test webhook</button></div>'+
    '<h3 class="mt-6">Raw config</h3><div class="code"><div class="ln">1</div><span class="tok-c">// current settings (JSON)</span>\\n'+escapeHtml(JSON.stringify(s,null,2)).replace(/\\n/g,"\\n").replace(/(".+?")/g,"<span class=tok-s>$1</span>")+'</div></div>';
}
function setDanger(){
  return '<div class="card" style="border-color:rgba(255,51,102,0.3)"><h3 class="text-red">Danger zone</h3>'+
    '<div class="row mt-3"><div><div style="font-weight:600">Export all data</div><div class="text-faint text-xs">Download a JSON backup.</div></div><button class="btn btn-ghost btn-sm" id="export-all" data-testid="export-all">Export</button></div>'+
    '<div class="row mt-3"><div><div style="font-weight:600">Reset settings</div><div class="text-faint text-xs">Restore defaults.</div></div><button class="btn btn-ghost btn-sm" id="reset-all">Reset</button></div>'+
    '<div class="row mt-3"><div><div style="font-weight:600 ;color:var(--red)">Delete account</div><div class="text-faint text-xs">Type DELETE ME to confirm.</div></div><div class="flex gap-2"><input id="del-me" placeholder="DELETE ME" class="input" style="padding:8px 12px;border-radius:8px;background:var(--surface);border:1px solid var(--border);font-family:var(--font-body)"/><button class="btn btn-danger btn-sm" id="del-me-btn" disabled>Delete</button></div></div>'+
  '</div>';
}
function wireSettingsBody(tab, s){
  const body = $("#set-body"); if (!body) return;
  // Saving
  let saveT;
  function saveSettings(){ clearTimeout(saveT); saveT = setTimeout(async ()=>{ try{ const r = await api("/api/settings",{method:"PUT", body:state.settings}); state.settings = r.settings; toast("success","Saved"); }catch(e){} }, 500); }
  $$("[data-set]", body).forEach(el=> el.addEventListener("input", ()=>{ state.settings[el.dataset.set] = el.value; saveSettings(); }));
  $$("[data-set-num]", body).forEach(el=> el.addEventListener("input", ()=>{
    const v = +el.value; state.settings[el.dataset.setNum] = v;
    if (el.dataset.setNum === "fontSize"){ document.documentElement.style.fontSize = v+"px"; const lbl=$("#fs-val"); if(lbl) lbl.textContent = v+"px"; }
    if (el.dataset.setNum === "gridOpacity"){ document.documentElement.style.setProperty("--grid-opacity", v/100); const lbl=$("#grid-val"); if (lbl) lbl.textContent = v; }
    if (el.dataset.setNum === "particleDensity"){ document.documentElement.style.setProperty("--particle-density", v); const lbl=$("#pd-val"); if (lbl) lbl.textContent = v; if (window.__particles) window.__particles.rebuild(); }
    if (el.dataset.setNum === "auroraIntensity"){ document.documentElement.style.setProperty("--aurora-intensity", v/300); const lbl=$("#ai-val"); if (lbl) lbl.textContent = v; }
    saveSettings();
  }));
  $$("[data-set-bool]", body).forEach(el=> el.addEventListener("change", ()=>{ state.settings[el.dataset.setBool] = el.checked; if (el.dataset.setBool==="reduceMotion") document.documentElement.classList.toggle("reduce-motion", el.checked); saveSettings(); }));
  $$("[data-notif]", body).forEach(el=> el.addEventListener("change", ()=>{ state.settings.notifications = state.settings.notifications||{}; state.settings.notifications[el.dataset.notif] = el.checked; saveSettings(); }));
  $$("[data-accent]", body).forEach(el=> el.onclick = ()=>{ const c = el.dataset.accent; state.settings.accentColor = c; document.documentElement.style.setProperty("--accent", c); $$("[data-accent]").forEach(x=> x.classList.toggle("active", x===el)); saveSettings(); });
  if (tab === "dev"){
    const wb = $("#webhook-test"); if (wb) wb.onclick = async ()=>{ try{ const r = await api("/api/webhook-test",{method:"POST"}); toast(r.ok?"success":"error", r.ok?"Webhook OK ("+r.status+")":"Webhook failed"); }catch(e){ toast("error",e.message); } };
  }
  if (tab === "danger"){
    const ex = $("#export-all"); if (ex) ex.onclick = async ()=>{ const me = await api("/api/me"); const a = document.createElement("a"); a.href = "data:application/json,"+encodeURIComponent(JSON.stringify(me,null,2)); a.download="void-export.json"; a.click(); };
    const rs = $("#reset-all"); if (rs) rs.onclick = async ()=>{ state.settings = {}; await api("/api/settings",{method:"PUT", body:{}}); toast("success","Settings reset"); render(); };
    const dm = $("#del-me"); const db = $("#del-me-btn"); if (dm) dm.addEventListener("input", ()=> db.disabled = dm.value !== "DELETE ME");
    if (db) db.onclick = ()=> toast("warning","Demo mode — deletion disabled.");
  }
}

/* ---------- Page: Docs ---------- */
async function renderDocs(){
  const inner = h("div",{ class:"stagger" });
  const sections = [
    ["quickstart","Quick Start"],
    ["auth","Authentication"],
    ["api","API Reference"],
    ["keys","API Keys"],
    ["kv","KV Storage"],
    ["webhooks","Webhooks"],
    ["examples","Examples"],
    ["faq","FAQ"]
  ];
  inner.innerHTML =
    '<div class="caption">Reference</div><h2 class="h2">Documentation</h2>'+
    '<div style="display:grid;grid-template-columns:200px 1fr;gap:32px;margin-top:24px" class="docs-grid">'+
      '<aside style="position:sticky;top:32px;align-self:start"><div style="display:flex;flex-direction:column;gap:2px">'+sections.map(([id,t])=>'<a href="#docs-'+id+'" class="sb-link" style="font-size:12px">'+t+'</a>').join("")+'</div></aside>'+
      '<div>'+
        '<section id="docs-quickstart"><h3 class="h3">Quick Start</h3><p class="text-dim mt-2 body">Three commands ship a global API.</p><div class="code mt-3"><div class="ln">1\\n2\\n3\\n4</div><span class="tok-c"># 1. Create a KV namespace</span>\\nnpx wrangler kv namespace create <span class="tok-s">"KV"</span>\\n<span class="tok-c"># 2. Set Clerk secret</span>\\nnpx wrangler secret put CLERK_SECRET_KEY\\n<span class="tok-c"># 3. Ship</span>\\nnpx wrangler deploy<button class="copy" data-copy="quickstart"><svg class="icon"><use href="#i-copy"/></svg></button></div></section>'+
        '<section id="docs-auth" class="mt-6"><h3 class="h3">Authentication</h3><p class="text-dim body">Every protected endpoint requires <code class="mono">Authorization: Bearer &lt;clerk_jwt&gt;</code>. The Worker verifies the JWT against the Clerk JWKS and namespaces KV reads/writes by <code class="mono">payload.sub</code>.</p></section>'+
        '<section id="docs-api" class="mt-6"><h3 class="h3">API Reference</h3>'+apiTable()+'</section>'+
        '<section id="docs-keys" class="mt-6"><h3 class="h3">API Keys</h3><p class="text-dim body">Keys are stored hashed; secrets are returned once on creation only. Permissions: <span class="pill cyan">read</span> <span class="pill violet">write</span> <span class="pill red">admin</span>.</p></section>'+
        '<section id="docs-kv" class="mt-6"><h3 class="h3">KV Storage</h3><div class="code"><div class="ln">1\\n2</div><span class="tok-k">await</span> env.KV.put(<span class="tok-s">"settings:"</span> + userId, JSON.stringify(s));\\n<span class="tok-k">const</span> s = <span class="tok-k">await</span> env.KV.get(<span class="tok-s">"settings:"</span> + userId, { type: <span class="tok-s">"json"</span> });</div></section>'+
        '<section id="docs-webhooks" class="mt-6"><h3 class="h3">Webhooks</h3><p class="text-dim body">Configure a webhook URL in Settings → Developer. Send a test ping with <code class="mono">POST /api/webhook-test</code>.</p></section>'+
        '<section id="docs-examples" class="mt-6"><h3 class="h3">Examples</h3><div class="code"><div class="ln">1\\n2\\n3\\n4\\n5</div><span class="tok-k">const</span> r = <span class="tok-k">await</span> <span class="tok-f">fetch</span>(<span class="tok-s">"/api/keys"</span>, {\\n  headers: { <span class="tok-s">"Authorization"</span>: <span class="tok-s">"Bearer "</span> + token }\\n});\\n<span class="tok-k">const</span> { keys } = <span class="tok-k">await</span> r.json();\\nconsole.log(keys.length);</div></section>'+
        '<section id="docs-faq" class="mt-6"><h3 class="h3">FAQ</h3>'+
          '<div class="faq mt-3">'+
            ['What does "single file" mean?,The Worker is one ~250KB file containing HTML, CSS, JS, API.',
             'Can I bring my own auth?,Yes — swap verifyClerkJwt for any JWT verifier.',
             'Where is data stored?,Cloudflare KV, namespaced per Clerk user id.'].map(p=>{ const [q,a]=p.split(","); return '<div class="faq-item"><button class="faq-q">'+q+'<span class="chev">⌄</span></button><div class="faq-a"><div>'+a+'</div></div></div>'; }).join("")+
          '</div>'+
        '</section>'+
      '</div>'+
    '</div>';
  setTimeout(()=>{
    $$(".faq-q", inner).forEach(b=> b.onclick = ()=> b.parentElement.classList.toggle("open"));
    $$(".code .copy", inner).forEach(c=> c.onclick = ()=>{ const t = c.parentElement.innerText.replace(/^.*?\\n/,""); navigator.clipboard.writeText(t); c.innerHTML = '<svg class="icon"><use href="#i-check"/></svg>'; setTimeout(()=> c.innerHTML='<svg class="icon"><use href="#i-copy"/></svg>',1500); });
  },30);
  return dashShell(inner);
}
function apiTable(){
  const rows = [
    ["GET","/api/health","Edge health, region & latency"],
    ["GET","/api/me","Current user + settings + keyCount"],
    ["GET","/api/keys","List API keys"],
    ["POST","/api/keys","Create new API key"],
    ["PATCH","/api/keys/:id","Edit a key"],
    ["DELETE","/api/keys/:id","Revoke a key"],
    ["GET","/api/activity","Last 100 log entries"],
    ["GET","/api/analytics","30-day rollups"],
    ["GET","/api/settings","Current settings"],
    ["PUT","/api/settings","Update settings"],
    ["POST","/api/webhook-test","Ping configured webhook"],
    ["GET","/api/notifications","Recent notifications"],
    ["PATCH","/api/notifications","Mark all read"],
    ["GET","/api/status","Public service status"]
  ];
  return '<div class="card mt-3" style="padding:0;overflow:hidden"><table style="width:100%;border-collapse:collapse"><thead><tr style="text-align:left"><th style="padding:14px;font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--text-faint);border-bottom:1px solid var(--border)">Method</th><th style="padding:14px;font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--text-faint);border-bottom:1px solid var(--border)">Endpoint</th><th style="padding:14px;font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--text-faint);border-bottom:1px solid var(--border)">Description</th></tr></thead><tbody>'+rows.map(([m,p,d])=>'<tr><td style="padding:14px;border-bottom:1px solid var(--border)"><span class="method '+m+'">'+m+'</span></td><td style="padding:14px;border-bottom:1px solid var(--border)" class="mono text-cyan">'+p+'</td><td style="padding:14px;border-bottom:1px solid var(--border);color:var(--text-dim)">'+d+'</td></tr>').join("")+'</tbody></table></div>';
}

/* ---------- Page: Integrations ---------- */
async function renderIntegrations(){
  const inner = h("div",{ class:"stagger" });
  
  // Try to fetch admin-managed content
  let adminContent = null;
  try { const r = await api("/api/content/integrations"); adminContent = r.data; } catch(e){}

  // Default categories
  const defaultCats = [
    ["Popular","star",[
      ["Stripe","SP","Accept payments and subscriptions globally",true,"payments"],
      ["GitHub","GH","Sync issues, PRs and releases automatically",true,"dev"],
      ["Slack","SL","Alerts, deploy notifications, command bots",true,"comms"],
      ["Linear","LN","Engineering issue tracking with bidirectional sync",false,"dev"]
    ]],
    ["Auth & Identity","shield",[
      ["Clerk","CK","Hosted user management with social login",true,"auth"],
      ["Auth0","A0","Enterprise SSO and identity federation",false,"auth"],
      ["WorkOS","WO","SAML, SCIM and admin portal in one API",false,"auth"]
    ]],
    ["AI & ML","sparkles",[
      ["OpenAI","OA","GPT, embeddings and image generation",true,"ai"],
      ["Anthropic","AT","Claude family of models for safe AI",true,"ai"],
      ["Pinecone","PC","Vector database for retrieval and search",false,"ai"],
      ["Replicate","RP","Run any open-source model on demand",false,"ai"]
    ]],
    ["Comms","bell",[
      ["Twilio","TW","Programmable SMS, voice, WhatsApp",true,"comms"],
      ["Resend","RS","Modern email API with React templates",true,"comms"],
      ["Discord","DC","Webhook drops to your server",false,"comms"],
      ["PostHog","PH","Product analytics and feature flags",true,"data"]
    ]]
  ];

  let cats;
  if (adminContent && typeof adminContent === "object" && !Array.isArray(adminContent) && Object.keys(adminContent).length > 0) {
    // Admin content exists - transform it to display format
    cats = Object.entries(adminContent).map(([title, items])=> [title, "zap", Array.isArray(items) ? items.map(it => [it.name||"—",it.abbr||"??",it.desc||"",!!it.connected,it.cat||"other"]) : []]);
  } else if (adminContent !== null && adminContent !== undefined && typeof adminContent === "object" && Object.keys(adminContent).length === 0) {
    cats = [];
  } else {
    cats = defaultCats;
  }

  let htmlStr = '<div class="caption">Connect</div><h2 class="h2">Integrations</h2><p class="text-dim mt-2 body" style="max-width:60ch">Wire up your favourite services in seconds. Configure once, fire from anywhere on the edge.</p>';

  if (cats.length === 0) {
    htmlStr += '<div class="card mt-8" style="text-align:center;padding:80px 32px"><svg class="icon xl" style="color:var(--text-faint);margin-bottom:16px;width:48px;height:48px"><use href="#i-zap"/></svg><h3 class="h3" style="color:var(--text-dim)">No integrations available yet</h3><p class="text-faint mt-2 body">Integrations will appear here once configured by the admin.</p></div>';
  } else {
    // Filter chips
    htmlStr += '<div class="flex gap-2 flex-wrap mt-6" id="int-filter">'+
      '<button class="pill cyan" data-fc="all">All</button>'+
      '<button class="pill" data-fc="payments">Payments</button>'+
      '<button class="pill" data-fc="dev">Dev tools</button>'+
      '<button class="pill" data-fc="comms">Comms</button>'+
      '<button class="pill" data-fc="ai">AI / ML</button>'+
      '<button class="pill" data-fc="auth">Auth</button>'+
      '<button class="pill" data-fc="data">Data</button>'+
      '</div>';
    for (const [title, ic, items] of cats){
      htmlStr += '<h3 class="h4 mt-8" style="font-family:var(--font-display);font-weight:600">'+escapeHtml(title)+'</h3>';
      htmlStr += '<div class="int-grid mt-3">';
      for (const [name, abbr, desc, connected, cat] of items){
        htmlStr += '<div class="int-card" data-int="'+escapeHtml(cat)+'" data-testid="int-card"><div class="head"><div class="ilogo">'+escapeHtml(abbr)+'</div><h4>'+escapeHtml(name)+'</h4></div>'+
          '<div class="desc">'+escapeHtml(desc)+'</div>'+
          '<div class="foot">'+
          (connected?'<span class="pill green">Connected</span>':'<span class="pill" style="color:var(--text-faint)">Available</span>')+
          '<button class="btn btn-ghost btn-sm" data-testid="int-toggle">'+(connected?'Manage':'Connect')+' <svg class="icon" width="12" height="12"><use href="#i-arrow-right"/></svg></button>'+
          '</div></div>';
      }
      htmlStr += '</div>';
    }
  }

  inner.innerHTML = htmlStr;
  setTimeout(()=>{
    let cur = "all";
    $$("#int-filter [data-fc]").forEach(b=> b.onclick = ()=>{
      cur = b.dataset.fc; $$("#int-filter [data-fc]").forEach(x=> x.classList.toggle("cyan", x===b));
      $$("[data-int]").forEach(c=>{ const show = cur==="all" || c.dataset.int===cur; c.style.display = show?"":"none"; });
    });
    $$("[data-testid=int-toggle]").forEach(b=> b.onclick = ()=> toast("info","Demo mode — integration flow disabled."));
  }, 30);
  return dashShell(inner);
}

/* ---------- Page: Changelog ---------- */
async function renderChangelog(){
  const inner = h("div",{ class:"stagger" });
  // Try to fetch admin-managed content first
  let adminContent = null;
  try { const r = await api("/api/content/changelog"); adminContent = r.data; } catch(e){}
  
  let versions;
  if (adminContent && Array.isArray(adminContent) && adminContent.length > 0) {
    versions = adminContent;
  } else if (adminContent !== null && adminContent !== undefined) {
    // Admin has set content but it is empty
    versions = [];
  } else {
    // No admin content set, use static defaults
    versions = [
      ["v2.4.0","Jan 5, 2026","Blue refresh + new pages",[
        ["Refined to a single-hue blue palette across all surfaces and charts.",true],
        ["New /integrations page with 15 connectors and category filters.",true],
        ["New /changelog page (this one) with semantic version timeline.",true],
        ["Keyboard shortcuts modal (press ? anywhere).",true],
        ["Customer logos strip on landing.",true],
        ["Dropped Syne / IBM Plex for Space Grotesk + JetBrains Mono + Manrope.",false]
      ]],
      ["v2.3.0","Dec 18, 2025","Live activity + analytics",[
        ["Real-time activity feed with filter tabs and search.",true],
        ["Analytics: 30-day sparkline, donut by method, world dot map, response histogram.",true],
        ["System health rings (CPU / Memory / KV Ops).",false]
      ]],
      ["v2.2.0","Nov 30, 2025","Settings overhaul",[
        ["Six-tab settings (Account, Security, Notifications, Appearance, Developer, Danger).",true],
        ["Live sliders: grid opacity, particle density, aurora intensity, font size.",true],
        ["Sound effects (Web Audio synth, no files).",false],
        ["Reduce-motion mode respected globally.",false]
      ]],
      ["v2.1.0","Nov 12, 2025","Command palette + cursor",[
        ["Cmd+K command palette with arrow nav.",true],
        ["Two-element magnetic cursor with hover states.",true],
        ["Confetti burst on first API key.",true]
      ]],
      ["v2.0.0","Oct 28, 2025","Single-file rebuild",[
        ["Entire app moved to one worker.js (HTML/CSS/JS embedded).",true],
        ["Clerk JWT verification via JWKS, networkless cached.",true],
        ["KV-backed user namespacing.",true]
      ]]
    ];
  }

  let htmlStr = '<div class="caption">Release notes</div><h2 class="h2">Changelog</h2><p class="text-dim mt-2 body" style="max-width:60ch">Every shipped update, since the rewrite.</p>';

  if (versions.length === 0) {
    htmlStr += '<div class="card mt-8" style="text-align:center;padding:80px 32px"><svg class="icon xl" style="color:var(--text-faint);margin-bottom:16px;width:48px;height:48px"><use href="#i-sparkles"/></svg><h3 class="h3" style="color:var(--text-dim)">No changelog entries yet</h3><p class="text-faint mt-2 body">Check back soon. Updates will appear here once published by the admin.</p></div>';
  } else {
    htmlStr += '<div class="timeline mt-8">';
    for (const v of versions){
      // Support both admin JSON format and static array format
      const ver = v.ver || v[0] || "—";
      const date = v.date || v[1] || "";
      const title = v.title || v[2] || "";
      const changes = v.changes || v[3] || [];
      htmlStr += '<div class="tl-item" data-testid="tl-item">'+
        '<div class="ver"><span class="v">'+escapeHtml(ver)+'</span><span class="d">.</span><span class="d">'+escapeHtml(date)+'</span></div>'+
        '<h4>'+escapeHtml(title)+'</h4>'+
        '<ul class="changes">';
      for (const c of changes){
        const text = c.text || c[0] || (typeof c === "string" ? c : "");
        const isFeat = c.isFeat || c[1] || false;
        htmlStr += '<li class="'+(isFeat?"feat":"")+'">'+escapeHtml(text)+'</li>';
      }
      htmlStr += '</ul></div>';
    }
    htmlStr += '</div>';
  }

  // Subscribe block
  htmlStr += '<div class="card mt-8" style="text-align:center;padding:48px"><h3 class="h3">Stay in the loop</h3><p class="text-dim mt-2 body" style="max-width:48ch;margin:8px auto 0">Get the next changelog drop in your inbox.</p>'+
    '<div class="flex gap-3 mt-4 justify-center"><input class="input" placeholder="you@domain.com" style="flex:0 1 320px;padding:12px 16px;border-radius:10px;background:var(--surface);border:1px solid var(--border);font-family:var(--font-body)" data-testid="changelog-email"/><button class="btn btn-primary" data-testid="changelog-subscribe">Subscribe <svg class="icon" width="14" height="14"><use href="#i-arrow-right"/></svg></button></div></div>';
  inner.innerHTML = htmlStr;
  setTimeout(()=>{
    const sb = $("[data-testid=changelog-subscribe]");
    if (sb) sb.onclick = ()=> { const e = $("[data-testid=changelog-email]"); if (e && e.value.includes("@")){ toast("success","You're in. Watch your inbox."); e.value=""; } else toast("warning","Enter a valid email."); };
  }, 30);
  return dashShell(inner);
}

/* ---------- Page: Admin ---------- */
async function renderAdmin(){
  const inner = h("div",{ class:"stagger" });
  inner.innerHTML =
    '<div class="flex justify-between items-center" style="flex-wrap:wrap;gap:16px">'+
      '<div><div class="caption" style="color:var(--blue-bright)">Restricted area</div><h2 class="h2 flex items-center gap-3"><svg class="icon xl" style="color:var(--blue-bright)"><use href="#i-shield"/></svg> Admin Panel</h2><p class="text-dim mt-2 body" style="max-width:60ch">Manage users, broadcast announcements and edit global content.</p></div>'+
      '<span class="ripple-dot" data-testid="admin-live"></span>'+
    '</div>'+
    '<div class="tabs mt-6" id="adm-tabs">'+
      '<button class="tab active" data-t="overview" data-testid="adm-tab-overview">Overview</button>'+
      '<button class="tab" data-t="users" data-testid="adm-tab-users">Users</button>'+
      '<button class="tab" data-t="broadcast" data-testid="adm-tab-broadcast">Broadcast</button>'+
      '<button class="tab" data-t="changelog" data-testid="adm-tab-changelog">Changelog</button>'+
      '<button class="tab" data-t="integrations" data-testid="adm-tab-integrations">Integrations</button>'+
      '<button class="tab" data-t="status" data-testid="adm-tab-status">Status</button>'+
      '<span class="tab-ind" id="adm-ind"></span>'+
    '</div>'+
    '<div id="adm-body" class="mt-2"></div>';
  setTimeout(async ()=>{
    const ind = $("#adm-ind");
    function moveInd(btn){ const r = btn.getBoundingClientRect(); const pr = btn.parentElement.getBoundingClientRect(); ind.style.left = (r.left-pr.left)+"px"; ind.style.width = r.width+"px"; }
    async function pick(t){
      $$("#adm-tabs .tab").forEach(b=> b.classList.toggle("active", b.dataset.t === t));
      moveInd(document.querySelector("#adm-tabs [data-t="+t+"]"));
      const body = $("#adm-body");
      body.innerHTML = '<div class="card"><div class="skel" style="height:80px"></div></div>';
      if (t === "overview")     await renderAdmOverview(body);
      else if (t === "users")   await renderAdmUsers(body);
      else if (t === "broadcast") renderAdmBroadcast(body);
      else if (t === "changelog") await renderAdmContent(body, "changelog");
      else if (t === "integrations") await renderAdmContent(body, "integrations");
      else if (t === "status")  await renderAdmContent(body, "status");
    }
    $$("#adm-tabs .tab").forEach(b=> b.onclick = ()=> pick(b.dataset.t));
    pick("overview");
    addEventListener("resize", ()=>{ const a = document.querySelector("#adm-tabs .tab.active"); if (a) moveInd(a); });
  }, 30);
  return dashShell(inner);
}

async function renderAdmOverview(body){
  let stats = {};
  try{ stats = await api("/api/admin/stats"); } catch(e){ stats = { error:e.message }; }
  body.innerHTML =
    '<div class="stats-row">'+
      sCard("Users", stats.users || 0, "Tracked", "up", "i-user")+
      sCard("API Keys", stats.keys || 0, "Provisioned", "up", "i-key")+
      sCard("Log Events", stats.logs || 0, "Last 100/user", "up", "i-activity")+
      sCard("Edge", "GLOBAL", "Cloudflare", "up", "i-globe", true)+
    '</div>'+
    '<div class="card mt-6"><h3><svg class="icon"><use href="#i-shield"/></svg> System info</h3>'+
      '<div class="form-grid mt-3"><div class="field"><label>App URL</label><input value="'+escapeHtml(window.__APP_URL__||location.origin)+'" disabled/></div>'+
      '<div class="field"><label>Clerk publishable</label><input value="'+escapeHtml((window.__CLERK_PK__||"").slice(0,18)+"…")+'" disabled/></div>'+
      '<div class="field"><label>Region</label><input value="Cloudflare Global Edge" disabled/></div>'+
      '<div class="field"><label>Snapshot</label><input value="'+new Date().toISOString()+'" disabled/></div></div>'+
    '</div>'+
    '<div class="card mt-6"><h3><svg class="icon"><use href="#i-key"/></svg> Bootstrap admin</h3>'+
      '<p class="text-dim body mt-2">Set <code class="mono">ADMIN_USER_IDS</code> in <code class="mono">wrangler.toml</code> with your Clerk User IDs (comma-separated) to grant admin access. Or set <code class="mono">publicMetadata.role = "admin"</code> on a user in the Clerk dashboard.</p>'+
    '</div>';
  setTimeout(()=>{ $$("[data-stat-num]").forEach(el=>{ const v = +el.dataset.statNum; const suf = el.dataset.suffix||""; if (Number.isFinite(v)) counter(el, v, 1100, suf); else el.textContent = el.dataset.statText || "—"; }); }, 0);
}

async function renderAdmUsers(body){
  let data;
  try{ data = await api("/api/admin/users"); } catch(e){ body.innerHTML = '<div class="card text-red">'+escapeHtml(e.message)+'</div>'; return; }
  const users = data.users || [];
  body.innerHTML =
    '<div class="card"><div class="flex justify-between items-center mb-4 flex-wrap gap-3">'+
      '<h3 style="margin:0">Users <span class="text-faint" style="font-size:13px">· '+users.length+' total</span></h3>'+
      '<input id="adm-user-search" placeholder="Filter…" data-testid="adm-user-search" style="padding:8px 12px;border-radius:10px;background:var(--surface);border:1px solid var(--border);font-family:var(--font-body)"/>'+
    '</div>'+
    '<div style="overflow-x:auto"><table id="adm-users-tbl" data-testid="adm-users-tbl" style="width:100%;border-collapse:collapse">'+
      '<thead><tr style="text-align:left">'+
        ['User','Email','Created','Last sign-in','Keys','Logs','Role',''].map(t=>'<th style="padding:12px;font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--text-faint);border-bottom:1px solid var(--border)">'+t+'</th>').join("")+
      '</tr></thead><tbody>'+
      users.map(u=>{
        const initials = ((u.firstName||u.email||"U").charAt(0) + (u.lastName ? u.lastName.charAt(0):"")).toUpperCase();
        return '<tr data-uid="'+u.id+'" data-q="'+escapeHtml(((u.email||"")+" "+(u.firstName||"")+" "+(u.lastName||"")).toLowerCase())+'">'+
          '<td style="padding:12px;border-bottom:1px solid var(--border)"><div class="flex items-center gap-3"><div class="avatar">'+escapeHtml(initials)+'</div><div><div style="font-weight:600">'+escapeHtml(((u.firstName||"")+" "+(u.lastName||"")).trim()||"—")+'</div><div class="text-faint text-xs mono">'+escapeHtml(u.id.slice(0,12))+'…</div></div></div></td>'+
          '<td style="padding:12px;border-bottom:1px solid var(--border)" class="mono text-sm">'+escapeHtml(u.email||"—")+'</td>'+
          '<td style="padding:12px;border-bottom:1px solid var(--border)" class="text-faint text-xs">'+(u.createdAt?new Date(u.createdAt).toISOString().slice(0,10):"—")+'</td>'+
          '<td style="padding:12px;border-bottom:1px solid var(--border)" class="text-faint text-xs">'+(u.lastSignIn?fmt.rel(u.lastSignIn):"never")+'</td>'+
          '<td style="padding:12px;border-bottom:1px solid var(--border)" class="mono">'+u.keyCount+'</td>'+
          '<td style="padding:12px;border-bottom:1px solid var(--border)" class="mono">'+u.logCount+'</td>'+
          '<td style="padding:12px;border-bottom:1px solid var(--border)">'+(u.isAdminMeta?'<span class="pill cyan">admin</span>':'<span class="pill">user</span>')+'</td>'+
          '<td style="padding:12px;border-bottom:1px solid var(--border)"><div class="flex gap-1"><button class="btn-icon" data-act="view" data-testid="user-view" aria-label="view"><svg class="icon"><use href="#i-eye"/></svg></button><button class="btn-icon" data-act="edit" data-testid="user-edit" aria-label="edit"><svg class="icon"><use href="#i-edit"/></svg></button><button class="btn-icon" data-act="delete" data-testid="user-delete" aria-label="delete"><svg class="icon"><use href="#i-trash"/></svg></button></div></td>'+
        '</tr>';
      }).join("")+
      '</tbody></table>'+
      (users.length ? '' : '<div class="text-faint" style="text-align:center;padding:60px">No users yet — they appear here once anyone signs in.</div>')+
    '</div></div>';
  setTimeout(()=>{
    const tb = $("#adm-users-tbl tbody");
    $("#adm-user-search").addEventListener("input",(e)=>{
      const q = e.target.value.toLowerCase();
      tb.querySelectorAll("tr").forEach(r=>{ r.style.display = !q || r.dataset.q.includes(q) ? "" : "none"; });
    });
    tb.addEventListener("click", async (e)=>{
      const btn = e.target.closest("[data-act]"); if (!btn) return;
      const tr = btn.closest("tr"); const uid = tr.dataset.uid;
      if (btn.dataset.act === "view"){
        try{ const data = await api("/api/admin/users/"+uid); openUserModal(data); }
        catch(err){ toast("error", err.message); }
      } else if (btn.dataset.act === "edit"){
        try{ const data = await api("/api/admin/users/"+uid); openUserEdit(data); }
        catch(err){ toast("error", err.message); }
      } else if (btn.dataset.act === "delete"){
        if (!confirm("Permanently delete all KV data for this user? This cannot be undone.")) return;
        try{ await api("/api/admin/users/"+uid, { method:"DELETE" }); tr.style.transition="all .3s"; tr.style.opacity=0; setTimeout(()=> tr.remove(), 300); toast("success","User purged."); }
        catch(err){ toast("error", err.message); }
      }
    });
  }, 0);
}

function openUserModal(data){
  const back = h("div",{ class:"cmd-back open", "data-testid":"user-modal" });
  const summary = { settings:data.settings, keyCount:(data.keys||[]).length, logCount:(data.logs||[]).length, notifications:(data.notifications||[]).length, profile: data.profile ? { email:data.profile.email_addresses && data.profile.email_addresses[0] && data.profile.email_addresses[0].email_address, name:((data.profile.first_name||"")+" "+(data.profile.last_name||"")).trim(), public_metadata:data.profile.public_metadata } : null };
  back.innerHTML = '<div class="cmd" style="width:min(720px,92vw);padding:28px;max-height:84vh;overflow-y:auto"><div class="flex justify-between items-center mb-4"><div><div class="caption">Inspect</div><h3 class="h3">User <span class="mono text-faint" style="font-size:14px">'+escapeHtml(data.id.slice(0,16))+'…</span></h3></div><button class="btn-icon" id="um-close" data-testid="um-close"><svg class="icon"><use href="#i-x"/></svg></button></div>'+
    '<div class="code">'+escapeHtml(JSON.stringify(summary,null,2))+'</div>'+
    '<h4 class="mt-6">Keys <span class="text-faint">('+((data.keys||[]).length)+')</span></h4>'+
    '<div class="mt-3" style="display:flex;flex-direction:column;gap:6px">'+(data.keys||[]).map(k=>'<div class="row"><div><div style="font-weight:600">'+escapeHtml(k.name)+'</div><div class="mono text-faint text-xs">'+escapeHtml(k.masked||"—")+'</div></div><button class="btn btn-ghost btn-sm" data-revoke="'+escapeHtml(k.id)+'" data-testid="adm-revoke">Revoke</button></div>').join("")+(((data.keys||[]).length===0)?'<div class="text-faint">No keys.</div>':'')+'</div>'+
    '</div>';
  document.body.appendChild(back);
  back.querySelector("#um-close").onclick = ()=> back.remove();
  back.addEventListener("click",(e)=>{ if (e.target === back) back.remove(); });
  back.querySelectorAll("[data-revoke]").forEach(b=> b.onclick = async ()=>{
    try{ await api("/api/admin/users/"+data.id+"/keys/"+b.dataset.revoke, { method:"DELETE" }); toast("success","Revoked."); b.closest(".row").remove(); }
    catch(err){ toast("error", err.message); }
  });
}

function openUserEdit(data){
  const s = data.settings || {};
  const back = h("div",{ class:"cmd-back open", "data-testid":"user-edit-modal" });
  back.innerHTML = '<div class="cmd" style="width:min(640px,92vw);padding:28px"><div class="flex justify-between items-center mb-4"><div><div class="caption">Edit settings</div><h3 class="h3">'+escapeHtml(data.id.slice(0,16))+'…</h3></div><button class="btn-icon" id="ue-close"><svg class="icon"><use href="#i-x"/></svg></button></div>'+
    '<div class="form-grid">'+
      '<div class="field"><label>Theme</label><select id="ue-theme"><option value="dark" '+(s.theme==='dark'?'selected':'')+'>dark</option><option value="light" '+(s.theme==='light'?'selected':'')+'>light</option><option value="system" '+(s.theme==='system'?'selected':'')+'>system</option></select></div>'+
      '<div class="field"><label>Accent</label><input id="ue-accent" value="'+escapeHtml(s.accentColor||"#2e7dff")+'"/></div>'+
      '<div class="field"><label>Rate limit</label><input id="ue-rate" type="number" value="'+(s.rateLimit||1000)+'"/></div>'+
      '<div class="field"><label>API version</label><input id="ue-ver" value="'+escapeHtml(s.apiVersion||"v1")+'"/></div>'+
    '</div>'+
    '<div class="flex gap-3 mt-4"><button class="btn btn-primary" id="ue-save" data-testid="ue-save">Save</button><button class="btn btn-ghost" id="ue-cancel">Cancel</button></div></div>';
  document.body.appendChild(back);
  const close = ()=> back.remove();
  back.querySelector("#ue-close").onclick = close;
  back.querySelector("#ue-cancel").onclick = close;
  back.addEventListener("click",(e)=>{ if (e.target === back) close(); });
  back.querySelector("#ue-save").onclick = async ()=>{
    const next = Object.assign({}, s, {
      theme: back.querySelector("#ue-theme").value,
      accentColor: back.querySelector("#ue-accent").value,
      rateLimit: +back.querySelector("#ue-rate").value,
      apiVersion: back.querySelector("#ue-ver").value
    });
    try{ await api("/api/admin/users/"+data.id+"/settings",{method:"PUT", body:next}); toast("success","Settings saved."); close(); }
    catch(err){ toast("error", err.message); }
  };
}

function renderAdmBroadcast(body){
  body.innerHTML =
    '<div class="card"><h3><svg class="icon"><use href="#i-bell"/></svg> Broadcast a notification</h3>'+
      '<p class="text-dim body mt-2">Drops a notification into every user&rsquo;s drawer. Keep it short — 280 chars max.</p>'+
      '<div class="form-grid mt-4"><div class="field"><label>Type</label><select id="bc-type" data-testid="bc-type"><option value="info">Info</option><option value="success">Success</option><option value="warning">Warning</option><option value="error">Error</option></select></div><div class="field"><label>Audience</label><select disabled><option>All users</option></select></div></div>'+
      '<div class="field mt-4"><label>Message</label><textarea id="bc-msg" rows="3" maxlength="280" placeholder="Heads up — scheduled maintenance Sunday at 03:00 UTC." data-testid="bc-msg" style="padding:12px;border-radius:10px;background:var(--surface);border:1px solid var(--border);color:#fff;font-family:var(--font-body);font-size:13px"></textarea></div>'+
      '<div class="flex justify-between items-center mt-4"><span class="text-faint text-xs"><span id="bc-count">0</span>/280</span><button class="btn btn-primary" id="bc-send" data-testid="bc-send">Send to all <svg class="icon" width="14" height="14"><use href="#i-arrow-right"/></svg></button></div>'+
    '</div>';
  setTimeout(()=>{
    const ta = $("#bc-msg"); const c = $("#bc-count");
    ta.addEventListener("input", ()=> c.textContent = ta.value.length);
    $("#bc-send").onclick = async ()=>{
      const message = ta.value.trim();
      if (!message) return toast("warning","Enter a message.");
      if (!confirm("Send this to every signed-up user?")) return;
      try{ const r = await api("/api/admin/broadcast",{method:"POST", body:{ message, type: $("#bc-type").value }}); toast("success","Sent to "+r.count+" users."); ta.value=""; c.textContent=0; }
      catch(err){ toast("error", err.message); }
    };
  }, 0);
}

async function renderAdmContent(body, key){
  let cur;
  try{ const r = await api("/api/admin/content/"+key); cur = r.data; } catch(e){ cur = null; }
  body.innerHTML =
    '<div class="card"><div class="flex justify-between items-center mb-4"><h3 style="margin:0;text-transform:capitalize">Edit '+key+' content</h3>'+
    '<div class="flex gap-2"><button class="btn btn-ghost btn-sm" id="ac-fmt" data-testid="ac-fmt">Format</button><button class="btn btn-primary btn-sm" id="ac-save" data-testid="ac-save">Save</button></div></div>'+
    '<p class="text-dim body mb-3">Anything you save here overrides the static defaults the SPA ships with. Schema is free-form JSON.</p>'+
    '<textarea id="ac-json" data-testid="ac-json" spellcheck="false" rows="22" style="width:100%;padding:16px;border-radius:12px;background:var(--void-3);border:1px solid var(--border);color:#d6e4ff;font-family:var(--font-body);font-size:12.5px;line-height:1.6;resize:vertical">'+escapeHtml(JSON.stringify(cur||defaultContent(key),null,2))+'</textarea>'+
    '</div>';
  setTimeout(()=>{
    $("#ac-fmt").onclick = ()=>{ try{ const v = JSON.parse($("#ac-json").value); $("#ac-json").value = JSON.stringify(v,null,2); toast("success","Formatted."); } catch(e){ toast("error","Invalid JSON: "+e.message); } };
    $("#ac-save").onclick = async ()=>{
      let parsed;
      try{ parsed = JSON.parse($("#ac-json").value); } catch(e){ return toast("error","Invalid JSON: "+e.message); }
      try{ await api("/api/admin/content/"+key,{method:"PUT", body:parsed}); toast("success","Saved."); }
      catch(err){ toast("error", err.message); }
    };
  }, 0);
}
function defaultContent(key){
  if (key === "changelog") return [{ ver:"v2.5.0", date:"2026-01-05", title:"Sample release", changes:[{text:"Edit me!", isFeat:true}] }];
  if (key === "integrations") return { Popular:[{name:"Stripe",abbr:"SP",desc:"Edit this list",connected:true,cat:"payments"}] };
  if (key === "status") return { services:[{name:"API Gateway", status:"operational", uptime:99.99, response:8}], incidents:[] };
  return {};
}


/* ---------- Keyboard shortcuts modal ---------- */
function openShortcuts(){
  const cur = $("#sc-modal");
  if (cur){ cur.remove(); return; }
  const back = h("div",{ class:"cmd-back open", id:"sc-modal", "data-testid":"sc-modal" });
  const rows = [
    ["Open command palette",["Ctrl","K"]],
    ["Show this help",["?"]],
    ["Go to Dashboard",["G","D"]],
    ["Go to API Keys",["G","K"]],
    ["Go to Analytics",["G","A"]],
    ["Go to Activity",["G","L"]],
    ["Go to Settings",["G","S"]],
    ["Open Notifications",["N"]],
    ["Toggle sidebar",["["]],
    ["Sign out",["Ctrl","Q"]],
    ["Close any modal",["Esc"]],
    ["Search current page",["/"]]
  ];
  let html = '<div class="cmd" style="width:min(680px,90vw);padding:28px"><div class="flex justify-between items-center mb-4"><div><div class="caption">Reference</div><h3 class="h3">Keyboard Shortcuts</h3></div><button class="btn-icon" id="sc-close" data-testid="sc-close" aria-label="close"><svg class="icon"><use href="#i-x"/></svg></button></div>';
  html += '<div class="shortcuts">';
  for (const [label, keys] of rows){
    html += '<div class="sc-row"><span class="text-dim text-sm">'+label+'</span><div class="kbd-wrap">'+keys.map(k=>'<kbd>'+k+'</kbd>').join('')+'</div></div>';
  }
  html += '</div><div class="text-faint text-xs mt-4 mono" style="text-align:center">Tip: many of these only fire when no input is focused.</div></div>';
  back.innerHTML = html;
  document.body.appendChild(back);
  back.querySelector("#sc-close").onclick = ()=> back.remove();
  back.addEventListener("click",(e)=>{ if (e.target === back) back.remove(); });
}


async function renderStatus(){
  const inner = h("div",{ class:"stagger" });
  
  // Try admin-managed status content
  let adminContent = null;
  try { const r = await api("/api/content/status"); adminContent = r.data; } catch(e){}
  
  let s;
  if (adminContent && adminContent.services && Array.isArray(adminContent.services)) {
    s = adminContent;
  } else {
    s = await api("/api/status").catch(()=>({services:[],incidents:[]}));
  }
  
  if (!s.services || s.services.length === 0) {
    inner.innerHTML =
      '<div class="card" style="text-align:center;padding:80px 32px"><svg class="icon xl" style="color:var(--text-faint);margin-bottom:16px;width:48px;height:48px"><use href="#i-cpu"/></svg><h3 class="h3" style="color:var(--text-dim)">No status information available</h3><p class="text-faint mt-2 body">Service status will appear here once configured by the admin.</p></div>';
    return dashShell(inner);
  }
  
  const ok = s.services.every(x=>x.status==="operational");
  inner.innerHTML =
    '<div class="card" style="text-align:center;padding:60px"><h2 class="h1 gradient-text">'+(ok?"All Systems Operational":"Degraded")+'</h2><p class="text-dim mt-3 mono">Last checked '+fmt.rel(s.ts||Date.now())+'</p><div class="flex justify-center gap-3 mt-4"><span class="pill green">Auto-refresh 60s</span><span class="pill cyan">Edge POP '+escapeHtml((state.user&&state.user.geoColo)||"???")+'</span></div></div>'+
    '<div class="card mt-6"><h3>Services</h3><div class="stagger" style="display:flex;flex-direction:column;gap:8px;margin-top:12px">'+s.services.map(svc=>{
      const statusColor = svc.status === "operational" ? "green" : svc.status === "degraded" ? "amber" : "red";
      return '<div class="row"><div class="flex items-center gap-3"><span class="pill '+statusColor+'">'+escapeHtml(svc.status)+'</span><div><div style="font-weight:600">'+escapeHtml(svc.name)+'</div><div class="text-faint text-xs mono">'+(svc.uptime != null ? svc.uptime.toFixed(2)+"%" : "—")+' . '+(svc.response != null ? svc.response+"ms" : "—")+'</div></div></div><div class="uptime-bars" style="width:280px">'+Array.from({length:90},(_,i)=>{ const r = Math.random(); return '<i class="'+(r<0.005?"red":r<0.02?"amber":"")+'" title="Day -'+(89-i)+'"></i>'; }).join("")+'</div></div>';
    }).join("")+'</div></div>'+
    '<div class="card mt-6"><h3>Incident history</h3>'+
    (s.incidents && s.incidents.length > 0 ? s.incidents.map(inc => '<div class="row mt-2"><div><div style="font-weight:600;color:var(--amber)">'+escapeHtml(inc.title||"Incident")+'</div><div class="text-dim text-xs">'+escapeHtml(inc.date||"")+" — "+escapeHtml(inc.description||"")+'</div></div></div>').join("") : '<div class="text-dim text-sm mt-2">No incidents in the last 90 days.</div>')+
    '</div>';
  return dashShell(inner);
}

/* ---------- Notification drawer ---------- */
async function loadNotifs(){
  if (!state.clerk || !state.clerk.user) return;
  try{ const d = await api("/api/notifications"); state.notifications = d.notifications||[]; }
  catch(e){ state.notifications = []; }
}
function openDrawer(){
  $("#drawer-back").classList.add("open");
  $("#notif-drawer").classList.add("open");
  const body = $("#notif-body");
  if (!state.notifications.length) body.innerHTML = '<div style="padding:60px 20px;text-align:center" class="text-faint"><svg class="icon xl" style="margin-bottom:12px;width:40px;height:40px"><use href="#i-bell"/></svg><div>You are all caught up!</div></div>';
  else body.innerHTML = state.notifications.map(n=>'<div class="notif '+(n.read?"":"unread")+'" data-testid="notif-item"><div class="nicon"><svg class="icon"><use href="#i-bell"/></svg></div><div><div class="msg">'+escapeHtml(n.message)+'</div><div class="time">'+fmt.rel(n.createdAt)+'</div></div></div>').join("");
}
function closeDrawer(){ $("#drawer-back").classList.remove("open"); $("#notif-drawer").classList.remove("open"); }

/* ---------- Command palette ---------- */
const COMMANDS = [
  ["Go to Dashboard","/dashboard","i-grid","G D"],
  ["Go to Profile","/profile","i-user","G P"],
  ["Go to API Keys","/keys","i-key","G K"],
  ["Go to Analytics","/analytics","i-chart","G A"],
  ["Go to Activity","/activity","i-activity","G L"],
  ["Go to Integrations","/integrations","i-zap","G I"],
  ["Go to Settings","/settings","i-settings","G S"],
  ["Open Docs","/docs","i-code",""],
  ["Open Changelog","/changelog","i-sparkles",""],
  ["Status Page","/status","i-cpu",""],
  ["Customize Appearance","/settings","i-sparkles",""],
  ["Keyboard Shortcuts","#shortcuts","i-terminal","?"],
  ["Sign Out","#signout","i-logout",""]
];
function openPalette(){
  $("#cmd-back").classList.add("open");
  const inp = $("#cmd-input"); inp.value = ""; inp.focus();
  paintPalette("");
}
function closePalette(){ $("#cmd-back").classList.remove("open"); }
function paintPalette(q){
  const list = COMMANDS.filter(c=> !q || c[0].toLowerCase().includes(q.toLowerCase()));
  const host = $("#cmd-list");
  host.innerHTML = list.map((c,i)=>'<div class="cmd-item '+(i===0?"sel":"")+'" data-cmd="'+escapeHtml(c[1])+'"><svg class="icon"><use href="#'+c[2]+'"/></svg><span>'+escapeHtml(c[0])+'</span>'+(c[3]?'<span class="kbd">'+c[3]+'</span>':'')+'</div>').join("");
  $$(".cmd-item", host).forEach(it=> it.onclick = ()=> runPalette(it.dataset.cmd));
}
function runPalette(cmd){
  closePalette();
  if (cmd === "#signout"){ if (state.clerk) state.clerk.signOut().then(()=> navigate("/")); return; }
  if (cmd === "#shortcuts"){ openShortcuts(); return; }
  navigate(cmd);
}

/* ---------- Mobile bottom nav ---------- */
function paintMobNav(){
  const nav = $("#mob-nav");
  if (!nav) return;
  if (!state.clerk || !state.clerk.user){ nav.style.display = "none"; return; }
  const links = [["/dashboard","i-grid","Home"],["/keys","i-key","Keys"],["/analytics","i-chart","Stats"],["/activity","i-activity","Logs"],["/settings","i-settings","More"]];
  nav.innerHTML = links.map(([p,i,l])=>'<a href="#'+p+'" class="mob-link '+(state.route===p?"active":"")+'" data-nav="'+p+'"><svg class="icon"><use href="#'+i+'"/></svg><span>'+l+'</span></a>').join("");
}

/* ---------- Boot ---------- */
async function boot(){
  console.log("🚀 BOOT START");
  initCursor();
  initShader();
  window.__particles = initParticles();

  // load Clerk
  console.log("📦 Loading Clerk...");
  state.clerk = await loadClerk();
  console.log("✅ Clerk loaded:", state.clerk ? "YES" : "NO (disabled/failed)");
  
  if (state.clerk){
    state.user = state.clerk.user ? {
      id: state.clerk.user.id,
      email: state.clerk.user.primaryEmailAddress ? state.clerk.user.primaryEmailAddress.emailAddress : "",
      firstName: state.clerk.user.firstName,
      lastName: state.clerk.user.lastName,
      image: state.clerk.user.imageUrl
    } : null;
    state.clerk.addListener(({ user })=>{
      if (user){
        state.user = { id:user.id, email:user.primaryEmailAddress?user.primaryEmailAddress.emailAddress:"", firstName:user.firstName, lastName:user.lastName, image:user.imageUrl };
        loadNotifs();
        api("/api/me").then(me=>{ state.isAdmin = !!me.isAdmin; state.settings = me.settings; }).catch(()=>{});
        if (state.route === "/" || !state.route) navigate("/dashboard");
        else render();
      } else {
        state.user = null; state.isAdmin = false;
        if (PROTECTED.includes(state.route)) navigate("/");
        else render();
      }
    });
    if (state.user) await loadNotifs();
    if (state.user){
      try{ const me = await api("/api/me"); state.isAdmin = !!me.isAdmin; state.settings = me.settings; }
      catch(e){ /* not logged in / 401 */ }
    }
  }

  // initial route
  state.route = location.hash.slice(1) || (state.user ? "/dashboard" : "/");

  console.log("📄 Rendering initial route:", state.route);
  await render();
  console.log("✅ Render complete");
  paintMobNav();

  // hide loader
  setTimeout(()=>{ const l = $("#load"); if (l) l.classList.add("gone"); setTimeout(()=> l && l.remove(), 500); }, 400);

  // global key bindings
  addEventListener("keydown",(e)=>{
    if ((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==="k"){ e.preventDefault(); openPalette(); }
    else if (e.key === "Escape"){ closePalette(); closeDrawer(); const sm = $("#sc-modal"); if (sm) sm.remove(); }
    else if (e.key === "?" && !["INPUT","TEXTAREA"].includes(document.activeElement && document.activeElement.tagName)){ e.preventDefault(); openShortcuts(); }
  });
  // palette input
  $("#cmd-input").addEventListener("input",(e)=> paintPalette(e.target.value));
  $("#cmd-back").addEventListener("click",(e)=>{ if (e.target.id==="cmd-back") closePalette(); });

  // drawer
  $("#drawer-back").onclick = closeDrawer;
  $("#drawer-close").onclick = closeDrawer;
  $("#mark-all-read").onclick = async ()=>{ try{ await api("/api/notifications",{method:"PATCH"}); state.notifications.forEach(n=> n.read = true); openDrawer(); }catch(e){} };

  // palette nav arrow keys
  let sel = 0;
  $("#cmd-input").addEventListener("keydown",(e)=>{
    const items = $$(".cmd-item");
    if (e.key === "ArrowDown"){ sel = (sel+1)%items.length; items.forEach((x,i)=> x.classList.toggle("sel", i===sel)); e.preventDefault(); }
    else if (e.key === "ArrowUp"){ sel = (sel-1+items.length)%items.length; items.forEach((x,i)=> x.classList.toggle("sel", i===sel)); e.preventDefault(); }
    else if (e.key === "Enter"){ if (items[sel]) runPalette(items[sel].dataset.cmd); }
  });

  // session timer
  setInterval(()=>{ const t = $("#session-timer"); if (t){ const m = Math.floor((Date.now()-state.sessionStart)/60000); t.textContent = "Active "+m+"m"; } }, 30000);

  // auto refresh status page
  setInterval(()=>{ if (state.route === "/status") render(); }, 60000);

  // mob nav repaint
  addEventListener("hashchange", paintMobNav);
  
  console.log("✅ BOOT COMPLETE");
}

document.addEventListener("DOMContentLoaded", boot);

`;
