# Void Interface — PRD

## Original problem statement
Build a single `worker.js` Cloudflare Worker that serves the entire "Void Interface" SPA — landing page, dashboard, profile, API keys, analytics, activity, settings, notifications, docs, status — with Clerk auth + KV storage, embedded HTML/CSS/JS, custom cursor, particle canvas, charts, command palette, and the "Void Interface" design system. Dark `#03030a` palette with cyan/violet/pink accents. Maximum animation fidelity, zero compromise.

## Architecture
- **Single file:** `/app/worker.js` (~135 KB rendered HTML, all assets inlined)
- **Runtime:** Cloudflare Workers (ES module export default { fetch })
- **Storage:** Cloudflare KV (`KV` binding)
- **Auth:** Clerk JWT verification via JWKS (cached 10 min) — networkless
- **Frontend:** vanilla JS hash router, no framework, no build step
- **Deploy:** `wrangler deploy` after `wrangler kv namespace create` and `wrangler secret put CLERK_SECRET_KEY`

## Implemented (Jan 5, 2026 — initial) + (Jan 5, 2026 — blue refresh) + (Jan 5, 2026 — fx + admin)
- All 14 user API routes plus **8 admin API routes** under `/api/admin/*`:
  `GET /users`, `GET /users/:id`, `DELETE /users/:id`, `PUT /users/:id/settings`,
  `DELETE /users/:id/keys/:keyId`, `POST /broadcast`, `GET|PUT /content/:section`
  (`changelog`/`integrations`/`status`), `GET /stats`. 401/403 enforced.
- Clerk JWT verification (RSASSA-PKCS1-v1_5, JWKS cached). `isAdmin(user, env)` check via
  `publicMetadata.role === "admin"` + `metadata.public.role` + `org_role` + bootstrap
  via `ADMIN_EMAILS` env CSV.
- KV schema: `settings:<uid>`, `keys:<uid>`, `logs:<uid>` (last 100), `notifications:<uid>` (last 50), `analytics:<uid>:<date>`, **`content:<section>`** (admin-edited content).
- Geo headers on every response: `X-Edge-Location`, `X-Request-Country`, `X-Latency-Ms`
- All 13 pages: Landing, Dashboard, Profile, API Keys, Analytics, Activity, Integrations, Settings (6 tabs), Docs, Changelog, Status, **Admin (6 tabs: Overview/Users/Broadcast/Changelog/Integrations/Status)**, Notifications drawer, Keyboard Shortcuts modal (`?` key)
- **Real-time effects:**
  - **WebGL flow-field shader background** (fragment shader with FBM noise, mouse-pull, blue palette, capped at ~30 fps, graceful fallback if WebGL unavailable).
  - **3D parallax tilt** auto-bound to every card on every render (perspective 900px, ±7deg, radial highlight follows cursor).
  - **Animated SVG path drawing** on icon hover (stroke-dashoffset trace).
  - **Cursor trail** — fading blue dots throttled at 28ms intervals.
  - **Liquid morphing gradient text** on hero h1 via SVG `<feTurbulence>` + `<feDisplacementMap>` filter.
- Refined design: pure blue/black palette, Space Grotesk + JetBrains Mono + Manrope fonts, lighter section padding, simpler gradients.
- Background system also retains: 3 blue aurora blobs, drifting grid, scan line, corner brackets, particle constellation canvas, spotlight follow.
- 30+ inlined SVG icons, custom 2-element cursor, magnetic CTAs, hero glitch (disabled in blue theme), customer logos strip.
- Charts: animated sparkline, donut, histogram (all blue), 64-city world dot map.
- Command palette (`Ctrl+K`) with arrow nav and search; entries for every page including Admin (when admin).
- Toasts (5 types), confetti on first key, number counters, settings live sliders, mobile bottom nav, reduce-motion respected.

## Configuration the user must complete
1. `wrangler kv namespace create "KV"` → paste id into `wrangler.toml`
2. Update `[vars].CLERK_PUBLISHABLE_KEY` in `wrangler.toml`
3. `wrangler secret put CLERK_SECRET_KEY` (paste real `sk_live_…`)
4. `wrangler deploy`

## Backlog / Future
- 2FA flow for Settings → Security
- Webhook signature verification helper
- Server-side rate limiting via KV counter
- Real device list integration (Clerk `getSessions`)
- WebSocket upgrade for live activity (currently polled)
- Light theme parity
- Export-as-PDF for Analytics

## Deferred
- Pull-to-refresh on dashboard (mobile)
- Swipe-left-to-delete on log rows (mobile)
- Sora-quality 3D bg (current uses 2D canvas)

## Test credentials
None — auth flows through Clerk directly. To test the live app, sign up via the Clerk modal triggered by "Get Started" once a real publishable key is set.
