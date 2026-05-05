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

## Implemented (Jan 5, 2026 — initial) + (updated Jan 5, 2026 — blue refresh)
- All 14 API routes (`/api/health`, `/api/me`, `/api/keys` CRUD, `/api/activity`, `/api/analytics`, `/api/settings`, `/api/webhook-test`, `/api/notifications`, `/api/status`)
- Clerk JWT verification (RSASSA-PKCS1-v1_5, JWKS cached)
- KV schema: `settings:<uid>`, `keys:<uid>`, `logs:<uid>` (last 100), `notifications:<uid>` (last 50), `analytics:<uid>:<date>`
- Geo headers on every response: `X-Edge-Location`, `X-Request-Country`, `X-Latency-Ms`
- All 12 pages (added /integrations and /changelog): Landing, Dashboard, Profile, API Keys, Analytics, Activity, Integrations, Settings (6 tabs), Docs, Changelog, Status, Notifications drawer, **Keyboard Shortcuts modal** (`?` key)
- Refined design: pure blue/black palette (no more cyan/violet/pink), Space Grotesk + JetBrains Mono + Manrope fonts, lighter section padding, simpler gradients, glitch animation removed, customer logos strip
- Background system: 3 blue aurora blobs, drifting grid, scan line, corner brackets, particle canvas (all blue) with constellation lines + mouse repulsion + click bursts, spotlight follow
- 30+ inlined SVG icons with stroke-current animations
- Custom 2-element cursor (dot + lagging ring) with hover states
- Hero: staggered word entrance (BUILD bright-blue / SHIP white / SCALE deep-blue), typewriter, magnetic CTAs, ripple
- Charts: animated sparkline (blue gradient), donut (blue family), histogram (blue grow), 64-city world dot map
- Command palette (`Ctrl+K` / `Cmd+K`) with arrow nav and search; new entries for Integrations, Changelog, Keyboard Shortcuts
- Toasts (5 types, swipe/click dismiss, progress bar, optional sound)
- Confetti on first API key creation (blue palette)
- Number counters animate from 0 on enter
- Settings: live sliders for grid opacity, particle density, aurora intensity, font size, accent color (8 blue swatches)
- Sidebar collapse persisted in localStorage; mobile bottom nav for ≤880px
- Reduce-motion mode respected
- Skeleton/progress bar loading states

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
