# Void Interface

Single-file Cloudflare Worker app — Clerk auth, KV storage, ten fully-designed pages. The HTML, CSS and JS are all inlined inside `worker.js`.

## Deploy

```bash
npm install
npx wrangler login
npx wrangler kv namespace create "KV"
npx wrangler kv namespace create "KV" --preview
# paste the two IDs into wrangler.toml

npx wrangler secret put CLERK_SECRET_KEY      # paste sk_live_...
# also edit wrangler.toml [vars].CLERK_PUBLISHABLE_KEY = "pk_live_..."

npx wrangler deploy
```

## Local dev

```bash
npx wrangler dev
```

## Structure

- `worker.js` — entire app (router, API, embedded SPA HTML/CSS/JS, 25 SVG icons, particle canvas, charts, command palette, etc.)
- `wrangler.toml` — Cloudflare Worker config
- `package.json` — only dev dep is wrangler

## Required env (Cloudflare dashboard or wrangler.toml)

| Key | Where | Example |
|-----|-------|---------|
| `CLERK_PUBLISHABLE_KEY` | `[vars]` in wrangler.toml | `pk_live_xxx` |
| `CLERK_SECRET_KEY` | `wrangler secret put` | `sk_live_xxx` |
| `KV` | `[[kv_namespaces]]` binding | namespace id |

## API surface

All under `/api/*`, all protected by Clerk JWT (`Authorization: Bearer <token>`) except `/api/health` and `/api/status`.

```
GET    /api/health
GET    /api/me
GET    /api/keys
POST   /api/keys
PATCH  /api/keys/:id
DELETE /api/keys/:id
GET    /api/activity
GET    /api/analytics
GET    /api/settings
PUT    /api/settings
POST   /api/webhook-test
GET    /api/status
GET    /api/notifications
PATCH  /api/notifications
```
