# HostCop

Neutral hosting watchdog. Paste a domain → HostCop detects who really hosts it
(IP → ASN), measures it live (response time, up/down), and ranks every host by
real crowdsourced data. No reviews, no affiliate bias.

## Stack
Cloudflare Worker + D1 + cron. No API keys, no paid services.

## Deploy
```bash
npm i -g wrangler
wrangler login

wrangler d1 create hostcop
# paste the printed database_id into wrangler.toml

wrangler d1 execute hostcop --remote --file=schema.sql
wrangler deploy
```

Local dev:
```bash
wrangler d1 execute hostcop --local --file=schema.sql
wrangler dev
```

## Routes
- `/`                    — home: hero + how-it-works + features + example + copy
- `/check/:domain`       — detect host (+CDN flag), measure, store; shareable URL
- `/check?domain=`       — same, query form (no-JS fallback)
- `/api/check?domain=`   — JSON API (CORS-open) for the badge / external use
- `/host/:provider`      — live stats + recent sites for one host
- `/hosts?sort=`         — leaderboard (uptime | speed | tested)
- `/badge/:domain.svg`   — embeddable "verified by HostCop" badge
- `/methodology` `/about` `/guides` `/guides/:slug` `/privacy` `/terms` `/contact`
- `/sitemap.xml` `/robots.txt` `/favicon.svg` `/og.svg`
- `www.*` → apex 301 redirect; custom 404
- cron (30 min)          — re-pings every tracked domain to keep data fresh

## How detection works (all free, all inside the Worker)
- **A record**: Cloudflare DNS-over-HTTPS (`cloudflare-dns.com/dns-query`)
- **IP → ASN + org name**: Team Cymru's free DNS service over DoH
- **Performance**: `fetch()` the domain, time it, record status
- **SSL expiry**: raw TCP via `cloudflare:sockets` + a hand-built TLS 1.2
  ClientHello; the cert's `notAfter` is parsed straight out of the handshake
  bytes (no fetch, no API). Servers that are TLS 1.3-only return null.

## The moat
Every check anyone runs is stored in `checks`. More checks → better rankings →
more useful → more checks. It compounds without you writing any content.

## v1.1 (deliberately left out to keep v1 tiny)
- Multi-region timing (measure from several CF colos via Durable Objects)
- Email alerts when a monitored host goes down
- Affiliate links on host pages, ranked by *your* data so it stays credible
