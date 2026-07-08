// HostCop — neutral hosting watchdog. Detect who really hosts a domain (behind
// CDNs/resellers), measure live performance, read SSL expiry, and rank hosts by
// crowdsourced real data. Stack: Cloudflare Worker + D1. No API keys, no paid APIs.

import { connect } from "cloudflare:sockets";

const BASE = "https://hostcop.com";
const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/125.0 Safari/537.36";

// The HostCop emblem (gold shield + magnifier) as a PNG, for email clients that
// won't render SVG. Served at /logo.png. Matches the nav emblem and favicon.
const LOGO_PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAEgAAABICAYAAABV7bNHAAAC+0lEQVR42u3bPUzbUBAHcLsISguUqFRCbBFLFwYmWGFgYkFC6hwxsnVgJjNDp66tZ6RKDN5YMjNlZcvWNZNno7+VJ1lXO67te5+5k54CSEF5P7+792EniiQkJCQkJCQkJCR0RJbGx1kaj7M0njjW8JmObaEMFx9glqVx7nibLT7r0BRM4gFKXUu0QWVpPPIYhrYRN85VQDiqXXECPQUI9MQJNAkQaCJAPgK9/FzPx6Ot/OJ0t2gfd77kXw8/Fz/fXO7kv+4287+P71YP6M/9+/zkaFCANLWD/b0CSzOUG0DopBopbRugMKKCBUI6oZNdcMoNoyk4oNffa7U4qtYAUI2y54eN/Mfth6IeGUKyC1RVb5BqgGt6L/CqcJnTzR4QZqm+IwCjiyIDjbFw2wFCB+jV75oeVTWMMdXsANHRg5rS56ojrTSNIjtANC046gYt3Ey1yDwQriytPRzpgNlNQ5qZB8JUTWctDiBN/9c+0Pdv2yxAdGQi5bwEogUVBZtr3aIhde2PoOvzT2wnAEGkGO0IUyr8MzK9BUKjCzu13+rTMGtpSF07QEgrzikZezdafzjQrQHROoSGv3VNLbrwxO/eb1bpARnSru1VxxKh6tgDJ5PeA9FirZD+dyRVrciD2c3XbQ/KNWnZaEJa1R2aqRRzcbOacMw+dAmAgo4ZCenU5tyaCSnhBBpkaTzl2GhytZ5I6MuA+/58ZySkVNs7G6g3GF3LbhV1ROLH4UBSSwCk1bI7Heg0YFTH8cqIpA+HC6k8qgCGooxXtLqOMiHpxyFIRp8ua0Jq2BjPjOGQZxPnLiHVvG9u81lFZ5BQ15zCcQ2p4iDfPo5NJLXqxoxXsTJ3B6eEdObQw1Fnrj5U7sKTsKPI5bCM5DaOZSQ/cCwh+YVTQhobwBlHPofm73YkUQihCSkMHE1IYeEwI4WJU0Lqc5Y0jUKPHgduU+NnOh4hrQ5OB6TVw2mBtLo4JaRhzVnS3Mg3lT1Bogdu7h14OYQkOA1IgiMhISGxiDe3as830gEmQwAAAABJRU5ErkJggg==";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Canonical host: www -> apex (SSL + one canonical URL everywhere)
    if (url.hostname.startsWith("www.")) {
      url.hostname = url.hostname.slice(4);
      return Response.redirect(url.toString(), 301);
    }

    const p = url.pathname.replace(/\/+$/, "") || "/";
    try {
      if (p === "/")             return handleHome(env);
      if (p === "/robots.txt")   return robots();
      if (p === "/sitemap.xml")  return sitemap(env);
      if (p === "/favicon.svg")  return favicon();
      if (p === "/logo.png")     return logoPng();
      if (p === "/og.svg")       return ogImage();
      if (p === "/api/check")    return apiCheck(url, request, env);
      if (p === "/check")        return handleCheck(cleanDomain(url.searchParams.get("domain") || ""), request, env);
      if (p.startsWith("/check/")) return handleCheck(cleanDomain(decodeURIComponent(p.slice(7))), request, env);
      if (p === "/hosts")        return handleLeaderboard(url, env);
      if (p.startsWith("/host/"))  return handleProvider(decodeURIComponent(p.slice(6)), env);
      if (p.startsWith("/badge/")) return handleBadge(decodeURIComponent(p.slice(7)).replace(/\.svg$/, ""), env);
      if (p === "/api")          return pageApi();
      if (p === "/bulk")         return handleBulk();
      if (p === "/compare")      return handleCompare(url, env, null);
      if (p.startsWith("/compare/")) return handleCompare(url, env, decodeURIComponent(p.slice(9)));
      if (p === "/monitor")      return request.method === "POST" ? handleMonitorCreate(request, env) : pageMonitor(url);
      if (p === "/monitor/verify")      return handleMonitorVerify(url, env);
      if (p === "/monitor/unsubscribe") return handleMonitorUnsub(url, env);
      if (p === "/pricing")      return pagePricing(url, env);
      if (p === "/upgrade")      return handleUpgrade(request, env, url);
      if (p === "/pro/welcome")  return pageProWelcome(url);
      if (p === "/stripe/webhook") return handleStripeWebhook(request, env);
      if (p === "/tools")        return pageTools();
      if (p === "/down" || p.startsWith("/down/"))       return toolDown(toolDomain(url, p, "/down"), env);
      if (p === "/ssl" || p.startsWith("/ssl/"))         return toolSsl(toolDomain(url, p, "/ssl"));
      if (p === "/dns-propagation" || p.startsWith("/dns-propagation/")) return toolPropagation(toolDomain(url, p, "/dns-propagation"));
      if (p === "/dns" || p.startsWith("/dns/"))         return toolDns(toolDomain(url, p, "/dns"));
      if (p === "/redirect" || p.startsWith("/redirect/")) return toolRedirect(toolDomain(url, p, "/redirect"));
      if (p === "/email" || p.startsWith("/email/"))     return toolEmail(toolDomain(url, p, "/email"));
      if (p === "/headers" || p.startsWith("/headers/")) return toolHeaders(toolDomain(url, p, "/headers"));
      if (p === "/reverse-ip" || p.startsWith("/reverse-ip/"))
        return toolReverseIp((p.startsWith("/reverse-ip/") ? decodeURIComponent(p.slice(12)) : (url.searchParams.get("domain") || "")).trim().toLowerCase(), env);
      if (p === "/whois" || p.startsWith("/whois/"))     return toolWhois(toolDomain(url, p, "/whois"));
      if (p === "/tech" || p.startsWith("/tech/"))       return toolTech(toolDomain(url, p, "/tech"));
      if (p === "/speed" || p.startsWith("/speed/"))     return toolSpeed(toolDomain(url, p, "/speed"), request, env);
      if (p === "/methodology")  return pageMethodology();
      if (p === "/about")        return pageAbout();
      if (p === "/guides")       return pageGuidesIndex();
      if (p.startsWith("/guides/")) return pageGuide(p.slice(8));
      if (p === "/privacy")      return pagePrivacy();
      if (p === "/terms")        return pageTerms();
      if (p === "/contact")      return pageContact();
      return notFound();
    } catch (e) {
      return html(layout({ title: "Error · HostCop", desc: "", path: p,
        body: `<h1>Something broke</h1><p class="muted">${esc(e.message)}</p>` }), 500);
    }
  },

  // Cron: */5 = Pro monitors (frequent); */30 = free+pro monitors + rankings sweep.
  async scheduled(event, env, ctx) {
    if (event.cron === "*/5 * * * *") {
      ctx.waitUntil(runMonitors(env, "pro"));
      return;
    }
    ctx.waitUntil(runMonitors(env, "all"));          // uptime/SSL email alerts
    const { results } = await env.DB.prepare(
      "SELECT domain FROM domains ORDER BY last_checked ASC LIMIT 50"
    ).all();
    for (const row of results) ctx.waitUntil(runCheck(row.domain, "cron", env));
  },
};

// ========================================================================
// MULTI-REGION: a Durable Object placed in each region measures from there
// ========================================================================

// Cloudflare location hints → friendly labels. Each becomes one prober DO.
const REGIONS = [
  ["enam", "N. America"],
  ["weur", "Europe"],
  ["apac", "Asia"],
  ["sam", "S. America"],
  ["oc", "Oceania"],
];

// The prober runs inside a region and times a single request to the target.
export class Prober {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(request) {
    const target = new URL(request.url).searchParams.get("url");
    if (!target) return Response.json({ error: "no url" }, { status: 400 });
    const t0 = Date.now();
    let status = 0, up = false;
    try {
      const r = await fetch(target, {
        redirect: "manual", cf: { cacheTtl: 0 }, signal: AbortSignal.timeout(8000),
        headers: { "user-agent": BROWSER_UA, accept: "text/html,application/xhtml+xml,*/*;q=0.8" },
      });
      status = r.status; up = true;
      try { await r.body?.cancel(); } catch { }
    } catch { }
    return Response.json({ ms: Date.now() - t0, status, up });
  }
}

// Fan out to every regional prober in parallel. Returns per-region results,
// or null if Durable Objects aren't available (falls back to single region).
async function probeRegions(url, env) {
  if (!env.PROBER) return null;
  return Promise.all(REGIONS.map(async ([hint, label]) => {
    try {
      const stub = env.PROBER.get(env.PROBER.idFromName(hint), { locationHint: hint });
      const d = await Promise.race([
        stub.fetch(`https://prober/?url=${encodeURIComponent(url)}`).then(r => r.json()),
        new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 12000)),
      ]);
      return { hint, label, ms: d.ms ?? null, status: d.status ?? 0, up: !!d.up };
    } catch { return { hint, label, ms: null, status: 0, up: false }; }
  }));
}

// ========================================================================
// CORE: detect + measure + store
// ========================================================================

async function runCheck(domain, region, env) {
  domain = cleanDomain(domain);
  if (!domain) return null;

  const ips = await resolveAllA(domain);
  if (!ips.length) return { domain, noDns: true };    // domain doesn't point anywhere

  // Majority ASN across the A records; flag when they span multiple providers.
  const distinctIps = [...new Set(ips)];
  const asns = await Promise.all(distinctIps.slice(0, 4).map(ip => ipToAsn(ip).catch(() => null)));
  const tally = {};
  asns.forEach(a => { if (a) (tally[a.name] ||= { n: 0, asn: a.asn, country: a.country }).n++; });
  let provider = "Unknown", asn = null, country = null, best = -1;
  for (const [name, v] of Object.entries(tally)) if (v.n > best) { best = v.n; provider = name; asn = v.asn; country = v.country; }
  const loadBalanced = Object.keys(tally).length > 1;
  const brand = cleanProvider(provider);
  const ip = distinctIps[0];

  const [pr, ssl] = await Promise.all([probe(domain), getSslExpiry(domain)]);
  const sslExpiry = ssl?.expiry ?? null;
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO checks (domain, ip, asn, provider, brand, country, response_ms, http_status, up, ssl_expiry, region, checked_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(domain, ip, asn, provider, brand, country,
         pr.ms, pr.finalStatus, pr.up ? 1 : 0, sslExpiry, region, now).run();

  await env.DB.prepare(
    `INSERT INTO domains (domain, provider, added_at, last_checked)
     VALUES (?,?,?,?)
     ON CONFLICT(domain) DO UPDATE SET provider=excluded.provider, last_checked=excluded.last_checked`
  ).bind(domain, provider, now, now).run();

  return { domain, ip, ips: distinctIps, provider, brand, country, asn, loadBalanced,
           sslExpiry, sslIssuer: ssl?.issuer ?? null, ...pr };
}

// Resolve A record via Cloudflare DNS-over-HTTPS (no key needed)
async function resolveA(domain) {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
    { headers: { accept: "application/dns-json" } });
  const j = await r.json();
  return (j.Answer || []).find(a => a.type === 1)?.data ?? null;
}

// All A records — used to detect load-balancing across providers.
async function resolveAllA(domain) {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
    { headers: { accept: "application/dns-json" } });
  const j = await r.json();
  return (j.Answer || []).filter(a => a.type === 1).map(a => a.data);
}

// IP -> ASN + org name + country via Team Cymru's free DNS service (over DoH)
async function ipToAsn(ip) {
  const rev = ip.split(".").reverse().join(".");
  const t1 = await dohTxt(`${rev}.origin.asn.cymru.com`);
  if (!t1) return null;
  const parts = t1.split("|");                       // "13335 | 1.1.1.0/24 | US | arin | ..."
  const asn = parts[0].trim();
  const country = (parts[2] || "").trim() || null;
  const t2 = await dohTxt(`AS${asn}.asn.cymru.com`); // "13335 | US | arin | ... | CLOUDFLARENET, US"
  const name = t2 ? t2.split("|").pop().trim().replace(/,\s*[A-Z]{2}$/, "") : `AS${asn}`;
  return { asn, name, country };
}

async function dohTxt(name) {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${name}&type=TXT`,
    { headers: { accept: "application/dns-json" } });
  const j = await r.json();
  return (j.Answer || []).find(a => a.type === 16)?.data?.replace(/"/g, "") ?? null;
}

async function dohAll(name, type) {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${name}&type=${type}`,
      { headers: { accept: "application/dns-json" } });
    const j = await r.json();
    return (j.Answer || []).map(a => a.data);
  } catch { return []; }
}

const baseDomain = h => {
  h = (h || "").replace(/\.$/, "").toLowerCase();
  const p = h.split(".");
  return p.length <= 2 ? h : p.slice(-2).join(".");
};

// Unmask the real origin behind a CDN, plus email / DNS host intel — all via DNS.
// Mail and origin-leaking subdomains usually aren't proxied, so they betray the
// true host even when the front door is Cloudflare/Akamai/etc.
async function discoverOrigin(domain, mainProvider) {
  const cdn = isCdn(mainProvider);
  const subs = ["direct", "cpanel", "webmail", "ftp", "mail", "server", "origin", "webdisk"];
  const [mxData, nsData, subIps] = await Promise.all([
    dohAll(domain, "MX"),
    dohAll(domain, "NS"),
    cdn ? Promise.all(subs.map(s => resolveA(`${s}.${domain}`).catch(() => null))) : Promise.resolve([]),
  ]);

  // Email host: first MX record -> registrable domain (+ the network that runs it)
  let mailHost = null, mailProvider = null;
  if (mxData.length) {
    const host = mxData[0].split(/\s+/).pop();          // "10 mail.example.com."
    mailHost = baseDomain(host);
    const mip = await resolveA(host).catch(() => null);
    if (mip) { const a = await ipToAsn(mip).catch(() => null); if (a) mailProvider = a.name; }
  }

  // DNS host: first NS record -> registrable domain
  const dnsHost = nsData.length ? baseDomain(nsData[0]) : null;

  // Origin: first origin-leaking subdomain whose network isn't the CDN itself
  let origin = null;
  if (cdn) {
    const found = subs.map((s, i) => ({ sub: s, ip: subIps[i] })).filter(x => x.ip);
    const distinct = [...new Map(found.map(x => [x.ip, x])).values()].slice(0, 4);
    for (const d of distinct) {
      const a = await ipToAsn(d.ip).catch(() => null);
      if (a && !isCdn(a.name)) {
        origin = { ip: d.ip, provider: a.name, method: `${d.sub}.${domain}`, country: a.country };
        break;
      }
    }
  }
  return { cdn, origin, mailHost, mailProvider, dnsHost };
}

// SSL cert expiry. fetch() won't give us the cert, so we open a raw TCP socket,
// send a hand-built TLS 1.2 ClientHello, and read notAfter out of the handshake.
async function getSslExpiry(domain) {
  let socket;
  try {
    socket = connect({ hostname: domain, port: 443 },
                     { secureTransport: "off", allowHalfOpen: false });
    const writer = socket.writable.getWriter();
    await writer.write(buildClientHello(domain));

    const reader = socket.readable.getReader();
    let buf = new Uint8Array(0);
    const deadline = Date.now() + 5000;
    let der = null;

    while (Date.now() < deadline) {
      let chunk;
      try { chunk = await withTimeout(reader.read(), deadline - Date.now()); }
      catch { break; }
      if (chunk.done || !chunk.value) break;
      buf = concatBytes(buf, chunk.value);
      der = extractLeafCert(buf);          // null = need more, "ALERT" = give up
      if (der) break;
    }
    try { reader.releaseLock(); writer.releaseLock(); } catch {}
    await socket.close().catch(() => {});
    if (!der || der === "ALERT") return null;
    let expiry = null, issuer = null;
    try { expiry = parseNotAfter(der); } catch {}
    try { issuer = parseIssuer(der); } catch {}
    return { expiry, issuer };
  } catch {
    try { await socket?.close(); } catch {}
    return null;
  }
}

// Pull the issuer organisation (O), falling back to CN, out of the cert DER.
function parseIssuer(der) {
  const cert = tlv(der, 0);
  const tbs = tlv(der, cert.headerEnd);
  const kids = [];
  let p = tbs.headerEnd;
  while (p < tbs.valueEnd) { const c = tlv(der, p); kids.push(c); p = c.valueEnd; }
  const vi = kids[0].tag === 0xa0 ? 4 : 3;      // validity index
  const issuer = kids[vi - 1];                   // issuer Name is right before it
  const buf = der.subarray(issuer.headerEnd, issuer.valueEnd);
  const find = oid => {
    for (let i = 0; i + oid.length < buf.length; i++) {
      let m = true;
      for (let k = 0; k < oid.length; k++) if (buf[i + k] !== oid[k]) { m = false; break; }
      if (m) { const v = tlv(buf, i + oid.length); return new TextDecoder().decode(buf.subarray(v.headerEnd, v.valueEnd)); }
    }
    return null;
  };
  return find([0x06, 0x03, 0x55, 0x04, 0x0a]) || find([0x06, 0x03, 0x55, 0x04, 0x03]); // O, then CN
}

// Reverse DNS (PTR) for an IP — evidence about the machine behind the address.
async function reverseDns(ip) {
  const rev = ip.split(".").reverse().join(".") + ".in-addr.arpa";
  const a = await dohAll(rev, "PTR");
  return a.length ? a[0].replace(/\.$/, "") : null;
}

// Generic wholesale infrastructure — if a "host" really runs here, it's a reseller.
const INFRA_NAMES = ["AMAZON", "AWS", "GOOGLE", "MICROSOFT", "AZURE", "HETZNER", "OVH",
  "DIGITALOCEAN", "LINODE", "AKAMAI-LINODE", "VULTR", "SOFTLAYER", "IBM", "INTERNAP",
  "LEASEWEB", "CONTABO", "ORACLE", "SCALEWAY", "ONLINE-NET", "DATACAMP", "PACKET"];
const isInfra = name => { const u = (name || "").toUpperCase(); return INFRA_NAMES.some(c => u.includes(c)); };

// Ranking thresholds — a host must clear these to be ranked (kills n=1 rankings).
const RANK_MIN_SITES = 3;
const RANK_MIN_CHECKS = 10;

// Raw ASN org -> clean brand name. Ordered specific-before-generic.
const BRANDS = [
  ["CLOUDFLARE", "Cloudflare"], ["AKAMAI", "Akamai"], ["FASTLY", "Fastly"],
  ["CLOUDFRONT", "Amazon CloudFront"], ["GOOGLE-CLOUD", "Google Cloud"], ["GOOGLE", "Google"],
  ["AMAZON", "Amazon AWS"], ["AWS", "Amazon AWS"], ["AZURE", "Microsoft Azure"], ["MICROSOFT", "Microsoft"],
  ["FACEBOOK", "Meta"], ["META-", "Meta"], ["DIGITALOCEAN", "DigitalOcean"], ["HETZNER", "Hetzner"],
  ["OVH", "OVHcloud"], ["LINODE", "Linode"], ["VULTR", "Vultr"], ["GODADDY", "GoDaddy"],
  ["HOSTINGER", "Hostinger"], ["SITEGROUND", "SiteGround"], ["BLUEHOST", "Bluehost"],
  ["UNIFIEDLAYER", "Bluehost"], ["HOSTGATOR", "HostGator"], ["NAMECHEAP", "Namecheap"],
  ["SOFTLAYER", "IBM Cloud"], ["IBM", "IBM Cloud"], ["INTERNAP", "Internap"], ["LEASEWEB", "Leaseweb"],
  ["CONTABO", "Contabo"], ["SCALEWAY", "Scaleway"], ["AUTOMATTIC", "Automattic"], ["GITHUB", "GitHub"],
  ["SHOPIFY", "Shopify"], ["ORACLE", "Oracle Cloud"], ["ALIBABA", "Alibaba Cloud"], ["TENCENT", "Tencent Cloud"],
  ["DREAMHOST", "DreamHost"], ["A2HOSTING", "A2 Hosting"], ["A2-", "A2 Hosting"], ["GCORE", "Gcore"],
  ["G-CORE", "Gcore"], ["NETLIFY", "Netlify"], ["VERCEL", "Vercel"], ["WPENGINE", "WP Engine"],
  ["WP-ENGINE", "WP Engine"], ["KINSTA", "Kinsta"], ["INMOTION", "InMotion"], ["LIQUIDWEB", "Liquid Web"],
  ["RACKSPACE", "Rackspace"], ["IONOS", "IONOS"], ["1AND1", "IONOS"],
];
function cleanProvider(raw) {
  if (!raw || raw === "Unknown") return "Unknown";
  const u = raw.toUpperCase();
  for (const [k, v] of BRANDS) if (u.includes(k)) return v;
  let s = raw.includes(" - ") ? raw.split(" - ").slice(1).join(" - ") : raw;
  s = s.replace(/,\s*[A-Z]{2}$/, "").replace(/[.,]?\s*(Inc|LLC|Ltd|Corp|Corporation|Co|GmbH|S\.?A|B\.?V|AB|Pty)\.?$/i, "").trim();
  return s || raw;
}

// Known domain-parking / for-sale networks.
const PARKING = ["SEDO", "BODIS", "AFTERNIC", "PARKINGCREW", "ABOVE.COM", "HUGEDOMAINS",
  "DAN.COM", "UNIREGISTRY", "PARKLOGIC", "SKENZO", "FASTPARK", "NAMEDRIVE", "PARK.IO"];
function looksParked(res, oi) {
  const hay = [res.provider, oi?.dnsHost, oi?.mailHost].filter(Boolean).join(" ").toUpperCase();
  return PARKING.some(p => hay.includes(p));
}

const speedWord = ms => ms < 200 ? "fast response" : ms < 500 ? "average response"
  : ms < 1000 ? "slow response" : "very slow response";

function statusText(s) {
  if (!s) return "no response";
  if (s === 200) return "OK";
  if ([301, 302, 303, 307, 308].includes(s)) return "redirect";
  if (s === 403 || s === 429) return "up but blocking automated visitors (common for big sites)";
  if (s === 404) return "homepage returns Not Found — possibly misconfigured";
  if (s >= 500) return "server error — the site may be having problems";
  if (s >= 400) return `client error (${s})`;
  return String(s);
}

const shortUrl = u => (u || "").replace(/^https?:\/\//, "").replace(/\/$/, "");

// One-sentence verdict: speed judgment + worst-applicable health judgment.
function buildVerdict(res, pctFaster) {
  const loc = res.country ? `${flag(res.country)} ${esc(res.country)}` : null;
  const days = res.sslExpiry != null ? Math.round((res.sslExpiry - Date.now()) / 86400000) : null;
  const s = res.finalStatus;
  let emoji = "✅", cls = "ok", health = "healthy setup";
  if (days != null && days < 0) { emoji = "🔴"; cls = "down"; health = "its SSL certificate has expired"; }
  else if (s >= 500) { emoji = "⚠️"; cls = "warn"; health = `the server is returning errors (${s})`; }
  else if (res.loop) { emoji = "⚠️"; cls = "warn"; health = "it's stuck in a redirect loop"; }
  else if (res.tooLong) { emoji = "⚠️"; cls = "warn"; health = "it has a very long redirect chain"; }
  else if (days != null && days < 30) { emoji = "⚠️"; cls = "warn"; health = `its SSL certificate expires in ${days} days`; }
  else if (s === 403 || s === 429) { emoji = "🟡"; cls = "note"; health = "it's up but blocking automated checks (likely fine for humans)"; }
  else if (s === 404) { emoji = "🟡"; cls = "note"; health = "its homepage returns Not Found (404)"; }
  else if (s >= 400) { emoji = "🟡"; cls = "note"; health = `its homepage returns ${s}`; }
  else if (days != null && days < 60) { emoji = "🟡"; cls = "note"; health = `SSL renews in ${days} days`; }
  const speed = speedWord(res.ms) +
    (res.ms < 200 && pctFaster != null && pctFaster >= 40 ? ` (faster than ${pctFaster}% of sites we've checked)` : "");
  return { line: `<b>${esc(res.domain)}</b> runs on <b>${esc(res.brand)}</b>${loc ? ` from ${loc}` : ""} — ${speed}, ${health}. ${emoji}`, cls };
}

// Minimal TLS 1.2 ClientHello with SNI; we omit supported_versions so a TLS 1.3
// server falls back to 1.2 and sends its Certificate in the clear.
function buildClientHello(host) {
  const name = new TextEncoder().encode(host);
  const sni = ext(0x0000, concatBytes(u16(name.length + 3),
    Uint8Array.of(0x00), u16(name.length), name));
  const groups = ext(0x000a, concatBytes(u16(6), u16(0x001d), u16(0x0017), u16(0x0018)));
  const points = ext(0x000b, Uint8Array.of(1, 0x00));
  const sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0601, 0x0201];
  const sigExt = ext(0x000d, concatBytes(u16(sigs.length * 2), ...sigs.map(u16)));
  // Empty renegotiation_info (RFC 5746). Strict CDNs like Cloudflare abort the
  // handshake without it, which made the cert unreadable on TLS-1.3-default hosts.
  const reneg = ext(0xff01, Uint8Array.of(0x00));
  const extensions = concatBytes(sni, groups, points, sigExt, reneg);

  const ciphers = [0xc02f, 0xc030, 0xc02b, 0xc02c, 0x009c, 0x009d, 0x002f, 0x0035];
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);

  const body = concatBytes(
    u16(0x0303), random, Uint8Array.of(0),
    u16(ciphers.length * 2), ...ciphers.map(u16),
    Uint8Array.of(1, 0x00),
    u16(extensions.length), extensions);
  const hs = concatBytes(Uint8Array.of(1), u24(body.length), body);
  return concatBytes(Uint8Array.of(22), u16(0x0301), u16(hs.length), hs);
}

function extractLeafCert(buf) {
  const hs = [];
  let p = 0;
  while (p + 5 <= buf.length) {
    const type = buf[p];
    const len = (buf[p + 3] << 8) | buf[p + 4];
    if (p + 5 + len > buf.length) break;
    if (type === 21) return "ALERT";
    if (type === 22) for (let i = 0; i < len; i++) hs.push(buf[p + 5 + i]);
    p += 5 + len;
  }
  const H = Uint8Array.from(hs);
  let q = 0;
  while (q + 4 <= H.length) {
    const mlen = (H[q + 1] << 16) | (H[q + 2] << 8) | H[q + 3];
    if (q + 4 + mlen > H.length) break;
    if (H[q] === 11) {
      const b = H.subarray(q + 4);
      const certLen = (b[3] << 16) | (b[4] << 8) | b[5];
      return b.subarray(6, 6 + certLen);
    }
    q += 4 + mlen;
  }
  return null;
}

function parseNotAfter(der) {
  const cert = tlv(der, 0);
  const tbs = tlv(der, cert.headerEnd);
  const kids = [];
  let p = tbs.headerEnd;
  while (p < tbs.valueEnd) { const c = tlv(der, p); kids.push(c); p = c.valueEnd; }
  const validity = kids[kids[0].tag === 0xa0 ? 4 : 3];
  const notBefore = tlv(der, validity.headerEnd);
  const notAfter = tlv(der, notBefore.valueEnd);
  const s = new TextDecoder().decode(der.subarray(notAfter.headerEnd, notAfter.valueEnd));
  let i = 0, y;
  if (notAfter.tag === 0x17) { y = +s.slice(0, 2); y += y < 50 ? 2000 : 1900; i = 2; }
  else { y = +s.slice(0, 4); i = 4; }
  return Date.UTC(y, +s.slice(i, i + 2) - 1, +s.slice(i + 2, i + 4),
                  +s.slice(i + 4, i + 6), +s.slice(i + 6, i + 8), +s.slice(i + 8, i + 10) || 0);
}

const u16 = n => Uint8Array.of((n >> 8) & 255, n & 255);
const u24 = n => Uint8Array.of((n >> 16) & 255, (n >> 8) & 255, n & 255);
const ext = (type, data) => concatBytes(u16(type), u16(data.length), data);
function concatBytes(...parts) {
  const total = parts.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of parts) { out.set(a, o); o += a.length; }
  return out;
}
function tlv(buf, pos) {
  const tag = buf[pos]; let p = pos + 1, len = buf[p++];
  if (len & 0x80) { let n = len & 0x7f; len = 0; while (n--) len = (len << 8) | buf[p++]; }
  return { tag, len, headerEnd: p, valueEnd: p + len };
}
const withTimeout = (promise, ms) => Promise.race([
  promise,
  new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), Math.max(0, ms))),
]);

function fetchOnce(url) {
  return fetch(url, {
    redirect: "manual",
    cf: { cacheTtl: 0 },
    signal: AbortSignal.timeout(8000),
    headers: {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
        "(KHTML, like Gecko) Chrome/125.0 Safari/537.36",
      "accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    },
  });
}

// Follow the redirect chain (max 5 hops) and time the FINAL destination — a fast
// 301 tells you nothing about the real page. A server is "up" if it answers with
// ANY status (200/301/even a 403 bot-block). Only a connection failure/timeout is
// down, and the first hop retries once before we call it down.
async function probe(domain) {
  const chain = [], seen = new Set();
  let url = `https://${domain}/`;
  let up = false, ms = 0, finalStatus = 0, finalUrl = url, server = null, loop = false, tooLong = false;

  for (let hop = 0; ; hop++) {
    if (hop > 5) { tooLong = true; break; }
    let r; const t0 = Date.now();
    try { r = await fetchOnce(url); }
    catch {
      if (hop === 0) {
        try { r = await fetchOnce(url); }             // one retry on the first hop
        catch { return { up: false, ms: 0, finalStatus: 0, finalUrl: url, chain, loop: false, tooLong: false, server: null }; }
      } else break;                                   // later hop failed — keep what we have
    }
    ms = Date.now() - t0;
    up = true; finalStatus = r.status; finalUrl = url;
    let sv = r.headers.get("server");
    if (sv && sv.toLowerCase() === "cloudflare") sv = null;   // Worker egress lies; drop it
    server = sv;
    chain.push({ url, status: r.status });
    const loc = r.headers.get("location");
    if ([301, 302, 303, 307, 308].includes(r.status) && loc) {
      let next; try { next = new URL(loc, url).toString(); } catch { break; }
      if (seen.has(next)) { loop = true; break; }
      seen.add(url); url = next; continue;
    }
    break;                                            // final (non-redirect) destination
  }
  return { up, ms, finalStatus, finalUrl, chain, loop, tooLong, server };
}

// CDN / edge-network detection: if the A record points here, the true origin is masked.
const CDN_NAMES = ["CLOUDFLARE", "AKAMAI", "FASTLY", "CLOUDFRONT", "INCAPSULA", "IMPERVA",
  "SUCURI", "STACKPATH", "BUNNY", "KEYCDN", "CDN77", "EDGECAST", "EDGIO", "LIMELIGHT",
  "CACHEFLY", "GCORE", "G-CORE", "QUIC", "JSDELIVR", "NETLIFY", "VERCEL", "FLY.IO"];
const isCdn = name => { const u = (name || "").toUpperCase(); return CDN_NAMES.some(c => u.includes(c)); };

// ========================================================================
// ROUTES: lookups
// ========================================================================

async function apiCheck(url, request, env) {
  const domain = cleanDomain(url.searchParams.get("domain") || "");
  if (!domain) return json({ error: "invalid domain" }, 400);
  const res = await runCheck(domain, request.cf?.colo || "edge", env);
  if (!res) return json({ error: "lookup failed" }, 502);
  if (res.noDns) return json({ domain: res.domain, resolves: false,
    verdict: `${res.domain} doesn't point anywhere — no DNS records found.` });

  const [oi, rdns] = await Promise.all([
    discoverOrigin(res.domain, res.provider),
    res.ip ? reverseDns(res.ip) : Promise.resolve(null),
  ]);
  const pctRow = res.up ? await env.DB.prepare(
    "SELECT ROUND(100.0*AVG(CASE WHEN response_ms > ? THEN 1 ELSE 0 END)) p FROM checks WHERE up=1"
  ).bind(res.ms).first() : null;
  const parked = looksParked(res, oi);
  const verdict = !res.up ? `${res.domain} appears to be down — the server didn't respond.`
    : parked ? `${res.domain} is a parked domain — not hosting a real website.`
    : buildVerdict(res, pctRow?.p ?? null).line.replace(/<\/?b>/g, "");
  return json({
    domain: res.domain, verdict,
    ip: res.ip, asn: res.asn ? "AS" + res.asn : null,
    host: res.brand, provider: res.provider, country: res.country, cdn: isCdn(res.brand),
    load_balanced: res.loadBalanced, parked,
    origin_provider: oi.origin ? cleanProvider(oi.origin.provider) : null, origin_ip: oi.origin?.ip ?? null,
    origin_found_via: oi.origin?.method ?? null,
    reseller: !!(oi.origin && isInfra(oi.origin.provider)),
    email_host: oi.mailHost, dns_host: oi.dnsHost,
    reverse_dns: rdns, server: res.server,
    up: res.up, response_ms: res.ms, http_status: res.finalStatus, final_url: res.finalUrl,
    redirects: res.chain, redirect_loop: res.loop || false,
    ssl_expiry: res.sslExpiry ? new Date(res.sslExpiry).toISOString() : null,
    ssl_issuer: res.sslIssuer ?? null,
  });
}

async function handleCheck(domain, request, env) {
  if (!domain) return html(layout({
    title: "Check a domain · HostCop", desc: "Look up who really hosts any website.",
    path: "/check", body: heroSection() }), 400);

  const res = await runCheck(domain, request.cf?.colo || "edge", env);
  if (!res) return html(layout({ title: `HostCop · ${domain}`, desc: "", path: "/check/" + domain,
    body: `<a class="back" href="/">← check another</a><h1>${esc(domain)}</h1>
           <p class="muted">Couldn't read that domain — please try again.</p>` }));

  if (res.noDns) return html(layout({
    title: `${domain} — no DNS records · HostCop`,
    desc: `${domain} has no DNS records — it doesn't point to a server.`,
    path: "/check/" + domain,
    body: `<a class="back" href="/">← check another</a><h1>${esc(domain)}</h1>
      <div class="verdict down"><b>${esc(domain)}</b> doesn't point anywhere — no DNS records found. 🔴</div>
      <p class="muted">There's no A record for this domain, so there's no server to measure. It may be unregistered, expired, or configured for other services only.</p>` }));

  const badge = res.up
    ? `<span class="up">UP</span> · ${res.ms} ms · HTTP ${res.finalStatus} <span class="muted">· ${esc(statusText(res.finalStatus))}</span>`
    : `<span class="down">DOWN</span> · no response`;

  let ssl = `<b>—</b>`;
  if (res.sslExpiry) {
    const days = Math.round((res.sslExpiry - Date.now()) / 86400000);
    const date = new Date(res.sslExpiry).toISOString().slice(0, 10);
    const cls = days < 0 ? "down" : days <= 21 ? "warn" : "up";
    ssl = `<b><span class="${cls}">${days < 0 ? "expired" : days + " days left"}</span> · ${date}${res.sslIssuer ? " · " + esc(res.sslIssuer) : ""}</b>`;
  } else if (res.up) {
    ssl = `<b class="muted">TLS 1.3+ · expiry not exposed (normal &amp; fine)</b>`;
  }

  // Dig for the real origin behind a CDN, plus email / DNS intel and reverse DNS.
  const [oi, rdns] = await Promise.all([
    discoverOrigin(res.domain, res.provider),
    res.ip ? reverseDns(res.ip) : Promise.resolve(null),
  ]);

  let invRows = "";
  let resellerNote = "";
  if (oi.cdn) {
    if (oi.origin) {
      const ob = cleanProvider(oi.origin.provider);
      invRows += `<div class="row"><span>Real origin (likely)</span>
           <b><a href="/host/${encodeURIComponent(ob)}">${esc(ob)}</a>${oi.origin.ip ? " · " + esc(oi.origin.ip) : ""}</b></div>
         <div class="row"><span>Found via</span><b>${esc(oi.origin.method)}</b></div>`;
      if (isInfra(oi.origin.provider))
        resellerNote = `<p class="note">🔎 <b>Reseller / white-label:</b> the real machine runs on <b>${esc(ob)}</b> (wholesale infrastructure). The brand on the invoice is likely reselling it.</p>`;
    } else {
      invRows += `<div class="row"><span>Real origin</span><b class="muted">not exposed via public signals — well shielded</b></div>`;
    }
  }
  if (oi.mailHost) invRows += `<div class="row"><span>Email host</span><b>${esc(oi.mailHost)}${oi.mailProvider ? " · " + esc(cleanProvider(oi.mailProvider)) : ""}</b></div>`;
  if (oi.dnsHost) invRows += `<div class="row"><span>DNS host</span><b>${esc(oi.dnsHost)}</b></div>`;
  if (rdns) invRows += `<div class="row"><span>Reverse DNS</span><b>${esc(rdns)}</b></div>`;
  if (res.server) invRows += `<div class="row"><span>Server</span><b>${esc(res.server)}</b></div>`;
  if (res.chain && res.chain.length > 1) {
    const hops = res.chain.map(c => `${esc(shortUrl(c.url))} <span class="muted">→ ${c.status || "…"}</span>`).join("<br>");
    invRows += `<div class="row"><span>Redirect chain</span><b>${hops}</b></div>`;
  }
  if (res.finalUrl && res.finalUrl !== `https://${res.domain}/`)
    invRows += `<div class="row"><span>Final URL</span><b>${esc(shortUrl(res.finalUrl))}</b></div>`;
  const investigation = invRows
    ? `<div class="kicker" style="margin-top:24px">Investigation · the evidence</div>
       <div class="card">${invRows}</div>
       ${resellerNote}
       ${oi.cdn ? `<p class="muted small">Origin found by probing records a CDN doesn't proxy (mail, common subdomains). A blank means the origin is genuinely well hidden.</p>` : ""}`
    : "";

  const cdnNote = isCdn(res.brand)
    ? `<p class="note">⚡ This domain sits behind <b>${esc(res.brand)}</b>, a CDN / edge network — so "Hosted by" is the CDN, not the real server. We dug for the true origin below.</p>`
    : "";

  // The verdict line — one plain-English sentence at the top.
  const pctRow = res.up ? await env.DB.prepare(
    "SELECT ROUND(100.0*AVG(CASE WHEN response_ms > ? THEN 1 ELSE 0 END)) p FROM checks WHERE up=1"
  ).bind(res.ms).first() : null;
  let verdict, vclass;
  if (!res.up) { verdict = `<b>${esc(domain)}</b> appears to be down — the server didn't respond. 🔴`; vclass = "down"; }
  else if (looksParked(res, oi)) { verdict = `<b>${esc(domain)}</b> is a parked domain — not hosting a real website. 🅿️`; vclass = "note"; }
  else { const v = buildVerdict(res, pctRow?.p ?? null); verdict = v.line; vclass = v.cls; }

  const loc = res.country ? `${flag(res.country)} ${esc(res.country)}` : "—";
  const shareUrl = `${BASE}/check/${res.domain}`;
  const badgeUrl = `${BASE}/badge/${res.domain}.svg`;
  const embed = `<a href="${BASE}/check/${res.domain}"><img src="${badgeUrl}" alt="Hosted on ${esc(res.provider)} — verified by HostCop"></a>`;

  return html(layout({
    title: `Who hosts ${domain}? · HostCop`,
    desc: `${domain} is hosted by ${res.provider}${res.country ? " (" + res.country + ")" : ""}. Live response time, SSL and uptime, measured by HostCop.`,
    path: "/check/" + domain,
    body: `
    <a class="back" href="/">← check another</a>
    <h1>${esc(domain)}</h1>
    <div class="verdict ${vclass}">${verdict}</div>
    ${res.loadBalanced ? `<p class="note">🔀 Load-balanced across multiple networks — the majority provider is shown.</p>` : ""}
    ${cdnNote}
    <div class="card">
      <div class="row"><span>Hosted by</span>
        <a href="/host/${encodeURIComponent(res.brand)}"><b>${esc(res.brand)}</b></a></div>
      <div class="row"><span>Type</span><b>${isCdn(res.brand) ? "CDN / edge network" : "Origin host"}</b></div>
      <div class="row"><span>IP address</span><b>${esc(res.ip || "—")}</b></div>
      <div class="row"><span>ASN</span><b>${res.asn ? "AS" + esc(res.asn) : "—"}</b></div>
      <div class="row"><span>Location (approx)</span><b>${loc}</b></div>
      <div class="row"><span>Status</span><b>${badge}</b></div>
      <div class="row"><span>SSL certificate</span>${ssl}</div>
    </div>

    ${investigation}

    <div class="actions">
      <a class="btn" href="/monitor?domain=${encodeURIComponent(res.domain)}">🔔 Monitor this site — free</a>
      <a class="btn ghost" href="/host/${encodeURIComponent(res.brand)}">${esc(res.brand)} ranking →</a>
      <a class="btn ghost" href="/hosts">Compare hosts</a>
    </div>

    <details class="share">
      <summary>Share this result &amp; embed a verified badge</summary>
      <label>Shareable link</label>
      <input class="copy" readonly value="${esc(shareUrl)}" onclick="this.select()">
      <label>Badge preview</label>
      <div class="badgeprev">${embed}</div>
      <label>Embed code</label>
      <textarea class="copy" readonly rows="2" onclick="this.select()">${esc(embed)}</textarea>
    </details>

    <p class="muted">This verdict was added to the public record for
      <a href="/host/${encodeURIComponent(res.provider)}">${esc(res.provider)}</a>.
      Measured live from Cloudflare's edge — see <a href="/methodology">methodology</a>.</p>
  ` }));
}

async function handleProvider(provider, env) {
  const { results } = await env.DB.prepare(
    `SELECT COUNT(*) checks, COUNT(DISTINCT domain) sites,
            ROUND(AVG(response_ms)) avg_ms,
            ROUND(100.0*SUM(up)/COUNT(*),1) uptime,
            MAX(checked_at) last_seen,
            MAX(country) country
     FROM checks WHERE brand = ?`
  ).bind(provider).all();
  const s = results[0];
  if (!s || !s.checks)
    return html(layout({ title: `${provider} · HostCop`, desc: "", path: "/host/" + provider,
      body: `<a class="back" href="/hosts">← all hosts</a><h1>${esc(provider)}</h1>
             <p class="muted">No measured data yet for this host. <a href="/">Check a domain</a> to add some.</p>` }));

  const recent = await env.DB.prepare(
    `SELECT domain, MAX(checked_at) t, ROUND(AVG(response_ms)) ms,
            ROUND(100.0*SUM(up)/COUNT(*)) up
     FROM checks WHERE brand = ? GROUP BY domain ORDER BY t DESC LIMIT 12`
  ).bind(provider).all();

  const rows = recent.results.map(d => `
    <tr><td><a href="/check/${esc(d.domain)}">${esc(d.domain)}</a></td>
        <td>${d.ms} ms</td><td>${d.up}%</td><td class="muted">${timeAgo(d.t)}</td></tr>`).join("");

  const cdn = isCdn(provider)
    ? `<p class="note">⚡ ${esc(provider)} is a CDN / edge network. Sites measured here are fronted by it; their true origin host may differ.</p>` : "";

  return html(layout({
    title: `${provider} hosting performance · HostCop`,
    desc: `Live measured performance for ${provider}: ${s.uptime}% uptime, ${s.avg_ms} ms average response across ${s.sites} sites. Neutral data, no affiliate bias.`,
    path: "/host/" + provider,
    body: `
    <a class="back" href="/hosts">← all hosts</a>
    <h1>${esc(provider)}</h1>
    <p class="muted">${s.country ? flag(s.country) + " " + esc(s.country) + " · " : ""}last measured ${timeAgo(s.last_seen)}</p>
    ${cdn}
    <div class="stats">
      <div><b>${s.avg_ms} ms</b><span>avg response</span></div>
      <div><b>${s.uptime}%</b><span>uptime</span></div>
      <div><b>${s.sites}</b><span>sites tested</span></div>
      <div><b>${s.checks}</b><span>total checks</span></div>
    </div>
    <h2>Recently measured sites</h2>
    <table><tr><th>Domain</th><th>Avg</th><th>Uptime</th><th>Last check</th></tr>${rows}</table>
    <p class="muted">Based only on live measurements from real checks — no reviews, no paid placement.
      HostCop uses <b>no affiliate links</b>. <a href="/methodology">How we measure →</a></p>
  ` }));
}

async function handleLeaderboard(url, env) {
  const sort = url.searchParams.get("sort") || "uptime";
  const order = sort === "speed" ? "avg_ms ASC"
    : sort === "tested" ? "sites DESC"
    : "uptime DESC, avg_ms ASC";

  const { results } = await env.DB.prepare(
    `SELECT brand, COUNT(DISTINCT domain) sites,
            ROUND(AVG(response_ms)) avg_ms,
            ROUND(100.0*SUM(up)/COUNT(*),1) uptime,
            COUNT(*) checks, MAX(checked_at) last_seen
     FROM checks WHERE brand IS NOT NULL AND brand != 'Unknown'
     GROUP BY brand
     HAVING COUNT(DISTINCT domain) >= ${RANK_MIN_SITES} AND COUNT(*) >= ${RANK_MIN_CHECKS}
     ORDER BY ${order} LIMIT 100`
  ).all();

  const hosts = results.filter(r => !isCdn(r.brand));
  const cdns = results.filter(r => isCdn(r.brand));

  const rowsOf = list => list.map((r, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><a href="/host/${encodeURIComponent(r.brand)}">${esc(r.brand)}</a></td>
      <td>${r.uptime}%</td>
      <td>${r.avg_ms} ms</td>
      <td>${r.sites}</td>
      <td>${r.checks}</td>
      <td class="muted">${timeAgo(r.last_seen)}</td>
    </tr>`).join("");
  const table = (list, empty) => list.length
    ? `<table><tr><th>#</th><th>Host</th><th>Uptime</th><th>Avg</th><th>Sites</th><th>Checks</th><th>Updated</th></tr>${rowsOf(list)}</table>`
    : `<p class="muted">${empty}</p>`;

  // Hosts that don't yet clear the bar — shown honestly, not ranked.
  const { results: emerging } = await env.DB.prepare(
    `SELECT brand, COUNT(*) checks FROM checks WHERE brand IS NOT NULL AND brand != 'Unknown'
     GROUP BY brand
     HAVING NOT (COUNT(DISTINCT domain) >= ${RANK_MIN_SITES} AND COUNT(*) >= ${RANK_MIN_CHECKS})
     ORDER BY checks DESC LIMIT 40`
  ).all();

  const tab = (key, label) => `<a class="pill ${sort === key ? "on" : ""}" href="/hosts?sort=${key}">${label}</a>`;

  return html(layout({
    title: "Web host rankings by measured uptime & speed · HostCop",
    desc: "Neutral hosting rankings built from live measurements — real uptime and response times crowdsourced from every domain checked. No reviews, no affiliate bias.",
    path: "/hosts",
    body: `
    <h1>Host rankings</h1>
    <div class="trustbadge">🛡 No affiliate links · No paid placements · Just measured data</div>
    <p class="muted">Ranked from live measurements. To qualify, a host needs at least <b>${RANK_MIN_SITES} distinct sites</b> and <b>${RANK_MIN_CHECKS} checks</b> — so no host is ranked on a single sample.</p>
    <div class="pills">${tab("uptime", "Most reliable")}${tab("speed", "Fastest")}${tab("tested", "Most tested")}</div>
    <p class="muted small">Two head-to-head? <a href="/compare">Compare any two hosts →</a></p>
    ${table(hosts, "Not enough qualifying hosts yet — check more domains to build the rankings.")}
    <h2>CDN &amp; edge networks</h2>
    <p class="muted small">Measured separately: a CDN's "uptime" reflects its edge answering, and many return a 403 to automated checks (still counted as up, since the server responded).</p>
    ${table(cdns, "No CDNs qualify yet.")}
    ${emerging.length ? `<h2>Building data</h2>
      <p class="muted small">Seen, but not enough measurements to rank fairly yet (checks in brackets):</p>
      <p class="muted small">${emerging.map(e => esc(e.brand) + " (" + e.checks + ")").join(" · ")}</p>` : ""}
    <p class="muted">The numbers here <i>are</i> the ranking — nothing hidden. See <a href="/methodology">methodology</a>.</p>
  ` }));
}

async function handleBadge(domain, env) {
  domain = cleanDomain(domain);
  let provider = "not checked";
  if (domain) {
    const row = await env.DB.prepare(
      "SELECT brand FROM checks WHERE domain = ? ORDER BY checked_at DESC LIMIT 1"
    ).bind(domain).first();
    if (row?.brand) provider = row.brand;
  }
  const left = "verified by HostCop";
  const right = provider;
  const cw = 6.6, pad = 12;
  const lw = Math.ceil(left.length * cw) + pad * 2;
  const rw = Math.ceil(right.length * cw) + pad * 2;
  const w = lw + rw, h = 28;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" role="img" aria-label="${esc(left)}: ${esc(right)}">
  <rect width="${w}" height="${h}" rx="5" fill="#0f172a"/>
  <rect x="${lw}" width="${rw}" height="${h}" rx="5" fill="#2563eb"/>
  <rect x="${lw}" width="8" height="${h}" fill="#2563eb"/>
  <g font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" font-size="12" fill="#fff">
    <text x="${pad}" y="18">🛡 ${esc(left)}</text>
    <text x="${lw + pad}" y="18" font-weight="700">${esc(right)}</text>
  </g></svg>`;
  return new Response(svg, { headers: {
    "content-type": "image/svg+xml",
    "cache-control": "max-age=3600",
  } });
}

// ---- compare + bulk + API docs ------------------------------------------

async function providerStats(env, brand) {
  const r = await env.DB.prepare(
    `SELECT COUNT(*) checks, COUNT(DISTINCT domain) sites,
            ROUND(AVG(response_ms)) avg_ms,
            ROUND(100.0*SUM(up)/COUNT(*),1) uptime
     FROM checks WHERE brand = ?`).bind(brand).first();
  return r && r.checks ? r : null;
}

async function topProviders(env, n) {
  const { results } = await env.DB.prepare(
    `SELECT brand FROM checks WHERE brand IS NOT NULL AND brand!='Unknown'
     GROUP BY brand HAVING COUNT(*)>=3 ORDER BY COUNT(*) DESC LIMIT ?`).bind(n).all();
  return results.map(r => r.brand);
}

const provSlug = s => (s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

async function handleCompare(url, env, pathSlug) {
  const provs = await topProviders(env, 80);
  let a = url.searchParams.get("a"), b = url.searchParams.get("b");
  if (pathSlug && (!a || !b)) {
    const [sa, sb] = pathSlug.split("-vs-");
    a = a || provs.find(p => provSlug(p) === sa);
    b = b || provs.find(p => provSlug(p) === sb);
  }
  const opts = sel => `<option value="">— pick —</option>` +
    provs.map(p => `<option value="${esc(p)}"${p === sel ? " selected" : ""}>${esc(p)}</option>`).join("");
  const picker = `<form class="compareform" action="/compare" method="get">
      <select name="a">${opts(a)}</select><span class="muted">vs</span>
      <select name="b">${opts(b)}</select><button>Compare</button></form>`;

  if (!a || !b || a === b) {
    return html(layout({
      title: "Compare web hosts head-to-head · HostCop",
      desc: "Compare any two hosting providers on real measured uptime and response time — neutral data, no affiliate bias.",
      path: "/compare",
      body: `<h1>Compare hosts head-to-head</h1>
        <p class="muted">Two providers side by side, on data we measured ourselves — not opinions. Pick two:</p>
        ${picker}
        ${a && b && a === b ? '<p class="muted">Pick two different hosts.</p>' : ""}` }));
  }

  const [sa, sb] = await Promise.all([providerStats(env, a), providerStats(env, b)]);
  const side = (name, s, o) => `<div class="col">
      <h3><a href="/host/${encodeURIComponent(name)}">${esc(name)}</a></h3>
      ${s ? `<div class="m"><span>avg response</span><b class="${o && s.avg_ms <= o.avg_ms ? "win" : ""}">${s.avg_ms} ms</b></div>
      <div class="m"><span>uptime</span><b class="${o && s.uptime >= o.uptime ? "win" : ""}">${s.uptime}%</b></div>
      <div class="m"><span>sites tested</span><b>${s.sites}</b></div>
      <div class="m"><span>total checks</span><b>${s.checks}</b></div>`
      : `<p class="muted">No measured data yet.</p>`}</div>`;

  return html(layout({
    title: `${a} vs ${b} — real hosting performance · HostCop`,
    desc: `${a} vs ${b} compared on live measured uptime and response time. Neutral, no affiliate bias.`,
    path: `/compare/${provSlug(a)}-vs-${provSlug(b)}`,
    body: `<a class="back" href="/compare">← compare others</a>
      <h1>${esc(a)} <span class="muted">vs</span> ${esc(b)}</h1>
      <p class="muted">Head-to-head on data HostCop measured — no reviews, no paid placement.</p>
      <div class="cmp">${side(a, sa, sb)}${side(b, sb, sa)}</div>
      ${picker}
      <p class="muted small">Winner highlighted per metric (faster response, higher uptime). Minimum 3 checks per host.</p>` }));
}

function handleBulk() {
  return html(layout({
    title: "Bulk host checker — many domains at once · HostCop",
    desc: "Paste up to 30 domains and see who hosts each, the real origin behind CDNs, status and SSL — all at once.",
    path: "/bulk",
    body: `<h1>Bulk host checker</h1>
      <p class="muted">Paste up to 30 domains (one per line). We detect the host, the real origin behind CDNs, status and SSL for each.</p>
      <textarea id="bulkin" rows="7" placeholder="example.com&#10;anothersite.com"></textarea>
      <div class="actions"><button onclick="hcBulk()">Check all</button></div>
      <table><thead><tr><th>Domain</th><th>Host (→ real origin)</th><th>Loc</th><th>Status</th><th>SSL</th></tr></thead>
      <tbody id="bulkbody"><tr><td colspan="5" class="muted">Results appear here.</td></tr></tbody></table>
      <script>
      function hcBulk(){
        var ta=document.getElementById('bulkin');
        var ds=ta.value.split(/\\s+/).map(function(s){return s.trim().toLowerCase().replace(/^https?:\\/\\//,'').replace(/\\/.*$/,'');}).filter(Boolean).slice(0,30);
        var tb=document.getElementById('bulkbody'); tb.innerHTML='';
        if(!ds.length){tb.innerHTML='<tr><td colspan="5" class="muted">No valid domains.</td></tr>';return;}
        function e(x){return (x==null?'':String(x)).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}
        var i=0;
        function next(){
          if(i>=ds.length)return;
          var d=ds[i++];
          var tr=document.createElement('tr'); tr.innerHTML='<td>'+e(d)+'</td><td colspan="4" class="muted">checking…</td>'; tb.appendChild(tr);
          fetch('/api/check?domain='+encodeURIComponent(d)).then(function(r){return r.json();}).then(function(j){
            var host=j.cdn?(j.origin_provider?(e(j.provider)+' → <b>'+e(j.origin_provider)+'</b>'):e(j.provider)+' (CDN)'):e(j.provider||'—');
            var st=j.up?('<span class="up">UP</span> '+j.response_ms+'ms'):'<span class="down">DOWN</span>';
            var ssl=j.ssl_expiry?e(j.ssl_expiry.slice(0,10)):'—';
            tr.innerHTML='<td><a href="/check/'+encodeURIComponent(d)+'">'+e(d)+'</a></td><td>'+host+'</td><td>'+e(j.country||'')+'</td><td>'+st+'</td><td>'+ssl+'</td>';
          }).catch(function(){tr.innerHTML='<td>'+e(d)+'</td><td colspan="4" class="muted">failed</td>';}).finally(function(){next();});
        }
        for(var k=0;k<Math.min(4,ds.length);k++)next();
      }
      </script>` }));
}

function pageApi() {
  const sample = "GET https://hostcop.com/api/check?domain=example.com";
  const body = `{
  "domain": "example.com",
  "provider": "CLOUDFLARENET - Cloudflare, Inc.",
  "cdn": true,
  "origin_provider": "AMAZON-AES - Amazon.com, Inc.",
  "origin_found_via": "webmail.example.com",
  "reseller": true,
  "email_host": "google.com",
  "dns_host": "cloudflare.com",
  "reverse_dns": "server123.host.net",
  "up": true,
  "response_ms": 120,
  "http_status": 200,
  "ssl_expiry": "2026-09-30T23:59:59.000Z",
  "ssl_issuer": "Let's Encrypt"
}`;
  return contentPage("API", "/api",
    "Free HostCop API — detect the host, the real origin behind CDNs, and live performance as JSON. No key required.",
    `<h1>HostCop API</h1>
     <p>A free, no-key JSON endpoint. CORS is open, so you can call it straight from the browser. Please be reasonable — each call runs a live check.</p>
     <h2>Endpoint</h2>
     <pre class="code">${esc(sample)}</pre>
     <h2>Example response</h2>
     <pre class="code">${esc(body)}</pre>
     <h2>Fields</h2>
     <ul>
       <li><b>provider</b> — the network the domain resolves to (the CDN, if it's fronted).</li>
       <li><b>cdn</b> — true when that network is a CDN / edge.</li>
       <li><b>origin_provider / origin_found_via</b> — the real host behind the CDN, and how we found it.</li>
       <li><b>reseller</b> — true when the real origin is wholesale infrastructure (AWS, Hetzner…).</li>
       <li><b>email_host / dns_host / reverse_dns / server</b> — supporting evidence.</li>
       <li><b>up / response_ms / http_status</b> — live reachability and speed.</li>
       <li><b>ssl_expiry / ssl_issuer</b> — certificate expiry and issuer (null on TLS 1.3-only servers).</li>
     </ul>
     <p class="muted">Need higher volume, bulk, or monitoring? That's the planned paid tier — <a href="/contact">tell us what you need</a>.</p>`);
}

// ---- uptime / SSL monitoring --------------------------------------------

// hostcop.com isn't verified in Resend yet, so we send from the verified
// fluxleads.com domain with a HostCop display name. Switch to @hostcop.com
// once that domain is verified in Resend.
const ALERT_FROM = "HostCop Alerts <alerts@fluxleads.com>";

async function sendEmail(env, to, subject, htmlBody) {
  if (!env.RESEND_API_KEY) return { ok: false, error: "email not configured" };
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({ from: ALERT_FROM, to: [to], reply_to: "hello@hostcop.com", subject, html: htmlBody }),
  });
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, id: j.id, error: j.message || j.name };
}

function emailShell(inner, token) {
  return `<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:520px;margin:0 auto;color:#0f172a;line-height:1.6">
    <div style="margin-bottom:16px">
      <img src="${BASE}/logo.png" width="26" height="26" alt="HostCop" style="vertical-align:middle;border:0;margin-right:6px">
      <span style="font-size:20px;font-weight:800;vertical-align:middle">Host<span style="color:#f5b301">Cop</span></span>
    </div>
    ${inner}
    <hr style="border:0;border-top:1px solid #e2e8f0;margin:22px 0">
    <p style="font-size:12px;color:#94a3b8">You're receiving this because you asked HostCop to watch this domain.
    ${token ? `<a href="${BASE}/monitor/unsubscribe?token=${token}" style="color:#94a3b8">Unsubscribe</a>` : ""}</p>
  </div>`;
}
const emailBtn = (href, label) =>
  `<p><a href="${href}" style="display:inline-block;background:#2563eb;color:#fff;padding:11px 20px;border-radius:8px;text-decoration:none;font-weight:600">${label}</a></p>`;

function monitorForm(domain, email) {
  return `<form class="monitorform" action="/monitor" method="post">
    <input name="domain" placeholder="yourdomain.com" value="${esc(domain)}" autocomplete="off" spellcheck="false">
    <input name="email" type="email" placeholder="you@email.com" value="${esc(email)}" autocomplete="off">
    <button>Monitor it</button></form>`;
}

function pageMonitor(url) {
  const domain = cleanDomain(url.searchParams.get("domain") || "");
  return html(layout({
    title: "Free uptime & SSL monitoring · HostCop",
    desc: "Get a free email the moment your site goes down or its SSL certificate is about to expire. No account needed, one-click unsubscribe.",
    path: "/monitor",
    body: `<h1>Monitor a site — free</h1>
      <p class="lede" style="margin:10px 0 20px">We check it around the clock and email you the instant it goes down, comes back, or its SSL certificate is within 14 days of expiring.</p>
      ${monitorForm(domain, "")}
      <div class="grid" style="margin-top:26px">
        <div class="feat"><b>🔴 Downtime alerts</b><span>Know before your visitors do.</span></div>
        <div class="feat"><b>🔒 SSL expiry alerts</b><span>Never get caught by a lapsed certificate again.</span></div>
        <div class="feat"><b>✉️ No account</b><span>Just your email. One-click unsubscribe in every message.</span></div>
        <div class="feat"><b>🛡 Neutral</b><span>No upsells, no affiliate host pushed on you.</span></div>
      </div>
      <p class="muted small" style="margin-top:16px">We send a confirmation email first, so nobody can sign you up without consent.</p>` }));
}

async function handleMonitorCreate(request, env) {
  const form = await request.formData();
  const domain = cleanDomain(form.get("domain") || "");
  const email = (form.get("email") || "").trim().toLowerCase();
  if (!domain || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
    return html(layout({ title: "Monitor · HostCop", desc: "", path: "/monitor",
      body: `<h1>Monitor a site</h1><p class="note">Please enter a valid domain and email address.</p>${monitorForm(domain, email)}` }), 400);

  // Plan limit — how many sites this email may watch.
  const plan = await getPlan(env, email);
  const limit = PLANS[plan].monitors;
  const existing = await env.DB.prepare("SELECT id FROM monitors WHERE domain=? AND email=?").bind(domain, email).first();
  if (!existing) {
    const cnt = await env.DB.prepare("SELECT COUNT(*) c FROM monitors WHERE email=?").bind(email).first();
    if ((cnt?.c || 0) >= limit)
      return html(layout({ title: "Monitor limit reached · HostCop", desc: "", path: "/monitor",
        body: `<h1>You're already watching ${limit} sites</h1>
          <p class="note">Your ${PLANS[plan].label} plan covers up to <b>${limit}</b> monitored sites.${plan === "free" ? ` Upgrade to Pro to watch up to ${PLANS.pro.monitors} sites, checked every 5 minutes.` : ""}</p>
          <p><a class="btn" href="/pricing">See plans →</a></p>` }));
  }

  const token = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO monitors (domain, email, status, token, verified, created_at)
     VALUES (?,?,?,?,0,?)
     ON CONFLICT(domain, email) DO UPDATE SET token=excluded.token, verified=0`
  ).bind(domain, email, "unknown", token, Date.now()).run();

  const r = await sendEmail(env, email, `Confirm monitoring for ${domain}`, emailShell(
    `<h2 style="margin:0 0 10px">Confirm alerts for ${esc(domain)}</h2>
     <p>Click below to start getting an email whenever <b>${esc(domain)}</b> goes down or its SSL certificate is about to expire.</p>
     ${emailBtn(`${BASE}/monitor/verify?token=${token}`, "Confirm monitoring")}
     <p style="font-size:12px;color:#94a3b8">If you didn't request this, just ignore this email — nothing will be sent.</p>`, token));

  return html(layout({ title: "Check your email · HostCop", desc: "", path: "/monitor",
    body: `<h1>Almost there ✉️</h1>
      <p>We sent a confirmation link to <b>${esc(email)}</b>. Click it to start monitoring <b>${esc(domain)}</b>.</p>
      ${r.ok ? "" : `<p class="note">The email couldn't be sent right now${r.error ? ` (${esc(r.error)})` : ""}. Please try again shortly.</p>`}
      <p class="muted small">No email in a minute? Check spam, or <a href="/monitor?domain=${encodeURIComponent(domain)}">re-send</a>.</p>` }));
}

async function handleMonitorVerify(url, env) {
  const token = url.searchParams.get("token") || "";
  const m = token ? await env.DB.prepare("SELECT * FROM monitors WHERE token=?").bind(token).first() : null;
  if (!m) return html(layout({ title: "Link invalid · HostCop", desc: "", path: "/monitor",
    body: `<h1>Link invalid or expired</h1><p><a href="/monitor">Set up monitoring again →</a></p>` }), 404);
  await env.DB.prepare("UPDATE monitors SET verified=1 WHERE id=?").bind(m.id).run();
  return html(layout({ title: "Monitoring active · HostCop", desc: "", path: "/monitor",
    body: `<div class="verdict ok"><b>${esc(m.domain)}</b> is now being monitored. ✅</div>
      <p>We'll email <b>${esc(m.email)}</b> the moment it goes down or recovers, and when its SSL certificate is within 14 days of expiring.</p>
      <p><a class="btn" href="/check/${esc(m.domain)}">See its current status →</a></p>` }));
}

async function handleMonitorUnsub(url, env) {
  const token = url.searchParams.get("token") || "";
  const m = token ? await env.DB.prepare("SELECT * FROM monitors WHERE token=?").bind(token).first() : null;
  if (m) await env.DB.prepare("DELETE FROM monitors WHERE id=?").bind(m.id).run();
  return html(layout({ title: "Unsubscribed · HostCop", desc: "", path: "/monitor",
    body: `<h1>Unsubscribed</h1><p>${m ? `You'll no longer get alerts for <b>${esc(m.domain)}</b>.` : "That link is no longer valid."}</p>` }));
}

// Cron worker: check each monitored domain, email on up/down transitions + SSL expiry.
async function runMonitors(env, scope = "all") {
  const proOnly = `SELECT DISTINCT m.domain FROM monitors m WHERE m.verified=1 AND EXISTS
    (SELECT 1 FROM subscriptions s WHERE s.email=m.email AND s.plan='pro' AND s.status='active')`;
  const { results: doms } = await env.DB.prepare(
    scope === "pro" ? proOnly : "SELECT DISTINCT domain FROM monitors WHERE verified=1").all();
  for (const { domain } of doms) {
    let res = await runCheck(domain, "monitor", env);
    if (!res) continue;
    let isUp = res.noDns ? false : !!res.up;
    if (!isUp && !res.noDns) {                      // confirm down from multiple regions before alerting
      const regions = await probeRegions(`https://${domain}/`, env);
      if (regions) isUp = regions.some(r => r.up);   // reachable from ANY region → not a real outage
      else { const res2 = await runCheck(domain, "monitor", env); if (res2) { res = res2; isUp = !res2.noDns && !!res2.up; } }
    }
    const cur = isUp ? "up" : "down";
    const { results: subs } = await env.DB.prepare(
      "SELECT * FROM monitors WHERE domain=? AND verified=1").bind(domain).all();

    for (const m of subs) {
      const prev = m.status || "unknown";
      if (prev !== "unknown" && prev !== cur) {
        const subj = cur === "down" ? `🔴 ${domain} is DOWN` : `✅ ${domain} is back UP`;
        const inner = cur === "down"
          ? `<h2 style="margin:0 0 10px">${esc(domain)} appears to be down</h2>
             <p>HostCop couldn't reach it just now — ${res.noDns ? "its DNS stopped resolving" : "the server didn't respond"}.</p>`
          : `<h2 style="margin:0 0 10px">${esc(domain)} is back online</h2>
             <p>It's responding again${res.ms ? ` (${res.ms} ms)` : ""}.</p>`;
        await sendEmail(env, m.email, subj, emailShell(inner + emailBtn(`${BASE}/check/${domain}`, "See full status"), m.token));
      }
      if (prev !== cur) await env.DB.prepare(
        "UPDATE monitors SET status=?, last_change=? WHERE id=?").bind(cur, Date.now(), m.id).run();

      if (res.sslExpiry) {
        const days = Math.round((res.sslExpiry - Date.now()) / 86400000);
        if (days >= 0 && days <= 14 && !m.ssl_alerted) {
          await sendEmail(env, m.email, `🔒 ${domain} SSL expires in ${days} day${days === 1 ? "" : "s"}`, emailShell(
            `<h2 style="margin:0 0 10px">${esc(domain)}'s SSL certificate expires in ${days} day${days === 1 ? "" : "s"}</h2>
             <p>Renew it before it lapses, or visitors will hit a security warning.</p>` +
            emailBtn(`${BASE}/check/${domain}`, "See details"), m.token));
          await env.DB.prepare("UPDATE monitors SET ssl_alerted=1 WHERE id=?").bind(m.id).run();
        } else if (days > 21 && m.ssl_alerted) {
          await env.DB.prepare("UPDATE monitors SET ssl_alerted=0 WHERE id=?").bind(m.id).run();  // renewed
        }
      }
    }
  }
}

// ---- plans & billing (Stripe) -------------------------------------------

const PLANS = {
  free: { label: "Free", monitors: 3, freq: "every 30 min" },
  pro: { label: "Pro", monitors: 50, freq: "every 5 min" },
};
const PRO_PRICE = "$7";        // per month — change here + in Stripe

async function getPlan(env, email) {
  if (!email) return "free";
  const r = await env.DB.prepare("SELECT plan, status FROM subscriptions WHERE email=?").bind(email).first();
  return r && r.plan === "pro" && r.status === "active" ? "pro" : "free";
}

async function upsertSub(env, email, plan, status, customer, sub) {
  if (!email) return;
  await env.DB.prepare(
    `INSERT INTO subscriptions (email, plan, status, stripe_customer, stripe_sub, updated)
     VALUES (?,?,?,?,?,?)
     ON CONFLICT(email) DO UPDATE SET plan=excluded.plan, status=excluded.status,
       stripe_customer=COALESCE(excluded.stripe_customer, subscriptions.stripe_customer),
       stripe_sub=COALESCE(excluded.stripe_sub, subscriptions.stripe_sub), updated=excluded.updated`
  ).bind(email.toLowerCase(), plan, status, customer || null, sub || null, Date.now()).run();
}

// Verify Stripe's webhook signature (HMAC-SHA256 over "timestamp.payload").
async function verifyStripe(payload, header, secret) {
  if (!header || !secret) return false;
  const parts = Object.fromEntries(header.split(",").map(kv => kv.split("=")));
  if (!parts.t || !parts.v1) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${parts.t}.${payload}`));
  const hex = [...new Uint8Array(mac)].map(b => b.toString(16).padStart(2, "0")).join("");
  return hex === parts.v1;
}

const billingLive = env => !!(env.STRIPE_SECRET_KEY && env.STRIPE_PRICE);

async function handleUpgrade(request, env, url) {
  const email = ((request.method === "POST"
    ? (await request.formData()).get("email")
    : url.searchParams.get("email")) || "").trim().toLowerCase();
  if (!billingLive(env)) return Response.redirect(`${BASE}/pricing?soon=1`, 303);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return Response.redirect(`${BASE}/pricing?bad=1`, 303);
  const body = new URLSearchParams();
  body.set("mode", "subscription");
  body.set("line_items[0][price]", env.STRIPE_PRICE);
  body.set("line_items[0][quantity]", "1");
  body.set("customer_email", email);
  body.set("success_url", `${BASE}/pro/welcome?email=${encodeURIComponent(email)}`);
  body.set("cancel_url", `${BASE}/pricing`);
  const r = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: { authorization: `Bearer ${env.STRIPE_SECRET_KEY}`, "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  const j = await r.json();
  return j.url ? Response.redirect(j.url, 303) : Response.redirect(`${BASE}/pricing?err=1`, 303);
}

async function handleStripeWebhook(request, env) {
  const payload = await request.text();
  const ok = await verifyStripe(payload, request.headers.get("stripe-signature"), env.STRIPE_WEBHOOK_SECRET);
  if (!ok) return new Response("bad signature", { status: 400 });
  let event; try { event = JSON.parse(payload); } catch { return new Response("bad json", { status: 400 }); }
  const obj = event.data?.object || {};
  if (event.type === "checkout.session.completed") {
    const email = obj.customer_email || obj.customer_details?.email;
    await upsertSub(env, email, "pro", "active", obj.customer, obj.subscription);
  } else if (event.type.startsWith("customer.subscription.")) {
    const plan = (obj.status === "active" || obj.status === "trialing") ? "pro" : "free";
    await env.DB.prepare("UPDATE subscriptions SET plan=?, status=?, updated=? WHERE stripe_customer=?")
      .bind(plan, obj.status || "canceled", Date.now(), obj.customer).run();
  }
  return new Response("ok");
}

function pagePricing(url, env) {
  const soon = url.searchParams.get("soon"), bad = url.searchParams.get("bad"), err = url.searchParams.get("err");
  const live = billingLive(env);
  const notice = soon ? `<p class="note">Pro is launching very soon — <a href="/contact">tell us you're interested</a> and we'll let you know.</p>`
    : bad ? `<p class="note">Please enter a valid email.</p>`
    : err ? `<p class="note">Couldn't start checkout — please try again.</p>` : "";
  const cta = live
    ? `<form class="monitorform" action="/upgrade" method="post" style="margin-top:12px">
         <input name="email" type="email" placeholder="you@email.com" required>
         <button>Upgrade to Pro — ${PRO_PRICE}/mo</button></form>`
    : `<a class="btn" href="/pricing?soon=1" style="margin-top:12px">Get notified when Pro launches</a>`;
  const feat = (ok, t) => `<div class="row"><span>${ok ? '<span class="up">✓</span>' : '<span class="muted">–</span>'} ${t}</span><b></b></div>`;
  return html(layout({
    title: "Pricing — free tools, Pro monitoring · HostCop",
    desc: "HostCop's tools are free forever. Pro adds monitoring for up to 50 sites checked every 5 minutes. No affiliate links, ever.",
    path: "/pricing",
    jsonld: [{
      "@context": "https://schema.org", "@type": "Product",
      name: "HostCop", description: "Neutral hosting watchdog with free website tools and optional Pro uptime + SSL monitoring.",
      brand: { "@type": "Brand", name: "HostCop" }, url: `${BASE}/pricing`,
      offers: [
        { "@type": "Offer", name: "Free", price: "0", priceCurrency: "USD", availability: "https://schema.org/InStock", url: `${BASE}/pricing` },
        { "@type": "Offer", name: "Pro", price: "7.00", priceCurrency: "USD", availability: "https://schema.org/InStock", url: `${BASE}/pricing`,
          priceSpecification: { "@type": "UnitPriceSpecification", price: "7.00", priceCurrency: "USD", referenceQuantity: { "@type": "QuantitativeValue", value: "1", unitCode: "MON" } } },
      ],
    }],
    body: `<h1>Pricing</h1>
      <div class="trustbadge">🛡 All tools free forever · No affiliate links, ever</div>
      ${notice}
      <div class="cmp" style="margin-top:14px">
        <div class="col">
          <h3>Free</h3>
          <p class="muted small" style="text-align:center;margin:0 0 8px">$0 — forever</p>
          ${feat(true, "Every tool, unlimited")}
          ${feat(true, "Full hosting reports")}
          ${feat(true, `Monitor ${PLANS.free.monitors} sites`)}
          ${feat(true, "Checked every 30 min")}
          ${feat(true, "Downtime & SSL email alerts")}
          ${feat(false, "5-minute checks")}
          <a class="btn ghost" href="/monitor" style="margin-top:12px">Start monitoring free</a>
        </div>
        <div class="col" style="border-color:var(--brand)">
          <h3>Pro <span class="tag">popular</span></h3>
          <p class="muted small" style="text-align:center;margin:0 0 8px">${PRO_PRICE}/month</p>
          ${feat(true, "Everything in Free")}
          ${feat(true, `Monitor ${PLANS.pro.monitors} sites`)}
          ${feat(true, "Checked every 5 min")}
          ${feat(true, "Multi-region downtime checks")}
          ${feat(true, "Priority email alerts")}
          ${feat(true, "Support an independent, unbiased watchdog")}
          ${cta}
        </div>
      </div>
      <p class="muted small" style="margin-top:18px">Pro is billed monthly and cancels anytime. Your email is your account — the same one you monitor with. HostCop makes money from Pro, never from affiliate links, so the rankings stay honest.</p>` }));
}

function pageProWelcome(url) {
  const email = cleanEmail(url.searchParams.get("email") || "");
  return html(layout({
    title: "Welcome to Pro · HostCop", desc: "", path: "/pro/welcome",
    body: `<div class="verdict ok">You're on <b>HostCop Pro</b> now. 🎉</div>
      <p>Thanks for backing an unbiased hosting watchdog. ${email ? `<b>${esc(email)}</b> can now monitor up to ${PLANS.pro.monitors} sites, checked every 5 minutes.` : `You can now monitor up to ${PLANS.pro.monitors} sites, checked every 5 minutes.`}</p>
      <p><a class="btn" href="/monitor">Add a site to monitor →</a></p>` }));
}

// ---- free tools (each = its own SEO landing page) -----------------------

const TOOLS = [
  ["/down", "🔴", "Is it down?", "Check if a website is down for everyone or just you."],
  ["/ssl", "🔒", "SSL checker", "Certificate expiry, issuer and validity."],
  ["/dns", "🗂️", "DNS lookup", "All records — A, AAAA, MX, TXT, NS, CNAME."],
  ["/redirect", "↪️", "Redirect checker", "Trace the full redirect chain."],
  ["/dns-propagation", "🌍", "DNS propagation", "Has your DNS updated across resolvers worldwide?"],
  ["/email", "✉️", "Email checker", "SPF, DKIM & DMARC — will your mail land?"],
  ["/headers", "🧾", "HTTP headers", "Response headers + a security grade."],
  ["/reverse-ip", "🔁", "Reverse IP", "Other sites seen on the same IP."],
  ["/whois", "🗓️", "WHOIS & age", "Domain age, registrar, expiry."],
  ["/tech", "🔎", "Tech stack", "CMS, framework, server, analytics."],
  ["/speed", "⚡", "Speed test", "Time to first byte + a performance grade."],
  ["/check", "🛡️", "Hosting report", "Who really hosts it — the full investigation."],
];

const toolDomain = (url, p, base) =>
  cleanDomain(p.startsWith(base + "/") ? decodeURIComponent(p.slice(base.length + 1)) : (url.searchParams.get("domain") || ""));

const crossLink = d =>
  `<div class="actions"><a class="btn" href="/check/${encodeURIComponent(d)}">🛡️ Full hosting report for ${esc(d)} →</a></div>`;

// ---- structured data (JSON-LD) helpers ----------------------------------
const stripTags = s => String(s || "").replace(/<[^>]+>/g, "")
  .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
  .replace(/\s+/g, " ").trim();

function faqLd(faqHtml) {
  const items = [];
  const re = /<h2>([\s\S]*?)<\/h2>\s*<p>([\s\S]*?)<\/p>/g;
  let m;
  while ((m = re.exec(faqHtml || ""))) {
    items.push({ "@type": "Question", name: stripTags(m[1]),
      acceptedAnswer: { "@type": "Answer", text: stripTags(m[2]) } });
  }
  return items.length ? { "@context": "https://schema.org", "@type": "FAQPage", mainEntity: items } : null;
}
const breadcrumbLd = items => ({
  "@context": "https://schema.org", "@type": "BreadcrumbList",
  itemListElement: items.map((it, i) => ({ "@type": "ListItem", position: i + 1, name: it.name, item: BASE + it.url })),
});

function toolShell({ title, desc, path, h1, intro, base, domain, result, faq }) {
  const jsonld = [
    faqLd(faq),
    breadcrumbLd([{ name: "Home", url: "/" }, { name: "Tools", url: "/tools" }, { name: stripTags(h1), url: base }]),
  ];
  return html(layout({
    title, desc, path, jsonld, body: `
    <div class="kicker">HostCop tools</div>
    <h1>${h1}</h1>
    <p class="lede" style="max-width:640px;margin:8px 0 18px">${intro}</p>
    <form class="toolform" action="${base}" method="get">
      <input name="domain" placeholder="yourdomain.com" value="${esc(domain || "")}" autocomplete="off" spellcheck="false"${domain ? "" : " autofocus"}>
      <button>Check</button>
    </form>
    ${result || ""}
    ${faq ? `<div class="prose" style="margin-top:30px">${faq}</div>` : ""}
    <p class="muted small" style="margin-top:22px"><a href="/tools">← all HostCop tools</a></p>` }));
}

function pageTools() {
  const cards = TOOLS.map(([href, icon, name, desc]) =>
    `<a class="toolcard" href="${href}"><b>${icon} ${esc(name)}</b><span>${esc(desc)}</span></a>`).join("");
  return html(layout({
    title: "Free website tools — DNS, SSL, uptime, redirects · HostCop",
    desc: "A fast, no-ads toolbox: check if a site is down, its SSL certificate, DNS records, redirect chain and DNS propagation — then see who really hosts it.",
    path: "/tools",
    body: `<h1>HostCop tools</h1>
      <p class="lede" style="max-width:640px">Fast, neutral, no-ads website tools. Every one links straight to the full hosting investigation.</p>
      <div class="toolgrid">${cards}</div>` }));
}

async function toolDown(domain, env) {
  let result = "";
  if (domain) {
    const res = await runCheck(domain, "tool", env);
    if (!res) result = `<p class="note">Couldn't check that domain — please try again.</p>`;
    else if (res.noDns) result = `<div class="verdict down"><b>${esc(domain)}</b> doesn't resolve — no DNS records found. 🔴</div>${crossLink(domain)}`;
    else {
      const regions = await probeRegions(`https://${res.domain}/`, env);
      const hostCard = `<div class="card"><div class="row"><span>Hosted by</span><b>${esc(res.brand)}</b></div>
        <div class="row"><span>IP</span><b>${esc(res.ip || "—")}</b></div></div>`;
      if (!regions) {
        // Fallback: single region
        result = res.up
          ? `<div class="verdict ok"><b>${esc(domain)}</b> is UP — it responded in ${res.ms} ms (HTTP ${res.finalStatus}). ✅</div>
             <p class="note">If <b>you</b> can't reach it, the problem is most likely local — ISP, DNS cache, VPN or firewall.</p>${hostCard}${crossLink(domain)}`
          : `<div class="verdict down"><b>${esc(domain)}</b> appears to be DOWN — no response. 🔴</div>${crossLink(domain)}`;
      } else {
        const upCount = regions.filter(r => r.up).length, total = regions.length;
        const rows = regions.map(r => `<div class="row"><span>${esc(r.label)}</span><b>${r.up ? `<span class="up">UP</span> · ${r.ms} ms` : '<span class="down">DOWN</span>'}</b></div>`).join("");
        const allUp = upCount === total && res.up;
        const allDown = upCount === 0 && !res.up;      // primary check agrees it's down
        let verdict, cls;
        if (allUp) { cls = "ok"; verdict = `<b>${esc(domain)}</b> is UP from all ${total} locations. ✅`; }
        else if (allDown) { cls = "down"; verdict = `<b>${esc(domain)}</b> is DOWN from every location — it's not just you. 🔴`; }
        else { cls = "warn"; verdict = `<b>${esc(domain)}</b> is reachable from ${upCount}/${total} regions — likely a regional or network issue, not a full outage. 🟡`; }
        result = `<div class="verdict ${cls}">${verdict}</div>
          <div class="kicker" style="margin-top:16px">By region</div>
          <div class="card">${rows}</div>
          <p class="muted small">Checked live from ${total} Cloudflare regions. If it's up here but down for you, the problem is local (ISP / DNS / VPN).</p>
          ${hostCard}${crossLink(domain)}`;
      }
    }
  }
  return toolShell({
    title: domain ? `Is ${domain} down right now? · HostCop` : "Is it down? Website down checker · HostCop",
    desc: domain ? `Is ${domain} down or is it just you? Live status, response time and who hosts it.` : "Check if any website is down for everyone or just you — live status from HostCop.",
    path: domain ? "/down/" + domain : "/down", base: "/down", domain, result,
    h1: domain ? `Is ${esc(domain)} down?` : "Is a website down?",
    intro: "Enter a domain to see if it's down for everyone — or just you. We check it live from several regions and tell you what's actually happening.",
    faq: `<h2>Down for everyone, or just me?</h2><p>HostCop checks from multiple Cloudflare regions. If it's <b>up</b> from our locations but you can't reach it, the outage is almost certainly local: your ISP, a stale DNS cache, a VPN, or a firewall. If it's down from all regions, the site itself is having problems.</p>` });
}

async function toolSsl(domain) {
  let result = "";
  if (domain) {
    const ssl = await getSslExpiry(domain);
    if (!ssl || ssl.expiry == null) result = `<div class="verdict note"><b>${esc(domain)}</b> — couldn't read a certificate. 🟡</div>
      <p class="note">The server may be TLS 1.3-only (its certificate isn't exposed to our probe), may not serve HTTPS, or may be unreachable right now.</p>${crossLink(domain)}`;
    else {
      const days = Math.round((ssl.expiry - Date.now()) / 86400000);
      const cls = days < 0 ? "down" : days <= 21 ? "warn" : "ok";
      const emoji = days < 0 ? "🔴" : days <= 21 ? "⚠️" : "✅";
      const state = days < 0 ? `expired ${-days} day${days === -1 ? "" : "s"} ago` : `valid — expires in ${days} day${days === 1 ? "" : "s"}`;
      result = `<div class="verdict ${cls}"><b>${esc(domain)}</b>'s SSL certificate is ${state}. ${emoji}</div>
        <div class="card">
          <div class="row"><span>Status</span><b>${days < 0 ? '<span class="down">Expired</span>' : '<span class="up">Valid</span>'}</b></div>
          <div class="row"><span>Expires</span><b>${new Date(ssl.expiry).toISOString().slice(0, 10)}${days < 0 ? "" : ` · in ${days} days`}</b></div>
          <div class="row"><span>Issuer</span><b>${esc(ssl.issuer || "—")}</b></div>
        </div>${crossLink(domain)}`;
    }
  }
  return toolShell({
    title: domain ? `${domain} SSL certificate check · HostCop` : "SSL certificate checker · HostCop",
    desc: domain ? `SSL certificate for ${domain}: expiry date, issuer and validity.` : "Check any site's SSL certificate — expiry date, issuer and validity, instantly.",
    path: domain ? "/ssl/" + domain : "/ssl", base: "/ssl", domain, result,
    h1: domain ? `${esc(domain)} SSL certificate` : "SSL certificate checker",
    intro: "Check a site's SSL certificate: when it expires, who issued it, and whether it's still valid.",
    faq: `<h2>Why it matters</h2><p>An expired certificate makes every browser show a big security warning and blocks visitors. HostCop reads the certificate straight from the server's TLS handshake — no third-party service involved.</p>` });
}

async function toolDns(domain) {
  let result = "";
  if (domain) {
    const types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"];
    const all = await Promise.all(types.map(t => dohAll(domain, t)));
    const rows = types.map((t, i) => `<div class="row"><span>${t}</span><b>${all[i].length ? all[i].map(x => esc(x.replace(/^"|"$/g, ""))).join("<br>") : '<span class="muted">—</span>'}</b></div>`).join("");
    result = `<div class="card">${rows}</div>${crossLink(domain)}`;
  }
  return toolShell({
    title: domain ? `${domain} DNS records lookup · HostCop` : "DNS lookup — all records · HostCop",
    desc: domain ? `DNS records for ${domain}: A, AAAA, MX, TXT, NS, CNAME.` : "Look up any domain's DNS records — A, AAAA, MX, TXT, NS and CNAME — instantly.",
    path: domain ? "/dns/" + domain : "/dns", base: "/dns", domain, result,
    h1: domain ? `${esc(domain)} DNS records` : "DNS lookup",
    intro: "See every DNS record for a domain — A, AAAA, MX, TXT, NS and CNAME — in one place.",
    faq: `<h2>What the records mean</h2><p><b>A/AAAA</b> point the domain at a server, <b>MX</b> routes its email, <b>TXT</b> holds SPF/verification data, <b>NS</b> is the authoritative DNS, and <b>CNAME</b> aliases one name to another.</p>` });
}

async function toolRedirect(domain) {
  let result = "";
  if (domain) {
    const pr = await probe(domain);
    if (!pr.up) result = `<div class="verdict down"><b>${esc(domain)}</b> didn't respond — can't trace redirects. 🔴</div>${crossLink(domain)}`;
    else if (pr.chain.length <= 1) result = `<div class="verdict ok"><b>${esc(domain)}</b> doesn't redirect — it serves directly (HTTP ${pr.finalStatus}). ✅</div>${crossLink(domain)}`;
    else {
      const hops = pr.chain.map((c, i) => `<div class="row"><span>Hop ${i + 1}</span><b>${esc(shortUrl(c.url))} <span class="muted">→ ${c.status}</span></b></div>`).join("");
      const n = pr.chain.length - 1;
      result = `<div class="verdict ${pr.loop ? "warn" : "ok"}"><b>${esc(domain)}</b> redirects through ${n} hop${n === 1 ? "" : "s"} to <b>${esc(shortUrl(pr.finalUrl))}</b>${pr.loop ? " — redirect loop detected ⚠️" : " ✅"}</div>
        <div class="card">${hops}</div>${crossLink(domain)}`;
    }
  }
  return toolShell({
    title: domain ? `${domain} redirect chain · HostCop` : "Redirect checker — trace redirects · HostCop",
    desc: domain ? `Full redirect chain for ${domain} — every hop and status code.` : "Trace a URL's full redirect chain — every hop and status code — with HostCop.",
    path: domain ? "/redirect/" + domain : "/redirect", base: "/redirect", domain, result,
    h1: domain ? `${esc(domain)} redirects` : "Redirect checker",
    intro: "Follow a URL through every redirect to its final destination — with the status code at each hop.",
    faq: `<h2>Why redirects matter</h2><p>Long redirect chains slow every visit and leak SEO value; loops break the page entirely. A clean setup is one hop (e.g. http→https or apex→www) straight to a 200.</p>` });
}

const RESOLVERS = [
  ["Cloudflare (1.1.1.1)", d => `https://cloudflare-dns.com/dns-query?name=${d}&type=A`],
  ["Google (8.8.8.8)", d => `https://dns.google/resolve?name=${d}&type=A`],
  ["Quad9 (9.9.9.9)", d => `https://dns.quad9.net:5053/dns-query?name=${d}&type=A`],
  ["DNS.SB", d => `https://doh.dns.sb/dns-query?name=${d}&type=A`],
];
async function resolverA(urlFn, domain) {
  try {
    const r = await fetch(urlFn(domain), { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(5000) });
    const j = await r.json();
    return (j.Answer || []).filter(a => a.type === 1).map(a => a.data).sort();
  } catch { return null; }
}
async function toolPropagation(domain) {
  let result = "";
  if (domain) {
    const answers = await Promise.all(RESOLVERS.map(([, fn]) => resolverA(fn, domain)));
    const responded = answers.filter(a => a !== null);
    const withRecords = responded.filter(a => a.length);
    const someEmpty = responded.some(a => !a.length);
    const uniqueSets = new Set(withRecords.map(a => a.join(",")));
    const rows = RESOLVERS.map(([name], i) => {
      const a = answers[i];
      const val = a === null ? '<span class="muted">no response</span>' : a.length ? a.map(esc).join(", ") : '<span class="down">no record</span>';
      return `<div class="row"><span>${esc(name)}</span><b>${val}</b></div>`;
    }).join("");
    let verdict, tail = "";
    if (responded.length < 2) verdict = `<div class="verdict note"><b>${esc(domain)}</b> — not enough resolver responses to compare. 🟡</div>`;
    else if (someEmpty && withRecords.length) { verdict = `<div class="verdict warn"><b>${esc(domain)}</b> — some resolvers don't see the record yet. Still propagating. ⚠️</div>`; }
    else if (uniqueSets.size <= 1) verdict = `<div class="verdict ok"><b>${esc(domain)}</b>'s DNS is identical across every resolver — fully propagated. ✅</div>`;
    else { verdict = `<div class="verdict note"><b>${esc(domain)}</b> resolves to different IPs per resolver. 🟡</div>`;
      tail = `<p class="note">Different IPs don't necessarily mean a propagation delay — many big sites use <b>load-balancing / GeoDNS</b> and hand out different servers by region. If you just changed DNS, give it time; otherwise this is normal.</p>`; }
    result = `${verdict}<div class="card">${rows}</div>${tail}
      <p class="muted small">Checked across major public resolvers. After a DNS change, different resolvers pick it up at different times.</p>${crossLink(domain)}`;
  }
  return toolShell({
    title: domain ? `${domain} DNS propagation check · HostCop` : "DNS propagation checker · HostCop",
    desc: domain ? `Is ${domain}'s DNS propagated? Compared across major public resolvers.` : "Check whether your DNS change has propagated across major public resolvers worldwide.",
    path: domain ? "/dns-propagation/" + domain : "/dns-propagation", base: "/dns-propagation", domain, result,
    h1: domain ? `${esc(domain)} DNS propagation` : "DNS propagation checker",
    intro: "Changed your DNS? See whether the update has reached the major public resolvers yet.",
    faq: `<h2>How long does propagation take?</h2><p>Usually minutes to a few hours, but it can take up to 48 hours depending on the record's TTL. Until every resolver agrees, some visitors reach the old server and some the new one.</p>` });
}

async function toolEmail(domain) {
  let result = "";
  if (domain) {
    const [txt, dmarcTxt, mx] = await Promise.all([
      dohAll(domain, "TXT"), dohAll("_dmarc." + domain, "TXT"), dohAll(domain, "MX")]);
    const spf = txt.map(t => t.replace(/"/g, "")).find(t => /^v=spf1/i.test(t.trim())) || null;
    const dmarc = dmarcTxt.map(t => t.replace(/"/g, "")).find(t => /v=DMARC1/i.test(t)) || null;
    const selectors = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2", "mandrill", "mailjet", "zoho", "fm1"];
    const dkimResults = await Promise.all(selectors.map(s =>
      dohAll(`${s}._domainkey.${domain}`, "TXT").then(r => ({ s, r })).catch(() => ({ s, r: [] }))));
    const dkimHit = dkimResults.find(x => x.r.some(t => /v=DKIM1|k=rsa|p=[A-Za-z0-9]/i.test(t)));

    let score = 0;
    const spfAll = spf && /-all/.test(spf) ? "strict (-all)" : spf && /~all/.test(spf) ? "soft (~all)" : spf ? "present" : null;
    if (spf) score += /-all/.test(spf) ? 2 : 1;
    const dmarcPol = dmarc ? (dmarc.match(/p=(\w+)/i)?.[1]?.toLowerCase() || "none") : null;
    if (dmarc) score += (dmarcPol === "reject" || dmarcPol === "quarantine") ? 2 : 1;
    if (dkimHit) score += 2;
    const grade = score >= 6 ? "A" : score >= 4 ? "B" : score >= 3 ? "C" : score >= 1 ? "D" : "F";
    const gcls = (grade === "A" || grade === "B") ? "ok" : (grade === "C" || grade === "D") ? "warn" : "down";
    const emoji = gcls === "ok" ? "✅" : gcls === "warn" ? "⚠️" : "🔴";
    const yn = (ok, txt) => `<b>${ok ? `<span class="up">✓</span> ${txt}` : `<span class="down">✗</span> ${txt}`}</b>`;

    result = `<div class="verdict ${gcls}"><b>${esc(domain)}</b>'s email authentication scores <b>${grade}</b>. ${emoji}</div>
      <div class="card">
        <div class="row"><span>SPF</span>${yn(!!spf, spf ? esc(spfAll) : "missing — anyone can spoof your domain")}</div>
        <div class="row"><span>DKIM</span>${dkimHit ? `<b><span class="up">✓</span> found (selector ${esc(dkimHit.s)})</b>` : `<b><span class="warn">?</span> not found with common selectors</b>`}</div>
        <div class="row"><span>DMARC</span>${dmarc ? `<b>${dmarcPol === "none" ? '<span class="warn">⚠</span>' : '<span class="up">✓</span>'} p=${esc(dmarcPol)}</b>` : `<b><span class="down">✗</span> missing</b>`}</div>
        <div class="row"><span>MX (mail server)</span>${yn(!!mx.length, mx.length ? esc(baseDomain(mx[0].split(/\s+/).pop())) : "none")}</div>
      </div>
      <p class="muted small">DKIM uses a provider-specific selector; we probe common ones, so "not found" may just mean a custom selector. DMARC <b>p=none</b> only monitors — move to <b>quarantine</b> or <b>reject</b> to actually stop spoofing.</p>
      ${crossLink(domain)}`;
  }
  return toolShell({
    title: domain ? `${domain} email deliverability (SPF, DKIM, DMARC) · HostCop` : "Email deliverability checker — SPF, DKIM, DMARC · HostCop",
    desc: domain ? `Is ${domain}'s email set up to land in inboxes? SPF, DKIM and DMARC checked and graded.` : "Check any domain's SPF, DKIM and DMARC records and get a deliverability grade.",
    path: domain ? "/email/" + domain : "/email", base: "/email", domain, result,
    h1: domain ? `${esc(domain)} email setup` : "Email deliverability checker",
    intro: "Will your email land in the inbox? Check your SPF, DKIM and DMARC records and get a grade.",
    faq: `<h2>What these do</h2><p><b>SPF</b> says which servers may send as you, <b>DKIM</b> cryptographically signs your mail, and <b>DMARC</b> tells receivers what to do with fakes. Missing any of them means your mail is easier to spoof and more likely to hit spam.</p>` });
}

async function toolHeaders(domain) {
  let result = "";
  if (domain) {
    const doc = await fetchDoc(`https://${domain}/`, 0);
    if (!doc.ok) result = `<div class="verdict down"><b>${esc(domain)}</b> didn't respond — no headers to read. 🔴</div>${crossLink(domain)}`;
    else {
      const sec = [
        ["strict-transport-security", "HSTS — forces HTTPS"],
        ["content-security-policy", "CSP — blocks injection / XSS"],
        ["x-frame-options", "clickjacking protection"],
        ["x-content-type-options", "MIME-sniffing protection"],
        ["referrer-policy", "referrer privacy"],
        ["permissions-policy", "browser-feature control"],
      ];
      const n = sec.filter(([h]) => doc.hdr[h]).length;
      const grade = n >= 5 ? "A" : n === 4 ? "B" : n === 3 ? "C" : n === 2 ? "D" : "F";
      const gcls = n >= 4 ? "ok" : n >= 2 ? "warn" : "down";
      const secRows = sec.map(([h, d]) => {
        const v = doc.hdr[h];
        return `<div class="row"><span>${h}<br><span class="muted small">${d}</span></span><b>${v ? '<span class="up">✓ present</span>' : '<span class="down">✗ missing</span>'}</b></div>`;
      }).join("");
      const allRows = Object.entries(doc.hdr).map(([k, v]) =>
        `<div class="row"><span>${esc(k)}</span><b class="mono" style="word-break:break-all;font-weight:500">${esc(v.length > 160 ? v.slice(0, 160) + "…" : v)}</b></div>`).join("");
      result = `<div class="verdict ${gcls}"><b>${esc(domain)}</b> — security-headers grade <b>${grade}</b> (${n}/6 present). ${gcls === "ok" ? "✅" : gcls === "warn" ? "⚠️" : "🔴"}</div>
        <div class="kicker" style="margin-top:18px">Security headers</div>
        <div class="card">${secRows}</div>
        <div class="kicker" style="margin-top:18px">All response headers</div>
        <div class="card">${allRows}</div>${crossLink(domain)}`;
    }
  }
  return toolShell({
    title: domain ? `${domain} HTTP headers & security grade · HostCop` : "HTTP header checker + security grade · HostCop",
    desc: domain ? `HTTP response headers for ${domain} plus a security-headers grade (HSTS, CSP, and more).` : "Inspect any site's HTTP response headers and grade its security headers — HSTS, CSP, X-Frame-Options and more.",
    path: domain ? "/headers/" + domain : "/headers", base: "/headers", domain, result,
    h1: domain ? `${esc(domain)} HTTP headers` : "HTTP header checker",
    intro: "See a site's full HTTP response headers and a grade for its security headers.",
    faq: `<h2>Why security headers matter</h2><p>Headers like <b>HSTS</b>, <b>CSP</b> and <b>X-Frame-Options</b> defend visitors against downgrade attacks, cross-site scripting and clickjacking. They're free to add and a strong signal of a well-run site.</p>` });
}

async function toolReverseIp(input, env) {
  let result = "";
  if (input) {
    const ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(input) ? input : await resolveA(input);
    if (!ip) result = `<div class="verdict note"><b>${esc(input)}</b> — couldn't resolve that to an IP. 🟡</div>`;
    else {
      const { results } = await env.DB.prepare(
        "SELECT DISTINCT domain FROM checks WHERE ip=? ORDER BY domain LIMIT 100").bind(ip).all();
      const list = results.map(r => `<a href="/check/${esc(r.domain)}">${esc(r.domain)}</a>`).join(" · ");
      result = `<div class="verdict ${results.length ? "ok" : "note"}"><b>${esc(ip)}</b> — ${results.length} domain${results.length === 1 ? "" : "s"} seen on this IP in HostCop's data. ${results.length ? "✅" : "🟡"}</div>
        ${results.length
          ? `<div class="card"><div class="row"><span>Domains</span><b>${list}</b></div></div>`
          : `<p class="note">We haven't recorded other domains on this IP yet — our reverse-IP data grows every time someone runs a check.</p>`}
        ${crossLink(input)}`;
    }
  }
  return toolShell({
    title: input ? `Reverse IP lookup for ${input} · HostCop` : "Reverse IP lookup — sites on the same server · HostCop",
    desc: input ? `Other domains HostCop has seen on the same IP as ${input}.` : "Find other websites sharing the same IP address, from HostCop's measured data.",
    path: input ? "/reverse-ip/" + input : "/reverse-ip", base: "/reverse-ip", domain: input, result,
    h1: input ? `Reverse IP · ${esc(input)}` : "Reverse IP lookup",
    intro: "Enter a domain or IP to see what other sites share the same server, from HostCop's own data.",
    faq: `<h2>What this tells you</h2><p>Sites on the same IP usually share a server. Lots of unrelated domains on one IP means cheap shared hosting; a dedicated IP is a sign of a more serious setup. This list is built from domains HostCop has actually measured, so it grows over time.</p>` });
}

function vcardFn(entity) {
  const v = entity?.vcardArray;
  if (!Array.isArray(v) || v.length < 2) return null;
  return v[1].find(p => p[0] === "fn")?.[3] || null;
}
function humanAge(dateStr) {
  const then = Date.parse(dateStr);
  if (isNaN(then)) return null;
  const months = Math.floor((Date.now() - then) / (86400000 * 30.44));
  if (months < 1) return "less than a month";
  const y = Math.floor(months / 12), m = months % 12;
  return [y ? `${y} year${y > 1 ? "s" : ""}` : "", m ? `${m} month${m > 1 ? "s" : ""}` : ""].filter(Boolean).join(", ");
}

async function toolWhois(domain) {
  let result = "";
  if (domain) {
    let j = null;
    try {
      const r = await fetch(`https://rdap.org/domain/${domain}`,
        { headers: { accept: "application/rdap+json", "user-agent": BROWSER_UA }, redirect: "follow", signal: AbortSignal.timeout(8000) });
      if (r.ok) j = await r.json();
    } catch { }
    if (!j) result = `<div class="verdict note"><b>${esc(domain)}</b> — no WHOIS/RDAP data available (some TLDs don't publish it). 🟡</div>${crossLink(domain)}`;
    else {
      const ev = a => j.events?.find(e => e.eventAction === a)?.eventDate || null;
      const created = ev("registration"), expires = ev("expiration"), updated = ev("last changed");
      const regName = vcardFn(j.entities?.find(e => e.roles?.includes("registrar")));
      const ns = (j.nameservers || []).map(n => n.ldhName?.toLowerCase()).filter(Boolean);
      const status = (j.status || []).join(", ");
      const age = created ? humanAge(created) : null;
      result = `<div class="verdict ok"><b>${esc(domain)}</b>${age ? ` is ${age} old` : ""}${created ? ` — registered ${esc(created.slice(0, 10))}` : ""}. 🗓️</div>
        <div class="card">
          <div class="row"><span>Registered</span><b>${created ? esc(created.slice(0, 10)) + (age ? ` · ${age} ago` : "") : "—"}</b></div>
          <div class="row"><span>Expires</span><b>${expires ? esc(expires.slice(0, 10)) : "—"}</b></div>
          <div class="row"><span>Last updated</span><b>${updated ? esc(updated.slice(0, 10)) : "—"}</b></div>
          <div class="row"><span>Registrar</span><b>${esc(regName || "—")}</b></div>
          <div class="row"><span>Nameservers</span><b>${ns.length ? ns.map(esc).join("<br>") : "—"}</b></div>
          ${status ? `<div class="row"><span>Status</span><b class="muted" style="font-weight:500">${esc(status)}</b></div>` : ""}
        </div>${crossLink(domain)}`;
    }
  }
  return toolShell({
    title: domain ? `${domain} WHOIS & domain age · HostCop` : "WHOIS & domain age lookup · HostCop",
    desc: domain ? `When was ${domain} registered? Domain age, registrar, expiry and nameservers.` : "Look up any domain's age, registrar, registration and expiry dates via RDAP.",
    path: domain ? "/whois/" + domain : "/whois", base: "/whois", domain, result,
    h1: domain ? `${esc(domain)} — WHOIS & age` : "WHOIS & domain age",
    intro: "How old is a domain, who registered it, and when does it expire? Pulled live from official RDAP.",
    faq: `<h2>Why domain age matters</h2><p>An older domain usually signals an established, more trustworthy business, while a domain registered days ago is a common scam signal. Registrar and expiry dates also tell you whether a site is well-maintained or about to lapse.</p>` });
}

// Tech-stack fingerprints from HTML + response headers.
async function toolTech(domain) {
  let result = "";
  if (domain) {
    const doc = await fetchDoc(`https://${domain}/`, 200000);
    const H = doc.html, hdr = doc.hdr;
    if (!doc.ok) result = `<div class="verdict down"><b>${esc(domain)}</b> didn't respond — nothing to fingerprint. 🔴</div>${crossLink(domain)}`;
    else {
      const gen = (H.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i) || [])[1] || "";
      const powered = hdr["x-powered-by"] || "", server = hdr["server"] || "", cookie = hdr["set-cookie"] || "";
      const found = {};
      const add = (cat, name) => (found[cat] = found[cat] || new Set()).add(name);
      if (/wp-content|wp-includes|wp-json/i.test(H) || /wordpress/i.test(gen)) add("CMS", "WordPress");
      if (/woocommerce/i.test(H)) add("E-commerce", "WooCommerce");
      if (/cdn\.shopify\.com|Shopify\.theme/i.test(H) || hdr["x-shopify-stage"] || hdr["x-shopid"]) add("E-commerce", "Shopify");
      if (/static\.wixstatic\.com|wix\.com\//i.test(H) || hdr["x-wix-request-id"]) add("Site builder", "Wix");
      if (/squarespace/i.test(H) || /squarespace/i.test(hdr["x-servedby"] || "")) add("Site builder", "Squarespace");
      if (/assets\.website-files\.com|webflow\.io|Generated by Webflow/i.test(H)) add("Site builder", "Webflow");
      if (/drupal/i.test(gen) || /Drupal\.settings|\/sites\/default\/files/i.test(H) || /drupal/i.test(hdr["x-generator"] || "")) add("CMS", "Drupal");
      if (/joomla/i.test(gen) || /\/media\/jui\//i.test(H)) add("CMS", "Joomla");
      if (/ghost/i.test(gen) || /content=["']Ghost/i.test(H)) add("CMS", "Ghost");
      if (/Mage\.|\/static\/version\d|Magento/i.test(H)) add("E-commerce", "Magento");
      if (/__NEXT_DATA__|\/_next\//i.test(H) || /next\.js/i.test(powered)) add("Framework", "Next.js");
      if (/__NUXT__|\/_nuxt\//i.test(H)) add("Framework", "Nuxt");
      if (/ng-version=|angular\.js/i.test(H)) add("Framework", "Angular");
      if (/data-reactroot|react-dom|_reactListening/i.test(H)) add("Framework", "React");
      if (/data-v-app|__VUE__|vue\.runtime/i.test(H)) add("Framework", "Vue");
      if (/__SVELTEKIT|svelte-/i.test(H)) add("Framework", "Svelte");
      if (/gatsby/i.test(H)) add("Framework", "Gatsby");
      if (/express/i.test(powered)) add("Framework", "Express");
      if (/nginx/i.test(server)) add("Server", "nginx");
      if (/apache/i.test(server)) add("Server", "Apache");
      if (/litespeed/i.test(server)) add("Server", "LiteSpeed");
      if (/microsoft-iis/i.test(server)) add("Server", "IIS");
      if (/php/i.test(powered) || /PHPSESSID/i.test(cookie)) add("Language", "PHP");
      if (/asp\.net/i.test(powered) || /ASP\.NET_SessionId/i.test(cookie)) add("Language", "ASP.NET");
      if (/googletagmanager\.com|gtag\(|google-analytics\.com/i.test(H)) add("Analytics", "Google Analytics / GTM");
      if (/plausible\.io/i.test(H)) add("Analytics", "Plausible");
      if (/static\.hotjar\.com/i.test(H)) add("Analytics", "Hotjar");
      if (/connect\.facebook\.net\/.*fbevents/i.test(H)) add("Analytics", "Meta Pixel");
      if (hdr["cf-ray"] || /cloudflare/i.test(server)) add("CDN", "Cloudflare");
      if (/fastly/i.test(hdr["x-served-by"] || "") || /fastly/i.test(hdr["x-cache"] || "")) add("CDN", "Fastly");
      if (hdr["x-amz-cf-id"]) add("CDN", "Amazon CloudFront");
      if (gen && !Object.keys(found).length) add("Generator", gen.slice(0, 40));

      const cats = Object.keys(found);
      if (!cats.length) result = `<div class="verdict note"><b>${esc(domain)}</b> — no recognisable technologies detected. 🟡</div>
        <p class="muted small">It may be custom-built, static, or deliberately hiding its stack.</p>${crossLink(domain)}`;
      else {
        const rows = cats.map(c => `<div class="row"><span>${esc(c)}</span><b>${[...found[c]].map(t => `<span class="tag">${esc(t)}</span>`).join(" ")}</b></div>`).join("");
        const total = cats.reduce((n, c) => n + found[c].size, 0);
        result = `<div class="verdict ok"><b>${esc(domain)}</b> — detected ${total} technolog${total === 1 ? "y" : "ies"}. 🔎</div>
          <div class="card">${rows}</div>${crossLink(domain)}`;
      }
    }
  }
  return toolShell({
    title: domain ? `${domain} tech stack — what's it built with? · HostCop` : "Tech stack detector · HostCop",
    desc: domain ? `What is ${domain} built with? CMS, framework, server, analytics and CDN detected.` : "Detect the technologies behind any website — CMS, framework, server, analytics and CDN.",
    path: domain ? "/tech/" + domain : "/tech", base: "/tech", domain, result,
    h1: domain ? `${esc(domain)} — tech stack` : "Tech stack detector",
    intro: "What is a website built with? Detect its CMS, framework, server, analytics and CDN from the page and headers.",
    faq: `<h2>How it works</h2><p>HostCop fingerprints the technologies from the page's HTML and HTTP headers — the same signatures tools like Wappalyzer use. Detection is best-effort: sites can hide or proxy these signals, so a blank result doesn't always mean nothing's there.</p>` });
}

async function ttfb(url) {
  const t0 = Date.now();
  try {
    await fetch(url, { redirect: "manual", cf: { cacheTtl: 0 }, signal: AbortSignal.timeout(8000), headers: { "user-agent": BROWSER_UA } });
    return Date.now() - t0;
  } catch { return null; }
}

// Robust page fetch for /headers and /tech: follows redirects, reads at most
// maxBytes of the body (so a huge/slow page can't time us out), retries once.
async function fetchDoc(url, maxBytes) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const r = await fetch(url, {
        redirect: "follow",
        signal: AbortSignal.timeout(9000),
        headers: { "user-agent": BROWSER_UA, accept: "text/html,application/xhtml+xml,*/*;q=0.8" },
      });
      const hdr = {};
      for (const [k, v] of r.headers) hdr[k.toLowerCase()] = v;
      let html = "";
      if (maxBytes > 0 && r.body) {
        const reader = r.body.getReader();
        const dec = new TextDecoder();
        let total = 0;
        while (total < maxBytes) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
          html += dec.decode(value, { stream: true });
        }
        try { await reader.cancel(); } catch { }
      } else if (r.body) { try { await r.body.cancel(); } catch { } }
      return { ok: true, status: r.status, hdr, html };
    } catch { /* retry once */ }
  }
  return { ok: false, hdr: {}, html: "" };
}

async function toolSpeed(domain, request, env) {
  let result = "";
  if (domain) {
    const res = await runCheck(domain, request.cf?.colo || "tool", env);
    if (!res || res.noDns) result = `<div class="verdict down"><b>${esc(domain)}</b> — nothing to time; it didn't resolve. 🔴</div>${crossLink(domain)}`;
    else if (!res.up) result = `<div class="verdict down"><b>${esc(domain)}</b> didn't respond, so there's no speed to measure. 🔴</div>${crossLink(domain)}`;
    else {
      const url = res.finalUrl;
      const regions = await probeRegions(url, env);
      let samples, perRegionRows = "", sourceNote;
      if (regions) {
        const up = regions.filter(r => r.up && r.ms != null);
        samples = up.map(r => r.ms).sort((a, b) => a - b);
        perRegionRows = regions.map(r => `<div class="row"><span>${esc(r.label)}</span><b>${r.up && r.ms != null ? `${r.ms} ms` : '<span class="down">no response</span>'}</b></div>`).join("");
        sourceNote = `Time to first byte, measured live from ${regions.length} Cloudflare regions.`;
      } else {
        samples = [res.ms, await ttfb(url), await ttfb(url)].filter(x => x != null).sort((a, b) => a - b);
        sourceNote = "Time to first byte from a single Cloudflare edge (multi-region temporarily unavailable).";
      }
      if (!samples.length) result = `<div class="verdict down"><b>${esc(domain)}</b> didn't respond, so there's no speed to measure. 🔴</div>${crossLink(domain)}`;
      else {
        const median = samples[Math.floor(samples.length / 2)];
        const best = samples[0];
        const [grade, label, cls] = median < 200 ? ["A", "fast", "ok"] : median < 500 ? ["B", "good", "ok"]
          : median < 1000 ? ["C", "average", "warn"] : median < 2000 ? ["D", "slow", "warn"] : ["F", "very slow", "down"];
        const emoji = cls === "ok" ? "✅" : cls === "warn" ? "⚠️" : "🔴";
        const pctRow = await env.DB.prepare(
          "SELECT ROUND(100.0*AVG(CASE WHEN response_ms > ? THEN 1 ELSE 0 END)) p FROM checks WHERE up=1").bind(median).first();
        const pct = pctRow?.p;
        result = `<div class="verdict ${cls}"><b>${esc(domain)}</b> — median <b>${median} ms</b>${regions ? ` across ${samples.length} region${samples.length === 1 ? "" : "s"}` : ""}, ${label} (grade ${grade}).${pct != null && pct >= 40 ? ` Faster than ${pct}% of sites we've checked.` : ""} ${emoji}</div>
          <div class="stats">
            <div><b>${grade}</b><span>grade</span></div>
            <div><b>${median} ms</b><span>median TTFB</span></div>
            <div><b>${best} ms</b><span>fastest</span></div>
            <div><b>${samples.length}</b><span>${regions ? "regions" : "samples"}</span></div>
          </div>
          ${perRegionRows ? `<div class="kicker" style="margin-top:16px">By region</div><div class="card">${perRegionRows}</div>` : ""}
          <div class="card">
            <div class="row"><span>Hosted by</span><b><a href="/host/${encodeURIComponent(res.brand)}">${esc(res.brand)}</a></b></div>
            <div class="row"><span>Final URL</span><b>${esc(shortUrl(url))}</b></div>
          </div>
          <p class="muted small">${sourceNote}</p>
          ${crossLink(domain)}`;
      }
    }
  }
  return toolShell({
    title: domain ? `${domain} speed test — TTFB & grade · HostCop` : "Website speed test — TTFB · HostCop",
    desc: domain ? `How fast is ${domain}? Time to first byte, a performance grade, and how it compares.` : "Test any website's response time (TTFB) and get a simple performance grade.",
    path: domain ? "/speed/" + domain : "/speed", base: "/speed", domain, result,
    h1: domain ? `${esc(domain)} speed test` : "Website speed test",
    intro: "How fast does a site respond? We measure its time to first byte and grade it — with how it stacks up against every site we've checked.",
    faq: `<h2>What is TTFB?</h2><p>Time to first byte is how long the server takes to start responding — the truest measure of backend and hosting speed, before any images or scripts load. Under 200 ms is excellent; over a second usually points to a slow host or heavy backend.</p>` });
}

// ========================================================================
// ROUTES: content pages
// ========================================================================

async function handleHome(env) {
  // Live figures + a real top-hosts preview, pulled straight from the database.
  let statLine = "", livePreview = "";
  try {
    const s = await env.DB.prepare(
      "SELECT COUNT(*) checks, COUNT(DISTINCT domain) domains, COUNT(DISTINCT brand) hosts FROM checks WHERE brand!='Unknown'"
    ).first();
    if (s && s.checks) statLine = `<div class="statline"><b>${s.checks.toLocaleString()}</b> checks · <b>${s.domains.toLocaleString()}</b> domains · <b>${s.hosts}</b> hosts measured — and counting.</div>`;
    const { results } = await env.DB.prepare(
      `SELECT brand, ROUND(AVG(response_ms)) ms, ROUND(100.0*SUM(up)/COUNT(*),1) up
       FROM checks WHERE brand IS NOT NULL AND brand!='Unknown'
       GROUP BY brand HAVING COUNT(DISTINCT domain) >= ${RANK_MIN_SITES} AND COUNT(*) >= ${RANK_MIN_CHECKS}
       ORDER BY up DESC, ms ASC LIMIT 5`
    ).all();
    if (results.length) livePreview = `
      <section>
        <div class="kicker">Live from the database</div>
        <h2>Most reliable hosts right now</h2>
        <div class="card">${results.map((r, i) =>
          `<div class="row"><span>${i + 1}. <a href="/host/${encodeURIComponent(r.brand)}">${esc(r.brand)}</a></span><b>${r.up}% · ${r.ms} ms</b></div>`).join("")}</div>
        <p class="muted small">Ranked by measured uptime, then speed. <a href="/hosts">See the full rankings →</a></p>
      </section>`;
  } catch {}

  const body = `
    ${heroSection()}
    <div class="trustbadge center">🛡 No affiliate links · No paid placements · Just measured data</div>
    ${statLine}
    ${livePreview}

    <section class="how">
      <div class="kicker">3 steps</div>
      <h2>How it works</h2>
      <ol class="steps">
        <li><b>1 · Enter a domain</b><span>Any website — yours or a competitor's.</span></li>
        <li><b>2 · We detect the real host</b><span>We resolve the IP and trace its network (ASN) to see who's actually behind the CDN or reseller.</span></li>
        <li><b>3 · We measure it live</b><span>Response time, up/down and SSL expiry — right now, from the edge, and saved to the public record.</span></li>
      </ol>
    </section>

    <section>
      <div class="kicker">Live output</div>
      <h2>Example result</h2>
      <p class="muted">This is what you get back the moment you check a domain:</p>
      <div class="card demo">
        <div class="demo-head">wikipedia.org <span class="tag">EXAMPLE</span></div>
        <div class="row"><span>Hosted by</span><b>WIKIMEDIA</b></div>
        <div class="row"><span>Type</span><b>Origin host</b></div>
        <div class="row"><span>Location (approx)</span><b>🇺🇸 US</b></div>
        <div class="row"><span>Status</span><b><span class="up">UP</span> · 41 ms · HTTP 200</b></div>
        <div class="row"><span>SSL certificate</span><b><span class="up">68 days left</span> · 2026-09-11</b></div>
      </div>
    </section>

    <section>
      <div class="kicker">Signals</div>
      <h2>What HostCop detects</h2>
      <div class="grid">
        <div class="feat"><b>Real hosting provider</b><span>The company whose network actually serves the site.</span></div>
        <div class="feat"><b>CDN &amp; edge networks</b><span>We flag Cloudflare, Akamai, Fastly &amp; co. so you know the origin is masked.</span></div>
        <div class="feat"><b>IP &amp; ASN</b><span>The exact address and autonomous system number behind the domain.</span></div>
        <div class="feat"><b>Approx. location</b><span>The country of the network serving the site.</span></div>
        <div class="feat"><b>Response time</b><span>How fast the server answers, measured live.</span></div>
        <div class="feat"><b>Uptime</b><span>Aggregated up/down across every check we've run.</span></div>
        <div class="feat"><b>SSL expiry</b><span>When the TLS certificate runs out — before it bites you.</span></div>
        <div class="feat"><b>Live host rankings</b><span>Every check feeds a neutral, unbiased leaderboard.</span></div>
      </div>
    </section>

    <section>
      <div class="kicker">Free tools</div>
      <h2>A whole toolbox — fast, neutral, no ads</h2>
      <div class="toolgrid">${TOOLS.map(([href, icon, name, d]) => `<a class="toolcard" href="${href}"><b>${icon} ${esc(name)}</b><span>${esc(d)}</span></a>`).join("")}</div>
    </section>

    <section class="why">
      <div class="kicker">Manifesto</div>
      <h2>Why HostCop exists</h2>
      <p>Almost every "best web hosting" list online is paid for. The sites at the top aren't the fastest or the most reliable — they're the ones paying the biggest affiliate commission. When you're trying to decide who to trust with your website, that's worse than no information at all.</p>
      <p>HostCop is the opposite. We don't run reviews and we don't take money to move anyone up the list. Instead, every time someone checks a domain, we measure the host for real — who they are, how fast they respond, whether they're up, and when their SSL expires — and we save it. The more people check, the sharper the picture gets. The rankings you see are literally the measurements, ordered. Nothing is editorialised, nothing is sponsored.</p>
      <p>That means you can finally answer the questions that matter before you pay anyone: <i>Who really hosts this site? Is my host quietly a reseller of someone else's servers? Is this "premium" host actually any faster than the cheap one? Is my certificate about to expire?</i> Check a domain above and see for yourself — it takes a couple of seconds and costs nothing.</p>
      <p class="muted">Neutral by design: HostCop uses <b>no affiliate links</b> today, and if that ever changes it will never influence a ranking and will be clearly labelled. Read our <a href="/methodology">methodology</a> or the story <a href="/about">behind the project</a>.</p>
    </section>
  `;
  return html(layout({
    title: "HostCop — who really hosts any website? Neutral, measured, no fake reviews",
    desc: "Paste a domain and HostCop detects the real hosting provider behind CDNs and resellers, then measures response time, uptime and SSL expiry live. Neutral host rankings from crowdsourced data — no reviews, no affiliate bias.",
    path: "/", body, home: true,
    jsonld: [{
      "@context": "https://schema.org", "@type": "WebSite", name: "HostCop", url: BASE + "/",
      potentialAction: {
        "@type": "SearchAction",
        target: { "@type": "EntryPoint", urlTemplate: `${BASE}/check/{domain}` },
        "query-input": "required name=domain",
      },
    }],
  }));
}

function heroSection() {
  return `
    <section class="hero">
      <div class="hero-copy">
        <div class="kicker">The hosting watchdog</div>
        <h1>Who <span class="hl">really</span> hosts your site?</h1>
        <p class="lede">HostCop traces the real host behind any domain — through CDNs and resellers — and measures how it actually performs. Measured data, never fake reviews.</p>
        <form id="checkform" action="/check" method="get">
          <input name="domain" placeholder="yourdomain.com" autofocus autocomplete="off" spellcheck="false">
          <button>Check host</button>
        </form>
        <a class="ranklink" href="/hosts">Or browse the live host rankings →</a>
      </div>
      <div class="hero-visual" aria-hidden="true">
        <div class="monitor">
          <div class="mhead"><span class="livedot"></span> live edge probe</div>
          <div class="mrow"><span>host</span><b>CLOUDFLARENET</b></div>
          <div class="mrow"><span>ip</span><b>104.16.132.229</b></div>
          <div class="mrow"><span>response</span><b class="up">38 ms</b></div>
          <div class="mrow"><span>uptime</span><b class="up">99.98%</b></div>
          <div class="mrow"><span>ssl</span><b>112 days</b></div>
        </div>
      </div>
    </section>`;
}

function pageMethodology() {
  return contentPage("Methodology", "/methodology",
    "How HostCop measures hosting performance: what we measure, from where, how often, and the limits of the data.",
    `<h1>Methodology</h1>
     <p>HostCop's whole value is that the numbers are honest. So here's exactly how they're produced — including where the method has limits.</p>
     <h2>Detecting the host</h2>
     <p>When you check a domain we resolve its <b>A record</b> using DNS-over-HTTPS, then look up which network owns that IP address via its <b>ASN</b> (autonomous system number). The ASN's registered organisation is the "host" we show. If that organisation is a known <b>CDN or edge network</b> (Cloudflare, Akamai, Fastly and others), we flag it clearly — because in that case the real origin server is deliberately hidden behind the CDN and cannot be seen from the outside.</p>
     <h2>Measuring performance</h2>
     <ul>
       <li><b>Response time</b> — we request the site over HTTPS and time how long it takes to respond. It's a single measurement per check, taken from Cloudflare's edge network closest to where the check runs.</li>
       <li><b>Up / down</b> — whether the server answered at all. Aggregated across every check, this becomes the uptime percentage.</li>
       <li><b>SSL expiry</b> — we open a raw TLS connection and read the certificate's expiry date directly from the handshake. Servers that only support TLS 1.3 don't expose this to us, so a few will show no date.</li>
     </ul>
     <h2>How often</h2>
     <p>Every domain you check is measured immediately, and tracked domains are automatically re-checked on a schedule (roughly every 30 minutes) so rankings reflect current reality, not a one-off snapshot.</p>
     <h2>How rankings are built</h2>
     <p>A host must have at least <b>3 checks</b> to appear in the rankings. We then order hosts by measured uptime, then by average response time. You can re-sort by fastest or most-tested. There is no manual curation and no sponsored placement — the ranking <i>is</i> the data.</p>
     <h2>Honest limits</h2>
     <p>The speed test and the "is it down" tool measure from <b>five Cloudflare regions</b> (North America, Europe, Asia, South America, Oceania) via edge-placed probes, so you see real per-region timing and we only call a site "down" when every region fails to reach it. Region placement is best-effort, so a probe sits <i>near</i> its region, not at a fixed city. ASN location is the network's registered country, an approximation of physical server location. And behind a CDN, we measure the CDN edge — not the hidden origin. We'd rather tell you these limits than pretend the data is perfect.</p>`);
}

function pageAbout() {
  return contentPage("About", "/about",
    "Who's behind HostCop and why it was built — a neutral hosting watchdog with no affiliate bias.",
    `<h1>About HostCop</h1>
     <p>HostCop is an independent project built to fix one specific, annoying problem: it's almost impossible to get an <b>honest</b> answer about web hosting. Search "best web host" and every result is an affiliate page ranking whoever pays the most. There was no neutral watchdog measuring hosts by what they actually do.</p>
     <p>So HostCop measures. Every time anyone checks a domain, we record who hosts it and how it performs, and that data — nobody's opinion — builds the rankings. The more people use it, the more accurate it gets. That's the entire idea.</p>
     <h2>Independence &amp; money</h2>
     <p>HostCop currently makes no money and uses <b>no affiliate links</b>. If we ever add them to keep the lights on, they will be clearly labelled and will <b>never</b> affect a host's ranking — rankings will always come purely from measured data. That promise is the point of the whole site; breaking it would make HostCop worthless.</p>
     <h2>Get in touch</h2>
     <p>Spotted something wrong, or want a feature? <a href="/contact">Contact us</a>.</p>`);
}

const GUIDES = {
  "who-hosts-a-website": {
    title: "How to find out who hosts a website",
    desc: "A simple, reliable way to discover the real hosting provider behind any domain — even when it's hidden behind a CDN.",
    date: "2026-07-05",
    body: `<p>Whether you're researching a competitor, chasing down abuse, or just curious, finding out who hosts a website is easier than most people think. Here's how it actually works.</p>
      <h2>1. Resolve the domain to an IP</h2>
      <p>Every website lives at an IP address. When you type a domain, DNS translates it to that address. The fastest way to see it is to check the domain's <b>A record</b> — or just <a href="/">paste the domain into HostCop</a>, which does it for you.</p>
      <h2>2. Trace the IP to a network (ASN)</h2>
      <p>An IP address on its own doesn't name a company. What you want is the <b>ASN</b> — the autonomous system number that owns the address block. The ASN maps to the organisation that actually runs the network: the real host. HostCop looks this up automatically and shows you the provider name.</p>
      <h2>3. Watch out for CDNs</h2>
      <p>Here's the catch. If a site uses a CDN like Cloudflare, Akamai or Fastly, the IP points to the <b>CDN</b>, not the origin server. So a naive lookup will tell you "Cloudflare" when the real host is someone else entirely, hidden behind it. HostCop flags this for you so you're not misled — when you see the CDN badge, you know the true origin is masked.</p>
      <h2>The shortcut</h2>
      <p>You can do all of this by hand with dig and whois — or you can <a href="/">check the domain on HostCop</a> and get the host, IP, ASN, location, speed and SSL status in one shot, for free.</p>`,
  },
  "is-my-host-a-reseller": {
    title: "Signs your web host is secretly a reseller",
    desc: "Many 'hosting companies' are just reselling someone else's servers at a markup. Here's how to tell.",
    date: "2026-07-05",
    body: `<p>A surprising number of hosting brands don't own any servers at all. They rent capacity wholesale from a bigger provider and resell it to you at a markup — sometimes with worse support and no real control. That's not always bad, but you should know when you're paying middleman prices.</p>
      <h2>1. The network doesn't match the brand</h2>
      <p>The clearest tell: look up who actually owns the IP your site sits on. If your host is "SuperFastHost" but the ASN belongs to a giant wholesale datacenter operator, you're on resold infrastructure. <a href="/">Check your domain on HostCop</a> — the "Hosted by" line shows the network's real owner, not the brand on your invoice.</p>
      <h2>2. Suspiciously cheap "unlimited" plans</h2>
      <p>Resellers compete on price because they can't compete on infrastructure. Unlimited-everything for a couple of dollars usually means heavily oversold shared servers.</p>
      <h2>3. Support that can't answer server questions</h2>
      <p>Ask a specific question about the underlying hardware, network, or a low-level configuration. A true host knows; a reseller often has to "escalate to the datacenter" — because they are the datacenter's customer, just like you.</p>
      <h2>4. Performance that doesn't match the marketing</h2>
      <p>Resold shared hosting is frequently slow under load. HostCop's <a href="/hosts">measured rankings</a> let you compare your host's real response time and uptime against others — no marketing, just numbers.</p>
      <p>None of these alone proves anything, but together they paint a picture. And the network-ownership check is the one that rarely lies.</p>`,
  },
  "what-is-an-asn": {
    title: "What is an ASN, and why it matters for hosting",
    desc: "A plain-English explanation of autonomous system numbers and how they reveal who really runs a website's servers.",
    date: "2026-07-05",
    body: `<p>If you've used HostCop you've seen a number like "AS13335" next to a domain. That's an <b>ASN</b> — an autonomous system number — and it's the key to knowing who really hosts a site. Here's the plain-English version.</p>
      <h2>The internet is a network of networks</h2>
      <p>The internet isn't one thing; it's thousands of independent networks that agree to route traffic to each other. Each of those networks is an "autonomous system", and each gets a unique number — its ASN. Cloudflare is AS13335, for example.</p>
      <h2>Why it identifies the host</h2>
      <p>IP addresses are handed out in blocks, and every block is announced to the internet by exactly one ASN — the network that controls it. So if you know the IP a website uses, you can find the ASN, and the ASN tells you which <b>organisation</b> actually operates the servers. That's far more reliable than trusting the brand name on a hosting invoice.</p>
      <h2>The CDN wrinkle</h2>
      <p>When a site is behind a CDN, the ASN you find is the CDN's, not the origin host's — because the CDN is what answers on that IP. That's why HostCop labels CDNs explicitly instead of pretending the CDN is the host.</p>
      <h2>See it yourself</h2>
      <p><a href="/">Check any domain</a> and HostCop shows the IP, its ASN, and the organisation behind it — the real answer to "who hosts this?".</p>`,
  },
  "how-to-choose-a-web-host": {
    title: "How to choose a web host (without falling for fake reviews)",
    desc: "A practical checklist for picking a web host based on measured performance, not affiliate-paid reviews.",
    date: "2026-07-06",
    body: `<p>Almost every "best web hosting 2026" list is an affiliate page — the hosts at the top are the ones paying the biggest commission, not the fastest or most reliable. Here's how to choose based on facts instead.</p>
      <h2>1. Ignore the review sites</h2>
      <p>If a page ranks hosts and links to them with tracking codes, assume the order is paid for. Real quality is measurable, so measure it. HostCop's <a href="/hosts">rankings</a> are built purely from live checks — uptime and response time — with no affiliate money involved.</p>
      <h2>2. What actually matters</h2>
      <p><b>Uptime</b> (does it stay online), <b>response time / TTFB</b> (how fast the server answers), <b>real support</b> (can they fix server issues, not just read a script), and <b>honest infrastructure</b> (are they a real host or reselling someone else's servers at a markup?). Price matters too, but cheap-and-slow is the most expensive option once you lose visitors.</p>
      <h2>3. Verify with data before you buy</h2>
      <p>Pick two or three candidates and check sites already hosted on them. <a href="/speed">Test their speed</a>, look at their <a href="/hosts">measured uptime</a>, and <a href="/compare">compare them head to head</a>. If a "host" turns out to run on Amazon or Hetzner, you may be paying a reseller markup — <a href="/">a full report</a> reveals that.</p>
      <h2>4. Red flags</h2>
      <p>"Unlimited everything" for a couple of dollars (oversold shared servers), support that always escalates "to the datacenter" (reseller), and no clear answer about where your site physically runs. When in doubt, favour a host that owns its infrastructure.</p>
      <h2>The shortcut</h2>
      <p>Start at the <a href="/hosts">HostCop rankings</a>, shortlist by measured uptime and speed, then <a href="/">check a few real sites</a> on each. Data beats reviews every time.</p>`,
  },
  "shared-vs-vps-vs-cloud-hosting": {
    title: "Shared vs VPS vs cloud hosting: which do you need?",
    desc: "Plain-English comparison of shared, VPS and cloud hosting — what each means, what it costs, and who it's for.",
    date: "2026-07-06",
    body: `<p>The three words you'll see everywhere when buying hosting — shared, VPS, cloud — describe how your website shares a physical server with others. Here's the difference in plain terms.</p>
      <h2>Shared hosting</h2>
      <p>Your site sits on one server alongside hundreds of others, all sharing the same CPU and memory. It's the cheapest option (a few dollars a month) and fine for small sites, blogs and brochure pages. The downside: a busy neighbour can slow you down, and it's often oversold. Most cheap "unlimited" plans are shared hosting.</p>
      <h2>VPS (Virtual Private Server)</h2>
      <p>The server is split into isolated virtual machines, and you get a guaranteed slice of CPU and RAM that others can't steal. More money (roughly $5–40/mo), more control, and far more consistent performance. Good once a site outgrows shared hosting or needs custom software.</p>
      <h2>Cloud hosting</h2>
      <p>Your site runs across a pool of servers instead of one machine, so it can scale up under traffic spikes and survive a single server failing. Providers like AWS, Google Cloud and DigitalOcean sell this. Pricing is usually usage-based. Best for apps that must stay up and handle variable load.</p>
      <h2>How to tell what a site uses</h2>
      <p>You often can't tell shared from VPS from the outside, but you <i>can</i> see the real infrastructure. <a href="/">Check a domain on HostCop</a> and it names the network behind it — if a small "host" actually runs on Amazon or Hetzner, that's resold cloud infrastructure. Lots of unrelated sites on <a href="/reverse-ip">the same IP</a> usually means shared hosting.</p>
      <h2>Which should you pick?</h2>
      <p>Small site on a budget: shared. Growing site that needs reliable speed: VPS. App that must scale and stay up: cloud. And whatever you choose, <a href="/monitor">monitor it</a> so you know the moment it goes down.</p>`,
  },
  "why-emails-go-to-spam": {
    title: "Why your emails go to spam (and how to fix it)",
    desc: "The real reasons business email lands in spam — SPF, DKIM and DMARC — and how to check and fix yours.",
    date: "2026-07-06",
    body: `<p>If your emails keep landing in spam, the cause is usually not your words — it's that receivers can't verify your mail is really from you. Three DNS records fix that.</p>
      <h2>SPF — who's allowed to send</h2>
      <p>SPF is a DNS record listing which servers may send email as your domain. Without it, anyone can forge your address, so receivers distrust everything. With a strict SPF record, they can reject fakes.</p>
      <h2>DKIM — a tamper-proof signature</h2>
      <p>DKIM cryptographically signs each message. The receiver checks the signature against a public key in your DNS. If it matches, the mail genuinely came from you and wasn't altered in transit.</p>
      <h2>DMARC — the policy that ties it together</h2>
      <p>DMARC tells receivers what to do with mail that fails SPF or DKIM: monitor it (p=none), send it to spam (p=quarantine), or reject it outright (p=reject). Crucially, <b>p=none does nothing</b> to stop spoofing — it only reports. Move to quarantine or reject once you're confident.</p>
      <h2>Other common causes</h2>
      <p>A brand-new sending domain with no reputation, links to a mismatched domain, spammy words, or sending from a shared IP with a bad history. But missing SPF/DKIM/DMARC is the number-one fixable cause.</p>
      <h2>Check yours in seconds</h2>
      <p>Run your domain through HostCop's <a href="/email">email deliverability checker</a>. It reads your SPF, DKIM and DMARC records, grades them, and tells you exactly what's missing — so you can hand the fix to your email provider or DNS host.</p>`,
  },
  "what-is-a-cdn": {
    title: "What is a CDN, and do you need one?",
    desc: "What a content delivery network does, when it helps, and how to tell if a site is already using one.",
    date: "2026-07-06",
    body: `<p>A CDN — content delivery network — is a layer of servers spread around the world that sits in front of your website and serves copies of it from wherever your visitor is. Here's what that actually buys you.</p>
      <h2>What a CDN does</h2>
      <p>Instead of every visitor reaching your one origin server (which might be on another continent), they hit the nearest CDN "edge" server, which serves cached content instantly. Cloudflare, Akamai and Fastly are the big names.</p>
      <h2>Why people use one</h2>
      <p><b>Speed</b> — content is closer to visitors, so pages load faster globally. <b>Protection</b> — CDNs absorb traffic spikes and block DDoS attacks. <b>Free SSL</b> — most include HTTPS. <b>Less load</b> — your origin server does less work.</p>
      <h2>The catch</h2>
      <p>A CDN <i>hides</i> your real host. Anyone looking up your site sees the CDN, not the origin — which is great for security but means the CDN's speed masks how good (or bad) your actual host is. Your real host still determines performance for anything the CDN can't cache.</p>
      <h2>Do you need one?</h2>
      <p>If you have visitors in more than one region, or you want DDoS protection and free SSL, a CDN is almost always worth it — and Cloudflare's free tier costs nothing. A small, single-region site may not need one.</p>
      <h2>Is a site already using a CDN?</h2>
      <p><a href="/">Check it on HostCop</a> — we flag CDNs explicitly and even try to reveal the <b>real origin host hidden behind them</b>. The <a href="/tech">tech-stack tool</a> also detects the CDN in use.</p>`,
  },
  "how-to-check-if-a-website-is-down": {
    title: "Is it down, or is it just you? How to check",
    desc: "How to tell whether a website is really down for everyone or just unreachable from your network.",
    date: "2026-07-06",
    body: `<p>A site won't load. Before you panic (or blame the host), find out whether it's actually down for everyone — or just unreachable from where you are.</p>
      <h2>Down for everyone vs just you</h2>
      <p>If a site is genuinely down, it fails from everywhere. If it works from other networks but not yours, the problem is local: your ISP, a stale DNS cache, a VPN, or a firewall. The two need completely different fixes.</p>
      <h2>Check from multiple locations</h2>
      <p>The reliable test is to reach the site from several places at once. HostCop's <a href="/down">is-it-down checker</a> pings the site from <b>five regions</b> (North America, Europe, Asia, South America, Oceania) and tells you how many can reach it — so you instantly know if it's a global outage or a local issue.</p>
      <h2>If it's just you</h2>
      <p>Flush your DNS cache, try a different network (e.g. mobile data), disable your VPN, or switch DNS to 1.1.1.1 or 8.8.8.8. The site is fine; your path to it isn't.</p>
      <h2>If it's really down</h2>
      <p>Check whether it's the whole server or one thing: is it a <a href="/ssl">certificate problem</a>, a <a href="/redirect">redirect loop</a>, or a 5xx server error? A <a href="/">full report</a> shows the status code and who to contact (the host).</p>
      <h2>Never be the last to know</h2>
      <p>If it's your own site, set up <a href="/monitor">free monitoring</a> — HostCop emails you the moment it goes down, so you hear it from us, not from an angry customer.</p>`,
  },
  "ssl-certificate-expired": {
    title: "SSL certificate expired? What it means and how to fix it",
    desc: "What happens when an SSL certificate expires, why it breaks your site, and how to renew and never get caught again.",
    date: "2026-07-06",
    body: `<p>An expired SSL certificate is one of the most avoidable ways to break a website — and one of the most common. Here's what it means and how to fix it fast.</p>
      <h2>What actually happens</h2>
      <p>An SSL/TLS certificate proves your site is really yours and encrypts traffic. It has an expiry date. The moment it lapses, every browser shows a full-page red <b>"Your connection is not private"</b> warning, and most visitors leave immediately. The site itself is fine — but nobody can get past the warning.</p>
      <h2>How to fix it now</h2>
      <p>Renew or reissue the certificate through whoever provides it — your host, Cloudflare, or a service like Let's Encrypt. If you use Cloudflare or a modern host, SSL usually auto-renews; a lapse often means auto-renewal broke and needs re-enabling.</p>
      <h2>Why it lapsed</h2>
      <p>Common causes: a manual certificate nobody remembered to renew, a domain that changed hosts, DNS validation that stopped working, or auto-renewal silently failing. Free Let's Encrypt certs last 90 days, so they must renew automatically.</p>
      <h2>Check any certificate's expiry</h2>
      <p>Run your domain through HostCop's <a href="/ssl">SSL checker</a> — it reads the certificate straight from the server and tells you the exact expiry date, days remaining, and the issuer.</p>
      <h2>Never get caught again</h2>
      <p>Set up <a href="/monitor">free monitoring</a>. HostCop emails you when your certificate is within <b>14 days</b> of expiring, so you always have time to renew before visitors ever see a warning.</p>`,
  },
  "dns-records-explained": {
    title: "DNS records explained: A, AAAA, MX, TXT, NS, CNAME",
    desc: "A beginner-friendly guide to the DNS records that make your website and email work.",
    date: "2026-07-06",
    body: `<p>DNS is the internet's address book: it turns a domain name into the information browsers and mail servers need. Here are the records you'll actually deal with.</p>
      <h2>A and AAAA — where the website lives</h2>
      <p>An <b>A record</b> points your domain to an IPv4 address (like 192.0.2.1); an <b>AAAA record</b> does the same for IPv6. This is what sends visitors to your web server. Change it and you move your site to a new host.</p>
      <h2>CNAME — an alias</h2>
      <p>A <b>CNAME</b> points one name at another name instead of an IP — e.g. <code>www</code> pointing to your root domain, or a subdomain pointing to a service like a CDN or site builder.</p>
      <h2>MX — where email goes</h2>
      <p><b>MX records</b> tell the world which mail servers handle email for your domain. If your email runs on Google Workspace or Microsoft 365, your MX records point there. No MX records means no incoming mail.</p>
      <h2>TXT — notes and verification</h2>
      <p><b>TXT records</b> hold plain text used for verification and email security — your <b>SPF</b> and <b>DMARC</b> records live here, as do domain-ownership checks for various services.</p>
      <h2>NS — who runs your DNS</h2>
      <p><b>NS records</b> name the authoritative nameservers for your domain — the DNS provider (your registrar, Cloudflare, etc.) that answers all these lookups.</p>
      <h2>See all of them for any domain</h2>
      <p>HostCop's <a href="/dns">DNS lookup tool</a> shows every record — A, AAAA, MX, TXT, NS and CNAME — in one place, and the <a href="/dns-propagation">propagation checker</a> tells you if a change has spread yet.</p>`,
  },
  "why-is-my-website-slow": {
    title: "Why is my website slow? Start with TTFB",
    desc: "How to diagnose a slow website, starting with time to first byte — the truest measure of hosting speed.",
    date: "2026-07-06",
    body: `<p>"My site is slow" has many causes, but there's one number that tells you whether the problem is your <i>host</i> or your <i>page</i>: time to first byte.</p>
      <h2>What TTFB is</h2>
      <p>Time to first byte (TTFB) is how long the server takes to <i>start</i> responding — before any images, fonts or scripts load. It measures the backend and the host, not the page weight. Under 200 ms is excellent; over a second points to a slow server or a heavy backend.</p>
      <h2>If TTFB is high, blame the backend</h2>
      <p>A slow TTFB usually means an overloaded shared host, a slow database, no caching, or a server far from your visitors. Fixes: better hosting, a caching layer, or a CDN to serve content closer to users. Compare your host's real speed in the <a href="/hosts">rankings</a>.</p>
      <h2>If TTFB is low but the page still feels slow</h2>
      <p>Then it's the front end: huge images, too many scripts, render-blocking resources. That's a page-optimisation problem, not a hosting one — compress images, defer scripts, and lazy-load.</p>
      <h2>Measure it properly</h2>
      <p>HostCop's <a href="/speed">speed test</a> measures TTFB from <b>five regions</b> and grades it, and tells you how you compare to every site we've checked. Testing from multiple regions matters — a site can be fast near its server and slow on the other side of the world.</p>
      <h2>Still slow after all that?</h2>
      <p>If your host's measured speed is poor across the board, the fix may simply be a better host. <a href="/compare">Compare two hosts</a> on real data before you switch.</p>`,
  },
};

function pageGuidesIndex() {
  const items = Object.entries(GUIDES).map(([slug, g]) =>
    `<li><a href="/guides/${slug}"><b>${esc(g.title)}</b></a><span class="muted">${esc(g.desc)}</span></li>`).join("");
  return contentPage("Guides", "/guides",
    "Plain-English guides to web hosting: how to find who hosts a site, spotting resellers, understanding ASNs and more.",
    `<h1>Guides</h1>
     <p class="muted">Practical, jargon-free explainers on hosting — how to see who's really behind a website and judge whether they're any good.</p>
     <ul class="guidelist">${items}</ul>`);
}

function pageGuide(slug) {
  const g = GUIDES[slug];
  if (!g) return notFound();
  const jsonld = [
    { "@context": "https://schema.org", "@type": "Article", headline: g.title, description: g.desc,
      datePublished: g.date, dateModified: g.date, url: `${BASE}/guides/${slug}`,
      author: { "@type": "Organization", name: "HostCop" },
      publisher: { "@type": "Organization", name: "HostCop", logo: { "@type": "ImageObject", url: `${BASE}/logo.png` } } },
    breadcrumbLd([{ name: "Home", url: "/" }, { name: "Guides", url: "/guides" }, { name: g.title, url: "/guides/" + slug }]),
  ];
  return contentPage(g.title, "/guides/" + slug, g.desc,
    `<a class="back" href="/guides">← all guides</a>
     <h1>${esc(g.title)}</h1>
     <p class="muted">Guide · updated ${g.date}</p>
     ${g.body}
     <p class="cta"><a class="btn" href="/">Check a domain now →</a></p>`, jsonld);
}

function pagePrivacy() {
  return contentPage("Privacy Policy", "/privacy",
    "How HostCop handles data. Short version: we store the domains checked and their public measurements, and nothing personal.",
    `<h1>Privacy Policy</h1>
     <p class="muted">Last updated 2026-07-05</p>
     <p>HostCop is built to be lightweight and privacy-respecting. This policy explains what we collect and why.</p>
     <h2>What we store</h2>
     <p>When a domain is checked, we store the <b>domain name</b> and the <b>public technical measurements</b> we take about it: its IP, ASN, hosting provider, approximate country, response time, up/down status and SSL expiry date. This is public infrastructure data about websites, not personal data about you.</p>
     <h2>What we don't do</h2>
     <p>We don't require an account, we don't ask for personal information, and we don't sell data. We don't use third-party advertising or tracking cookies. Standard server logs and Cloudflare's infrastructure may process request metadata (such as IP addresses) transiently to serve and protect the site.</p>
     <h2>Public data</h2>
     <p>Because HostCop is a public watchdog, the measurements collected about a domain (host, performance, etc.) may be shown publicly on result and ranking pages. Please don't check domains you consider confidential.</p>
     <h2>Contact</h2>
     <p>Questions? <a href="/contact">Get in touch</a>.</p>`);
}

function pageTerms() {
  return contentPage("Terms of Service", "/terms",
    "The terms for using HostCop. Provided as-is, for informational purposes, with no warranty.",
    `<h1>Terms of Service</h1>
     <p class="muted">Last updated 2026-07-05</p>
     <p>By using HostCop you agree to these terms.</p>
     <h2>Informational service</h2>
     <p>HostCop provides technical measurements about websites for informational purposes. We work hard to be accurate, but the data is provided <b>"as is"</b> without warranty of any kind. Measurements can be affected by transient network conditions, CDNs, and the limits described in our <a href="/methodology">methodology</a>. Don't rely on HostCop as the sole basis for a critical decision.</p>
     <h2>Acceptable use</h2>
     <p>Use HostCop to check domains and read rankings. Don't abuse the service — no automated bulk scraping designed to overload it, and no use of the data to harm others. We may rate-limit or block abusive traffic.</p>
     <h2>No affiliation</h2>
     <p>Hosting providers named on HostCop are identified purely from public network data. Their appearance does not imply any relationship with, or endorsement by, them or us.</p>
     <h2>Changes</h2>
     <p>We may update these terms; continued use means you accept the current version.</p>`);
}

function pageContact() {
  return contentPage("Contact", "/contact",
    "Get in touch with HostCop — corrections, feature requests, or questions.",
    `<h1>Contact</h1>
     <p>Found a wrong result, want a feature, or just have a question? We'd like to hear it.</p>
     <p class="contact"><a href="mailto:hello@hostcop.com">hello@hostcop.com</a></p>
     <p class="muted">HostCop is an independent, neutral project. If you're a hosting provider and think a measurement is unfair, email us — but note that rankings come only from measured data and we don't remove accurate results.</p>`);
}

// Shared content-page wrapper
function contentPage(title, path, desc, inner, jsonld) {
  return html(layout({ title: `${title} · HostCop`, desc, path, jsonld, body: `<article class="prose">${inner}</article>` }));
}

// ========================================================================
// STATIC ASSETS
// ========================================================================

function robots() {
  return new Response(`User-agent: *\nAllow: /\nSitemap: ${BASE}/sitemap.xml\n`,
    { headers: { "content-type": "text/plain" } });
}

async function sitemap(env) {
  const staticUrls = ["/", "/hosts", "/compare", "/monitor", "/pricing", "/bulk", "/api",
    "/tools", "/down", "/ssl", "/dns", "/redirect", "/dns-propagation", "/email", "/headers", "/reverse-ip", "/whois", "/tech", "/speed",
    "/guides", "/methodology", "/about", "/privacy", "/terms", "/contact",
    ...Object.keys(GUIDES).map(s => "/guides/" + s)];
  let providerUrls = [], compareUrls = [], domainUrls = [];
  try {
    const top = await topProviders(env, 200);
    providerUrls = top.map(p => "/host/" + encodeURIComponent(p));
    // Seed a batch of comparison pages between the most-tested hosts for SEO.
    for (let i = 0; i + 1 < Math.min(top.length, 24); i += 2)
      compareUrls.push(`/compare/${provSlug(top[i])}-vs-${provSlug(top[i + 1])}`);
    // Every checked domain gets its "who hosts X" report page indexed.
    const { results } = await env.DB.prepare(
      "SELECT domain FROM checks WHERE brand IS NOT NULL AND brand!='Unknown' GROUP BY domain ORDER BY MAX(checked_at) DESC LIMIT 1000").all();
    domainUrls = results.map(r => "/check/" + encodeURIComponent(r.domain));
  } catch {}
  const urls = [...staticUrls, ...providerUrls, ...compareUrls, ...domainUrls]
    .map(u => `<url><loc>${BASE}${u}</loc></url>`).join("");
  return new Response(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>`,
    { headers: { "content-type": "application/xml" } });
}

function favicon() {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <path d="M12 2 4 5v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V5l-8-3Z" fill="#f5b301"/>
  <circle cx="11.2" cy="10.2" r="2.4" fill="none" stroke="#0a0d14" stroke-width="1.7"/>
  <path d="m13.1 12.1 2 2.2" stroke="#0a0d14" stroke-width="1.7" stroke-linecap="round" fill="none"/></svg>`;
  return new Response(svg, { headers: { "content-type": "image/svg+xml", "cache-control": "max-age=86400" } });
}

function logoPng() {
  const bytes = Uint8Array.from(atob(LOGO_PNG_B64), c => c.charCodeAt(0));
  return new Response(bytes, { headers: { "content-type": "image/png", "cache-control": "max-age=604800" } });
}

function ogImage() {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <rect width="1200" height="630" fill="#0b1120"/>
  <text x="80" y="250" font-family="system-ui,Arial" font-size="86" font-weight="800" fill="#fff">Host<tspan fill="#3b82f6">Cop</tspan></text>
  <text x="82" y="330" font-family="system-ui,Arial" font-size="38" fill="#94a3b8">Who really hosts your site — measured, not reviewed.</text>
  <text x="82" y="400" font-family="system-ui,Arial" font-size="30" fill="#64748b">Real host behind CDNs · response time · uptime · SSL · neutral rankings</text>
  <rect x="80" y="470" width="220" height="64" rx="10" fill="#2563eb"/>
  <text x="190" y="512" font-family="system-ui,Arial" font-size="30" font-weight="700" fill="#fff" text-anchor="middle">hostcop.com</text>
</svg>`;
  return new Response(svg, { headers: { "content-type": "image/svg+xml", "cache-control": "max-age=86400" } });
}

function notFound() {
  return html(layout({ title: "Not found · HostCop", desc: "", path: "/404",
    body: `<div class="hero"><h1>404</h1><p class="lede">That page doesn't exist.</p>
           <a class="btn" href="/">Check a domain →</a></div>` }), 404);
}

// ========================================================================
// LAYOUT
// ========================================================================

function layout({ title, desc, path, body, home, jsonld }) {
  const canonical = BASE + (path === "/" ? "" : path);
  const d = desc || "HostCop — the neutral hosting watchdog. Detect the real host behind any domain and measure its performance.";
  const blocks = [
    { "@context": "https://schema.org", "@type": "Organization", name: "HostCop", url: BASE + "/",
      logo: `${BASE}/logo.png`, description: "Neutral web-hosting watchdog: detect the real host behind any domain, measure performance, and rank hosts by crowdsourced data." },
    ...(jsonld || []).filter(Boolean),
  ];
  const ld = blocks.map(b =>
    `<script type="application/ld+json">${JSON.stringify(b).replace(/</g, "\\u003c")}</script>`).join("");
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<script>try{document.documentElement.setAttribute('data-theme',localStorage.getItem('hc-theme')||'dark');}catch(e){document.documentElement.setAttribute('data-theme','dark');}</script>
<title>${esc(title)}</title>
<meta name="description" content="${esc(d)}">
<link rel="canonical" href="${esc(canonical)}">
<meta name="theme-color" content="#2563eb">
<meta property="og:type" content="website">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(d)}">
<meta property="og:url" content="${esc(canonical)}">
<meta property="og:image" content="${BASE}/og.svg">
<meta property="og:site_name" content="HostCop">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(d)}">
<meta name="twitter:image" content="${BASE}/og.svg">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap">
${ld}
<style>${CSS}</style>
</head><body>
<div id="overlay"><div class="spin"></div><p id="ovmsg"></p></div>
<header class="nav"><div class="nav-in">
  <a class="brand" href="/"><svg class="emblem" viewBox="0 0 24 24"><path class="s" d="M12 2 4 5v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V5l-8-3Z"/><path class="s2" d="M12 2 4 5v6c0 5 3.4 8 8 9V2Z"/><circle class="g" cx="11.2" cy="10.2" r="2.4"/><path class="g" d="m13.1 12.1 2 2.2" stroke-linecap="round"/></svg>Host<span>Cop</span></a>
  <nav>
    <span class="livepill"><span class="livedot"></span>LIVE</span>
    <a href="/tools">Tools</a>
    <a href="/hosts">Rankings</a>
    <a href="/monitor">Monitor</a>
    <a href="/pricing">Pricing</a>
    <a href="/about">About</a>
    <button class="themebtn" onclick="hcToggle()" aria-label="Toggle dark mode" title="Toggle theme">◐</button>
  </nav>
</div></header>
<main${home ? ' class="wide"' : ""}>${body}</main>
<footer>
  <div class="fcols">
    <div><b>HostCop</b><p class="muted">Neutral hosting watchdog. Measured data, never fake reviews. <b>No affiliate links.</b></p></div>
    <div><a href="/tools">Tools</a><a href="/hosts">Rankings</a><a href="/compare">Compare</a><a href="/monitor">Monitor</a><a href="/pricing">Pricing</a><a href="/bulk">Bulk check</a><a href="/api">API</a><a href="/guides">Guides</a></div>
    <div><a href="/methodology">Methodology</a><a href="/about">About</a><a href="/contact">Contact</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a></div>
  </div>
  <p class="muted small">© 2026 HostCop · Built on Cloudflare. Data is measured live and provided as-is.</p>
</footer>
<script>
(function(){
  window.hcToggle=function(){var el=document.documentElement;var n=el.getAttribute('data-theme')==='dark'?'light':'dark';el.setAttribute('data-theme',n);try{localStorage.setItem('hc-theme',n);}catch(e){}};
  var f=document.getElementById('checkform');
  if(f){f.addEventListener('submit',function(e){
    var raw=(f.domain.value||'').trim().toLowerCase().replace(/^https?:\\/\\//,'').replace(/\\/.*$/,'');
    if(!raw)return;
    e.preventDefault();
    var ov=document.getElementById('overlay');
    if(ov){ov.style.display='flex';
      var msgs=['Resolving DNS…','Detecting the real host…','Measuring response time…','Reading SSL certificate…'];
      var i=0,m=document.getElementById('ovmsg');
      if(m)m.textContent=msgs[0];
      setInterval(function(){i=(i+1)%msgs.length;if(m)m.textContent=msgs[i];},900);
    }
    location.assign('/check/'+encodeURIComponent(raw));
  });}
})();
</script>
</body></html>`;
}

const CSS = `
:root{--bg:#0a0d14;--surface:#111725;--surface2:#161d2e;--fg:#e9eef7;--muted:#93a1b8;--faint:#586885;--border:#1f2838;--line:#182031;--brand:#f5b301;--brand2:#ffcb3d;--brandfg:#0a0d14;--link:#7cc7ff;--up:#34d399;--down:#f87171;--warn:#fb923c;--tag:#1b2436;--tagfg:#ffce4a;--dot:rgba(255,255,255,.035);--glow:rgba(245,179,1,.14)}
[data-theme=light]{--bg:#f6f8fb;--surface:#ffffff;--surface2:#f1f4f9;--fg:#0d1526;--muted:#54637d;--faint:#8a99b3;--border:#e4e9f1;--line:#eef2f7;--brand:#d99400;--brand2:#f5b301;--brandfg:#231a00;--link:#2563eb;--up:#059669;--down:#dc2626;--warn:#ea580c;--tag:#fff7e6;--tagfg:#a16207;--dot:rgba(10,20,40,.05);--glow:rgba(245,179,1,.10)}
*{box-sizing:border-box}
html{color-scheme:light dark}
body{margin:0;font:16px/1.65 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--fg);background:radial-gradient(circle at 1px 1px,var(--dot) 1px,transparent 0) 0 0/22px 22px fixed,var(--bg)}
body::before{content:"";position:fixed;top:-18%;left:50%;transform:translateX(-50%);width:900px;height:520px;max-width:120vw;background:radial-gradient(ellipse at center,var(--glow),transparent 70%);pointer-events:none;z-index:0}
main,.nav,footer{position:relative;z-index:1}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
h1,h2,h3{font-family:'Space Grotesk',system-ui,sans-serif;letter-spacing:-.02em;font-weight:700}
h1{font-size:2.5rem;line-height:1.1;margin:.2em 0}h2{font-size:1.5rem;margin:1.7em 0 .6em}
.kicker{font-family:'JetBrains Mono',monospace;font-size:.7rem;letter-spacing:.22em;text-transform:uppercase;color:var(--brand);font-weight:600;margin-bottom:6px}
.mono,.stats b,.row b,.mrow,.copy,th,.pill,.tag,.livepill{font-family:'JetBrains Mono',monospace}
main{max-width:780px;margin:0 auto;padding:26px 20px 10px}
main.wide{max-width:980px}
.nav{position:sticky;top:0;z-index:20;backdrop-filter:blur(10px);background:color-mix(in srgb,var(--bg) 80%,transparent);border-bottom:1px solid var(--border)}
.nav-in{max-width:980px;margin:0 auto;padding:12px 20px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:9px;font-family:'Space Grotesk',sans-serif;font-weight:700;font-size:1.18rem;color:var(--fg);letter-spacing:-.01em}
.brand:hover{text-decoration:none}.brand span{color:var(--brand)}
.emblem{width:26px;height:26px;flex:none}
.emblem .s{fill:var(--brand)}.emblem .s2{fill:var(--brand);opacity:.7}.emblem .g{fill:none;stroke:var(--brandfg);stroke-width:1.7}
.nav nav{display:flex;align-items:center;gap:18px}
.nav nav a{color:var(--muted);font-size:.92rem;font-weight:500}
.nav nav a:hover{color:var(--fg);text-decoration:none}
.livepill{display:inline-flex;align-items:center;gap:6px;font-size:.64rem;letter-spacing:.14em;color:var(--up);border:1px solid var(--border);border-radius:999px;padding:3px 9px}
.livedot{width:7px;height:7px;border-radius:50%;background:var(--up);flex:none;animation:pulse 1.9s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(52,211,153,.55)}70%{box-shadow:0 0 0 7px rgba(52,211,153,0)}100%{box-shadow:0 0 0 0 rgba(52,211,153,0)}}
.themebtn{background:none;border:1px solid var(--border);border-radius:8px;color:var(--muted);width:34px;height:34px;cursor:pointer;font-size:16px}
.themebtn:hover{color:var(--fg);border-color:var(--brand)}
.hero{display:grid;grid-template-columns:1.15fr .85fr;gap:36px;align-items:center;padding:46px 0 28px}
.hero-copy h1{font-size:3rem}
.hl{color:var(--brand);position:relative;white-space:nowrap}
.hl::after{content:"";position:absolute;left:0;right:0;bottom:.06em;height:.16em;background:var(--brand);opacity:.28;border-radius:3px}
.lede{color:var(--muted);font-size:1.12rem;margin:16px 0 24px;max-width:36ch}
form{display:flex;gap:8px;max-width:470px}
input{flex:1;min-width:0;padding:14px 15px 14px 42px;border:1px solid var(--border);border-radius:12px;font:15px/1 'JetBrains Mono',monospace;color:var(--fg);background:var(--surface) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2393a1b8' stroke-width='2' stroke-linecap='round'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='m21 21-4.3-4.3'/%3E%3C/svg%3E") no-repeat 14px center}
input:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px var(--glow)}
button{padding:14px 20px;border:0;border-radius:12px;background:linear-gradient(180deg,var(--brand2),var(--brand));color:var(--brandfg);font-weight:700;cursor:pointer;font-size:15px;white-space:nowrap}
button:hover{filter:brightness(1.06)}
.ranklink{display:inline-block;margin-top:16px;color:var(--muted);font-size:.95rem}
.hero-visual{min-width:0}
.monitor{background:linear-gradient(180deg,var(--surface),var(--surface2));border:1px solid var(--border);border-radius:16px;padding:15px 18px;box-shadow:0 24px 60px -24px rgba(0,0,0,.6)}
.mhead{display:flex;align-items:center;gap:8px;font-family:'JetBrains Mono',monospace;font-size:.68rem;letter-spacing:.12em;color:var(--muted);text-transform:uppercase;padding-bottom:11px;border-bottom:1px solid var(--line);margin-bottom:4px}
.mrow{display:flex;justify-content:space-between;padding:8px 0;font-size:.9rem}
.mrow span{color:var(--faint)}.mrow b{color:var(--fg);font-weight:600}
section{margin:42px 0}
.steps{list-style:none;padding:0;margin:0;display:grid;gap:12px}
.steps li{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--brand);border-radius:12px;padding:15px 18px}
.steps b{display:block;font-family:'Space Grotesk',sans-serif;margin-bottom:2px}.steps span{color:var(--muted);font-size:.95rem}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.feat{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:15px}
.feat b{display:block;font-family:'Space Grotesk',sans-serif}.feat span{color:var(--muted);font-size:.9rem}
.why p{color:var(--fg)}
.card,.stats{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:20px;margin:16px 0}
.card{position:relative;overflow:hidden}
.card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--brand),transparent 55%)}
.demo .demo-head{font-family:'JetBrains Mono',monospace;font-weight:600;margin-bottom:6px}
.row{display:flex;justify-content:space-between;gap:12px;padding:11px 0;border-bottom:1px solid var(--line)}
.row:last-child{border:0}.row>span{color:var(--muted);font-size:.92rem}
.row b{font-weight:600}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;text-align:center}
.stats div b{display:block;font-size:1.7rem;color:var(--brand);font-weight:700}
.stats div span{color:var(--muted);font-size:.74rem;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);border-radius:14px;overflow:hidden;font-size:.94rem}
th,td{padding:11px 14px;text-align:left;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
th{color:var(--faint);font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;font-weight:600}
table tr:hover td{background:var(--surface2)}
.up{color:var(--up);font-weight:700}.down{color:var(--down);font-weight:700}.warn{color:var(--warn);font-weight:700}
.muted{color:var(--muted)}.small{font-size:.85rem}
.note{background:var(--tag);border:1px solid var(--border);border-left:3px solid var(--brand);color:var(--fg);border-radius:10px;padding:11px 14px;font-size:.94rem}
.tag{display:inline-block;background:var(--tag);color:var(--tagfg);font-size:.62rem;font-weight:700;padding:2px 7px;border-radius:5px;letter-spacing:.05em;vertical-align:middle}
.back{display:inline-block;margin-bottom:6px;color:var(--muted)}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}
.btn{background:linear-gradient(180deg,var(--brand2),var(--brand));color:var(--brandfg);padding:12px 18px;border-radius:12px;font-weight:700}
.btn:hover{text-decoration:none;filter:brightness(1.06)}
.btn.ghost{background:transparent;color:var(--fg);border:1px solid var(--border)}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}
.pill{padding:7px 14px;border:1px solid var(--border);border-radius:999px;color:var(--muted);font-size:.8rem}
.pill.on{background:var(--brand);color:var(--brandfg);border-color:var(--brand);font-weight:700}
.pill:hover{text-decoration:none;border-color:var(--brand)}
.share{margin:18px 0;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:6px 16px}
.share summary{cursor:pointer;padding:10px 0;font-weight:600}
.share label{display:block;color:var(--muted);font-size:.82rem;margin:10px 0 4px}
.copy{width:100%;padding:9px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--fg);font-size:.85rem}
.badgeprev{padding:6px 0}
.guidelist{list-style:none;padding:0;display:grid;gap:12px}
.guidelist li{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:15px 18px}
.guidelist b{display:block;font-family:'Space Grotesk',sans-serif;font-size:1.05rem}.guidelist span{display:block;margin-top:3px}
.prose p,.prose li{color:var(--fg)}.prose h2{color:var(--fg)}
.prose ul{padding-left:20px}.prose li{margin:6px 0}
.cta{margin-top:26px}
.contact{font-family:'JetBrains Mono',monospace;font-size:1.25rem;font-weight:700}
footer{max-width:980px;margin:56px auto 0;padding:30px 20px;border-top:1px solid var(--border)}
.fcols{display:grid;grid-template-columns:2fr 1fr 1fr;gap:20px}
.fcols a{display:block;color:var(--muted);font-size:.92rem;padding:2px 0}
.fcols>div>b{font-family:'Space Grotesk',sans-serif;font-weight:700}
.trustbadge{display:inline-block;background:var(--tag);color:var(--tagfg);border:1px solid var(--border);border-radius:999px;padding:7px 14px;font-family:'JetBrains Mono',monospace;font-size:.76rem;margin:2px 0 12px}
.trustbadge.center{display:block;width:max-content;max-width:100%;margin:0 auto 10px;text-align:center}
.statline{text-align:center;color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:.85rem;margin:2px 0 10px}
.statline b{color:var(--brand)}
.verdict{font-size:1.16rem;line-height:1.5;padding:15px 18px;border-radius:14px;border:1px solid var(--border);border-left:4px solid var(--brand);background:var(--surface);margin:8px 0 16px}
.verdict.down{border-left-color:var(--down)}.verdict.warn{border-left-color:var(--warn)}
.verdict.note{border-left-color:var(--warn)}.verdict.ok{border-left-color:var(--up)}
.verdict b{font-weight:700}
textarea{width:100%;padding:12px 14px;border:1px solid var(--border);border-radius:12px;background:var(--surface);color:var(--fg);font-family:'JetBrains Mono',monospace;font-size:.9rem;resize:vertical}
textarea:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px var(--glow)}
select{padding:11px 12px;border:1px solid var(--border);border-radius:10px;background:var(--surface);color:var(--fg);font-size:.95rem;max-width:46%}
.compareform{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:16px 0}
.monitorform{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0;max-width:560px}
.monitorform input{flex:1;min-width:180px}
.toolform{display:flex;gap:8px;margin:16px 0;max-width:480px}
.toolform input{flex:1;min-width:0}
.toolgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:18px 0}
.toolcard{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:16px 18px;color:var(--fg)}
.toolcard:hover{text-decoration:none;border-color:var(--brand)}
.toolcard b{display:block;font-family:'Space Grotesk',sans-serif;font-size:1.05rem;margin-bottom:3px}
.toolcard span{color:var(--muted);font-size:.9rem}
@media(max-width:560px){.toolgrid{grid-template-columns:1fr}}
.cmp{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:16px 0}
.cmp .col{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:18px}
.cmp .col h3{margin:.1em 0 .6em;font-size:1.05rem;text-align:center}
.cmp .m{display:flex;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--line);font-family:'JetBrains Mono',monospace;font-size:.9rem}
.cmp .m:last-child{border:0}.cmp .m span{color:var(--muted)}
.win{color:var(--up)}
pre.code{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--brand);border-radius:10px;padding:14px;overflow-x:auto;font-family:'JetBrains Mono',monospace;font-size:.82rem;line-height:1.5;color:var(--fg)}
#overlay{display:none;position:fixed;inset:0;background:var(--bg);z-index:60;flex-direction:column;align-items:center;justify-content:center;gap:16px}
#overlay p{color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:.9rem}
.spin{width:42px;height:42px;border:3px solid var(--border);border-top-color:var(--brand);border-radius:50%;animation:sp 1s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
@media(max-width:820px){.hero{grid-template-columns:1fr;gap:24px}.hero-visual{max-width:440px}.hero-copy h1{font-size:2.5rem}}
@media(max-width:560px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}.fcols{grid-template-columns:1fr 1fr}.hero-copy h1{font-size:2.1rem}h1{font-size:2rem}.nav nav{gap:13px}.livepill{display:none}}
`;

// ========================================================================
// UTILS
// ========================================================================

const html = (b, status = 200) =>
  new Response(b, { status, headers: { "content-type": "text/html;charset=utf-8" } });

const json = (o, status = 200) =>
  new Response(JSON.stringify(o, null, 2), { status, headers: {
    "content-type": "application/json;charset=utf-8",
    "access-control-allow-origin": "*",
  } });

function cleanDomain(d) {
  d = (d || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d) ? d : "";
}

const cleanEmail = e => {
  e = (e || "").trim().toLowerCase();
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) ? e : "";
};

function timeAgo(ms) {
  if (!ms) return "—";
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

// ISO country code -> flag emoji
function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1f1e6 + c.charCodeAt(0) - 65));
}

const esc = s => String(s ?? "").replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
