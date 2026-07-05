// HostCop — neutral hosting watchdog. Detect who really hosts a domain (behind
// CDNs/resellers), measure live performance, read SSL expiry, and rank hosts by
// crowdsourced real data. Stack: Cloudflare Worker + D1. No API keys, no paid APIs.

import { connect } from "cloudflare:sockets";

const BASE = "https://hostcop.com";

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

  // Cron: re-ping tracked domains so rankings stay live.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runMonitors(env));                 // uptime/SSL email alerts
    const { results } = await env.DB.prepare(
      "SELECT domain FROM domains ORDER BY last_checked ASC LIMIT 50"
    ).all();
    for (const row of results) ctx.waitUntil(runCheck(row.domain, "cron", env));
  },
};

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
  const extensions = concatBytes(sni, groups, points, sigExt);

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
    <div style="font-size:20px;font-weight:800;margin-bottom:14px">🛡 Host<span style="color:#f5b301">Cop</span></div>
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
async function runMonitors(env) {
  const { results: doms } = await env.DB.prepare(
    "SELECT DISTINCT domain FROM monitors WHERE verified=1").all();
  for (const { domain } of doms) {
    let res = await runCheck(domain, "monitor", env);
    if (!res) continue;
    let isUp = res.noDns ? false : !!res.up;
    if (!isUp) {                                   // confirm down with a 2nd check (single-region safety)
      const res2 = await runCheck(domain, "monitor", env);
      if (res2) { res = res2; isUp = !res2.noDns && !!res2.up; }
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
     <p>Response time today is measured from one region, so it reflects performance to a well-connected network rather than every corner of the world (multi-region measurement is on the roadmap). ASN location is the network's registered country, which is an approximation of physical server location. And behind a CDN, we measure the CDN edge — not the hidden origin. We'd rather tell you these limits than pretend the data is perfect.</p>`);
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
  return contentPage(g.title, "/guides/" + slug, g.desc,
    `<a class="back" href="/guides">← all guides</a>
     <h1>${esc(g.title)}</h1>
     <p class="muted">Guide · updated ${g.date}</p>
     ${g.body}
     <p class="cta"><a class="btn" href="/">Check a domain now →</a></p>`);
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
function contentPage(title, path, desc, inner) {
  return html(layout({ title: `${title} · HostCop`, desc, path, body: `<article class="prose">${inner}</article>` }));
}

// ========================================================================
// STATIC ASSETS
// ========================================================================

function robots() {
  return new Response(`User-agent: *\nAllow: /\nSitemap: ${BASE}/sitemap.xml\n`,
    { headers: { "content-type": "text/plain" } });
}

async function sitemap(env) {
  const staticUrls = ["/", "/hosts", "/compare", "/monitor", "/bulk", "/api", "/guides", "/methodology", "/about", "/privacy", "/terms", "/contact",
    ...Object.keys(GUIDES).map(s => "/guides/" + s)];
  let providerUrls = [], compareUrls = [];
  try {
    const top = await topProviders(env, 200);
    providerUrls = top.map(p => "/host/" + encodeURIComponent(p));
    // Seed a batch of comparison pages between the most-tested hosts for SEO.
    for (let i = 0; i + 1 < Math.min(top.length, 24); i += 2)
      compareUrls.push(`/compare/${provSlug(top[i])}-vs-${provSlug(top[i + 1])}`);
  } catch {}
  const urls = [...staticUrls, ...providerUrls, ...compareUrls]
    .map(u => `<url><loc>${BASE}${u}</loc></url>`).join("");
  return new Response(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>`,
    { headers: { "content-type": "application/xml" } });
}

function favicon() {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <path d="M32 3 6 14v18c0 16 11 25 26 29 15-4 26-13 26-29V14L32 3Z" fill="#2563eb"/>
  <path d="M32 3 6 14v18c0 16 11 25 26 29V3Z" fill="#1d4ed8"/>
  <text x="32" y="42" font-family="system-ui,Arial" font-size="34" font-weight="800"
        fill="#fff" text-anchor="middle">H</text></svg>`;
  return new Response(svg, { headers: { "content-type": "image/svg+xml", "cache-control": "max-age=86400" } });
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

function layout({ title, desc, path, body, home }) {
  const canonical = BASE + (path === "/" ? "" : path);
  const d = desc || "HostCop — the neutral hosting watchdog. Detect the real host behind any domain and measure its performance.";
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
<style>${CSS}</style>
</head><body>
<div id="overlay"><div class="spin"></div><p id="ovmsg"></p></div>
<header class="nav"><div class="nav-in">
  <a class="brand" href="/"><svg class="emblem" viewBox="0 0 24 24"><path class="s" d="M12 2 4 5v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V5l-8-3Z"/><path class="s2" d="M12 2 4 5v6c0 5 3.4 8 8 9V2Z"/><circle class="g" cx="11.2" cy="10.2" r="2.4"/><path class="g" d="m13.1 12.1 2 2.2" stroke-linecap="round"/></svg>Host<span>Cop</span></a>
  <nav>
    <span class="livepill"><span class="livedot"></span>LIVE</span>
    <a href="/hosts">Rankings</a>
    <a href="/guides">Guides</a>
    <a href="/methodology">Methodology</a>
    <a href="/about">About</a>
    <button class="themebtn" onclick="hcToggle()" aria-label="Toggle dark mode" title="Toggle theme">◐</button>
  </nav>
</div></header>
<main${home ? ' class="wide"' : ""}>${body}</main>
<footer>
  <div class="fcols">
    <div><b>HostCop</b><p class="muted">Neutral hosting watchdog. Measured data, never fake reviews. <b>No affiliate links.</b></p></div>
    <div><a href="/hosts">Rankings</a><a href="/compare">Compare</a><a href="/monitor">Monitor</a><a href="/bulk">Bulk check</a><a href="/api">API</a><a href="/guides">Guides</a></div>
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
