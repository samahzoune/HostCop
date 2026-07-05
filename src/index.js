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

  const ip = await resolveA(domain);
  const asnInfo = ip ? await ipToAsn(ip) : null;
  const provider = asnInfo ? asnInfo.name : "Unknown";
  const country = asnInfo?.country ?? null;
  const [perf, sslExpiry] = await Promise.all([measure(domain), getSslExpiry(domain)]);
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO checks (domain, ip, asn, provider, country, response_ms, http_status, up, ssl_expiry, region, checked_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(domain, ip, asnInfo?.asn ?? null, provider, country,
         perf.ms, perf.status, perf.up ? 1 : 0, sslExpiry, region, now).run();

  await env.DB.prepare(
    `INSERT INTO domains (domain, provider, added_at, last_checked)
     VALUES (?,?,?,?)
     ON CONFLICT(domain) DO UPDATE SET provider=excluded.provider, last_checked=excluded.last_checked`
  ).bind(domain, provider, now, now).run();

  return { domain, ip, provider, country, asn: asnInfo?.asn ?? null, sslExpiry, ...perf };
}

// Resolve A record via Cloudflare DNS-over-HTTPS (no key needed)
async function resolveA(domain) {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
    { headers: { accept: "application/dns-json" } });
  const j = await r.json();
  return (j.Answer || []).find(a => a.type === 1)?.data ?? null;
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
    return parseNotAfter(der);
  } catch {
    try { await socket?.close(); } catch {}
    return null;
  }
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

async function measure(domain) {
  const t0 = Date.now();
  let status = 0, up = false;
  try {
    const r = await fetch(`https://${domain}/`, { redirect: "manual", cf: { cacheTtl: 0 } });
    status = r.status; up = true;
  } catch (_) {}
  return { ms: Date.now() - t0, status, up };
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
  return json({
    domain: res.domain, ip: res.ip, asn: res.asn ? "AS" + res.asn : null,
    provider: res.provider, country: res.country, cdn: isCdn(res.provider),
    up: res.up, response_ms: res.ms, http_status: res.status,
    ssl_expiry: res.sslExpiry ? new Date(res.sslExpiry).toISOString() : null,
  });
}

async function handleCheck(domain, request, env) {
  if (!domain) return html(layout({
    title: "Check a domain · HostCop", desc: "Look up who really hosts any website.",
    path: "/check", body: heroSection() }), 400);

  const res = await runCheck(domain, request.cf?.colo || "edge", env);
  if (!res) return html(layout({ title: `HostCop · ${domain}`, desc: "", path: "/check/" + domain,
    body: `<a class="back" href="/">← check another</a><h1>${esc(domain)}</h1>
           <p class="muted">Couldn't read that domain — it may not resolve or may be offline.</p>` }));

  const badge = res.up
    ? `<span class="up">UP</span> · ${res.ms} ms · HTTP ${res.status}`
    : `<span class="down">DOWN</span> · no response`;

  let ssl = `<b>—</b>`;
  if (res.sslExpiry) {
    const days = Math.round((res.sslExpiry - Date.now()) / 86400000);
    const date = new Date(res.sslExpiry).toISOString().slice(0, 10);
    const cls = days < 0 ? "down" : days <= 21 ? "warn" : "up";
    ssl = `<b><span class="${cls}">${days < 0 ? "expired" : days + " days left"}</span> · ${date}</b>`;
  }

  const cdnNote = isCdn(res.provider)
    ? `<p class="note">⚡ This domain sits behind <b>${esc(res.provider)}</b>, a CDN / edge network — the real origin server is masked. What you see below is the edge that answers for it.</p>`
    : "";

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
    ${cdnNote}
    <div class="card">
      <div class="row"><span>Hosted by</span>
        <a href="/host/${encodeURIComponent(res.provider)}"><b>${esc(res.provider)}</b></a></div>
      <div class="row"><span>Type</span><b>${isCdn(res.provider) ? "CDN / edge network" : "Origin host"}</b></div>
      <div class="row"><span>IP address</span><b>${esc(res.ip || "—")}</b></div>
      <div class="row"><span>ASN</span><b>${res.asn ? "AS" + esc(res.asn) : "—"}</b></div>
      <div class="row"><span>Location (approx)</span><b>${loc}</b></div>
      <div class="row"><span>Status</span><b>${badge}</b></div>
      <div class="row"><span>SSL certificate</span>${ssl}</div>
    </div>

    <div class="actions">
      <a class="btn" href="/host/${encodeURIComponent(res.provider)}">See ${esc(res.provider)}'s ranking →</a>
      <a class="btn ghost" href="/hosts">Compare all hosts</a>
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
     FROM checks WHERE provider = ?`
  ).bind(provider).all();
  const s = results[0];
  if (!s || !s.checks)
    return html(layout({ title: `${provider} · HostCop`, desc: "", path: "/host/" + provider,
      body: `<a class="back" href="/hosts">← all hosts</a><h1>${esc(provider)}</h1>
             <p class="muted">No measured data yet for this host. <a href="/">Check a domain</a> to add some.</p>` }));

  const recent = await env.DB.prepare(
    `SELECT domain, MAX(checked_at) t, ROUND(AVG(response_ms)) ms,
            ROUND(100.0*SUM(up)/COUNT(*)) up
     FROM checks WHERE provider = ? GROUP BY domain ORDER BY t DESC LIMIT 12`
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
    `SELECT provider, COUNT(DISTINCT domain) sites,
            ROUND(AVG(response_ms)) avg_ms,
            ROUND(100.0*SUM(up)/COUNT(*),1) uptime,
            MAX(checked_at) last_seen
     FROM checks WHERE provider != 'Unknown'
     GROUP BY provider HAVING COUNT(*) >= 3
     ORDER BY ${order} LIMIT 100`
  ).all();

  const rows = results.map((r, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><a href="/host/${encodeURIComponent(r.provider)}">${esc(r.provider)}</a>${isCdn(r.provider) ? ' <span class="tag">CDN</span>' : ""}</td>
      <td>${r.uptime}%</td>
      <td>${r.avg_ms} ms</td>
      <td>${r.sites}</td>
      <td class="muted">${timeAgo(r.last_seen)}</td>
    </tr>`).join("") || `<tr><td colspan="6">No hosts ranked yet — <a href="/">check a domain</a> to seed the data.</td></tr>`;

  const tab = (key, label) => `<a class="pill ${sort === key ? "on" : ""}" href="/hosts?sort=${key}">${label}</a>`;

  return html(layout({
    title: "Web host rankings by measured uptime & speed · HostCop",
    desc: "Neutral hosting rankings built from live measurements — real uptime and response times crowdsourced from every domain checked. No reviews, no affiliate bias.",
    path: "/hosts",
    body: `
    <h1>Host rankings</h1>
    <p class="muted">Ranked from live measured data — real uptime and response time, crowdsourced from every domain checked. Minimum 3 checks to appear. No reviews, no paid placement.</p>
    <div class="pills">${tab("uptime", "Most reliable")}${tab("speed", "Fastest")}${tab("tested", "Most tested")}</div>
    <table>
      <tr><th>#</th><th>Host</th><th>Uptime</th><th>Avg</th><th>Sites</th><th>Updated</th></tr>
      ${rows}
    </table>
    <p class="muted">The numbers here <i>are</i> the ranking — nothing hidden. See <a href="/methodology">methodology</a>.</p>
  ` }));
}

async function handleBadge(domain, env) {
  domain = cleanDomain(domain);
  let provider = "not checked";
  if (domain) {
    const row = await env.DB.prepare(
      "SELECT provider FROM checks WHERE domain = ? ORDER BY checked_at DESC LIMIT 1"
    ).bind(domain).first();
    if (row?.provider) provider = row.provider;
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

// ========================================================================
// ROUTES: content pages
// ========================================================================

function handleHome(env) {
  const body = `
    ${heroSection()}

    <section class="how">
      <h2>How it works</h2>
      <ol class="steps">
        <li><b>1 · Enter a domain</b><span>Any website — yours or a competitor's.</span></li>
        <li><b>2 · We detect the real host</b><span>We resolve the IP and trace its network (ASN) to see who's actually behind the CDN or reseller.</span></li>
        <li><b>3 · We measure it live</b><span>Response time, up/down and SSL expiry — right now, from the edge, and saved to the public record.</span></li>
      </ol>
    </section>

    <section>
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
    <div class="hero">
      <h1>Who really hosts your site?</h1>
      <p class="lede">HostCop detects the real host behind any domain — even through CDNs and resellers — and measures how it actually performs. Neutral data, no fake reviews.</p>
      <form id="checkform" action="/check" method="get">
        <input name="domain" placeholder="yourdomain.com" autofocus autocomplete="off" spellcheck="false">
        <button>Check host</button>
      </form>
      <a class="ranklink" href="/hosts">Or browse the live host rankings →</a>
    </div>`;
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
  const staticUrls = ["/", "/hosts", "/guides", "/methodology", "/about", "/privacy", "/terms", "/contact",
    ...Object.keys(GUIDES).map(s => "/guides/" + s)];
  let providerUrls = [];
  try {
    const { results } = await env.DB.prepare(
      "SELECT provider, COUNT(*) c FROM checks WHERE provider!='Unknown' GROUP BY provider HAVING c>=3 LIMIT 200"
    ).all();
    providerUrls = results.map(r => "/host/" + encodeURIComponent(r.provider));
  } catch {}
  const urls = [...staticUrls, ...providerUrls]
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
<script>try{var t=localStorage.getItem('hc-theme');if(t)document.documentElement.setAttribute('data-theme',t);}catch(e){}</script>
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
<style>${CSS}</style>
</head><body>
<div id="overlay"><div class="spin"></div><p id="ovmsg">Resolving DNS…</p></div>
<header class="nav">
  <a class="brand" href="/">🛡 Host<span>Cop</span></a>
  <nav>
    <a href="/hosts">Rankings</a>
    <a href="/guides">Guides</a>
    <a href="/methodology">Methodology</a>
    <a href="/about">About</a>
    <button class="themebtn" onclick="hcToggle()" aria-label="Toggle dark mode" title="Toggle theme">◐</button>
  </nav>
</header>
<main${home ? ' class="wide"' : ""}>${body}</main>
<footer>
  <div class="fcols">
    <div><b>HostCop</b><p class="muted">Neutral hosting watchdog. Measured data, never fake reviews. <b>No affiliate links.</b></p></div>
    <div><a href="/hosts">Rankings</a><a href="/guides">Guides</a><a href="/methodology">Methodology</a></div>
    <div><a href="/about">About</a><a href="/contact">Contact</a><a href="/privacy">Privacy</a><a href="/terms">Terms</a></div>
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
      setInterval(function(){i=(i+1)%msgs.length;if(m)m.textContent=msgs[i];},900);
    }
    location.assign('/check/'+encodeURIComponent(raw));
  });}
})();
</script>
</body></html>`;
}

const CSS = `
:root{--bg:#f8fafc;--fg:#0f172a;--muted:#64748b;--faint:#94a3b8;--card:#fff;--border:#e2e8f0;--line:#f1f5f9;--brand:#2563eb;--brandfg:#fff;--up:#16a34a;--down:#dc2626;--warn:#d97706;--tag:#eef2ff;--tagfg:#4338ca}
[data-theme=dark]{--bg:#0b1120;--fg:#e2e8f0;--muted:#94a3b8;--faint:#64748b;--card:#111827;--border:#1f2937;--line:#1f2937;--brand:#3b82f6;--brandfg:#fff;--tag:#1e293b;--tagfg:#93c5fd}
*{box-sizing:border-box}
html{color-scheme:light dark}
body{font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;color:var(--fg);background:var(--bg)}
a{color:var(--brand);text-decoration:none}a:hover{text-decoration:underline}
h1{font-size:2rem;margin:.3em 0}h2{font-size:1.3rem;margin:1.6em 0 .5em}
main{max-width:720px;margin:0 auto;padding:28px 20px 10px}
main.wide{max-width:860px}
.nav{max-width:860px;margin:0 auto;padding:16px 20px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.brand{font-weight:800;font-size:1.2rem;color:var(--fg)}.brand span{color:var(--brand)}.brand:hover{text-decoration:none}
.nav nav{display:flex;align-items:center;gap:16px}
.nav nav a{color:var(--muted);font-size:.95rem}
.themebtn{background:none;border:1px solid var(--border);border-radius:8px;color:var(--muted);width:34px;height:34px;cursor:pointer;font-size:16px}
.hero{text-align:center;padding:36px 0 20px}
.hero h1{font-size:2.5rem;line-height:1.15}
.lede{color:var(--muted);font-size:1.1rem;max-width:520px;margin:14px auto 26px}
form{display:flex;gap:8px;max-width:440px;margin:0 auto}
input{flex:1;padding:13px 15px;border:1px solid var(--border);border-radius:10px;font-size:16px;background:var(--card);color:var(--fg)}
button{padding:13px 20px;border:0;border-radius:10px;background:var(--brand);color:var(--brandfg);font-weight:600;cursor:pointer;font-size:16px}
.ranklink{display:inline-block;margin-top:18px;color:var(--muted)}
section{margin:34px 0}
.steps{list-style:none;padding:0;display:grid;gap:14px}
.steps li{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px}
.steps b{display:block;color:var(--brand)}.steps span{color:var(--muted)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.feat{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px}
.feat b{display:block}.feat span{color:var(--muted);font-size:.92rem}
.why p{color:var(--fg)}
.card,.stats{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;margin:16px 0}
.demo .demo-head{font-weight:700;margin-bottom:6px}
.row{display:flex;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid var(--line)}
.row:last-child{border:0}.row span{color:var(--muted)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;text-align:center}
.stats div b{display:block;font-size:1.5rem;color:var(--brand)}.stats div span{color:var(--muted);font-size:.82rem}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:14px;overflow:hidden;font-size:.95rem}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
th{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.03em}
.up{color:var(--up);font-weight:700}.down{color:var(--down);font-weight:700}.warn{color:var(--warn);font-weight:700}
.muted{color:var(--muted)}.small{font-size:.85rem}
.note{background:var(--tag);border:1px solid var(--border);color:var(--fg);border-radius:10px;padding:10px 14px;font-size:.95rem}
.tag{background:var(--tag);color:var(--tagfg);font-size:.68rem;font-weight:700;padding:2px 7px;border-radius:6px;vertical-align:middle}
.back{display:inline-block;margin-bottom:6px;color:var(--muted)}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}
.btn{background:var(--brand);color:var(--brandfg);padding:11px 16px;border-radius:10px;font-weight:600}
.btn:hover{text-decoration:none;opacity:.92}
.btn.ghost{background:transparent;color:var(--brand);border:1px solid var(--border)}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}
.pill{padding:7px 14px;border:1px solid var(--border);border-radius:999px;color:var(--muted);font-size:.9rem}
.pill.on{background:var(--brand);color:var(--brandfg);border-color:var(--brand)}
.share{margin:18px 0;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:6px 16px}
.share summary{cursor:pointer;padding:10px 0;font-weight:600}
.share label{display:block;color:var(--muted);font-size:.82rem;margin:10px 0 4px}
.copy{width:100%;padding:9px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--fg);font-family:ui-monospace,monospace;font-size:.85rem}
.badgeprev{padding:6px 0}
.guidelist{list-style:none;padding:0;display:grid;gap:12px}
.guidelist li{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px}
.guidelist b{display:block;font-size:1.05rem}.guidelist span{display:block;margin-top:3px}
.prose p,.prose li{color:var(--fg)}.prose h2{color:var(--fg)}
.prose ul{padding-left:20px}.prose li{margin:6px 0}
.cta{margin-top:26px}
.contact{font-size:1.3rem;font-weight:700}
footer{max-width:860px;margin:40px auto 0;padding:26px 20px;border-top:1px solid var(--border)}
.fcols{display:grid;grid-template-columns:2fr 1fr 1fr;gap:20px}
.fcols a{display:block;color:var(--muted);font-size:.92rem;padding:2px 0}
.fcols>div>b{font-weight:800}
#overlay{display:none;position:fixed;inset:0;background:var(--bg);z-index:60;flex-direction:column;align-items:center;justify-content:center;gap:16px}
#overlay p{color:var(--muted)}
.spin{width:42px;height:42px;border:4px solid var(--border);border-top-color:var(--brand);border-radius:50%;animation:sp 1s linear infinite}
@keyframes sp{to{transform:rotate(360deg)}}
@media(max-width:560px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}.fcols{grid-template-columns:1fr 1fr}.hero h1{font-size:2rem}}
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
