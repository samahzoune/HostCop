// HostCop — neutral hosting watchdog. Detect who hosts a domain + measure it live.
// Stack: Cloudflare Worker + D1. No API keys, no paid services.

import { connect } from "cloudflare:sockets";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    try {
      if (p === "/")               return html(homePage());
      if (p === "/check")          return handleCheck(url, request, env);
      if (p === "/hosts")          return handleLeaderboard(env);
      if (p.startsWith("/host/"))  return handleProvider(decodeURIComponent(p.slice(6)), env);
      return html(shell("Not found", "<p>Nothing here.</p>"), 404);
    } catch (e) {
      return html(shell("Error", `<p>${esc(e.message)}</p>`), 500);
    }
  },

  // Cron: re-ping everything we're tracking so the database stays fresh.
  async scheduled(event, env, ctx) {
    const { results } = await env.DB.prepare(
      "SELECT domain FROM domains ORDER BY last_checked ASC LIMIT 50"
    ).all();
    for (const row of results) {
      ctx.waitUntil(runCheck(row.domain, "cron", env));
    }
  },
};

// ---- core: detect + measure + store -------------------------------------

async function runCheck(domain, region, env) {
  domain = cleanDomain(domain);
  if (!domain) return null;

  const ip = await resolveA(domain);
  const asnInfo = ip ? await ipToAsn(ip) : null;
  const provider = asnInfo ? asnInfo.name : "Unknown";
  const [perf, sslExpiry] = await Promise.all([measure(domain), getSslExpiry(domain)]);
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO checks (domain, ip, asn, provider, response_ms, http_status, up, ssl_expiry, region, checked_at)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(domain, ip, asnInfo?.asn ?? null, provider,
         perf.ms, perf.status, perf.up ? 1 : 0, sslExpiry, region, now).run();

  await env.DB.prepare(
    `INSERT INTO domains (domain, provider, added_at, last_checked)
     VALUES (?,?,?,?)
     ON CONFLICT(domain) DO UPDATE SET provider=excluded.provider, last_checked=excluded.last_checked`
  ).bind(domain, provider, now, now).run();

  return { domain, ip, provider, asn: asnInfo?.asn ?? null, sslExpiry, ...perf };
}

// Resolve A record via Cloudflare DNS-over-HTTPS (no key needed)
async function resolveA(domain) {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
    { headers: { accept: "application/dns-json" } });
  const j = await r.json();
  return (j.Answer || []).find(a => a.type === 1)?.data ?? null;
}

// IP -> ASN + org name via Team Cymru's free DNS service (over DoH)
async function ipToAsn(ip) {
  const rev = ip.split(".").reverse().join(".");
  const t1 = await dohTxt(`${rev}.origin.asn.cymru.com`);
  if (!t1) return null;
  const asn = t1.split("|")[0].trim();              // "13335 | 1.1.1.0/24 | US | ..."
  const t2 = await dohTxt(`AS${asn}.asn.cymru.com`); // "13335 | US | arin | ... | CLOUDFLARENET, US"
  const name = t2 ? t2.split("|").pop().trim().replace(/,\s*[A-Z]{2}$/, "") : `AS${asn}`;
  return { asn, name };
}

async function dohTxt(name) {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${name}&type=TXT`,
    { headers: { accept: "application/dns-json" } });
  const j = await r.json();
  return (j.Answer || []).find(a => a.type === 16)?.data?.replace(/"/g, "") ?? null;
}

// SSL cert expiry. fetch() won't give us the cert, so we open a raw TCP socket,
// send a hand-built TLS 1.2 ClientHello, and read notAfter out of the handshake.
// Returns epoch ms, or null if we couldn't read it.
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

// Build a minimal TLS 1.2 ClientHello record with SNI. We deliberately omit the
// supported_versions extension so a TLS 1.3 server falls back to 1.2 and sends
// its Certificate message in the clear (in 1.3 it would be encrypted).
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
    u16(0x0303), random, Uint8Array.of(0),           // version, random, no session id
    u16(ciphers.length * 2), ...ciphers.map(u16),
    Uint8Array.of(1, 0x00),                           // compression: null
    u16(extensions.length), extensions);
  const hs = concatBytes(Uint8Array.of(1), u24(body.length), body);
  return concatBytes(Uint8Array.of(22), u16(0x0301), u16(hs.length), hs);
}

// Scan accumulated TCP bytes: reassemble handshake records, find Certificate (11),
// return the leaf cert DER. null if incomplete, "ALERT" if the server bailed.
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
    if (H[q] === 11) {                                 // Certificate message
      const b = H.subarray(q + 4);
      const certLen = (b[3] << 16) | (b[4] << 8) | b[5];
      return b.subarray(6, 6 + certLen);               // first = leaf cert
    }
    q += 4 + mlen;
  }
  return null;
}

// Walk the X.509 DER to Validity.notAfter. Cert = SEQUENCE { tbs = SEQUENCE {
// [0] version?, serial, sigAlg, issuer, validity{ notBefore, notAfter }, ... } }
function parseNotAfter(der) {
  const cert = tlv(der, 0);
  const tbs = tlv(der, cert.headerEnd);
  const kids = [];
  let p = tbs.headerEnd;
  while (p < tbs.valueEnd) { const c = tlv(der, p); kids.push(c); p = c.valueEnd; }
  const validity = kids[kids[0].tag === 0xa0 ? 4 : 3];  // skip optional version
  const notBefore = tlv(der, validity.headerEnd);
  const notAfter = tlv(der, notBefore.valueEnd);
  const s = new TextDecoder().decode(der.subarray(notAfter.headerEnd, notAfter.valueEnd));
  let i = 0, y;
  if (notAfter.tag === 0x17) { y = +s.slice(0, 2); y += y < 50 ? 2000 : 1900; i = 2; }
  else { y = +s.slice(0, 4); i = 4; }                   // GeneralizedTime
  return Date.UTC(y, +s.slice(i, i + 2) - 1, +s.slice(i + 2, i + 4),
                  +s.slice(i + 4, i + 6), +s.slice(i + 6, i + 8), +s.slice(i + 8, i + 10) || 0);
}

// byte + ASN.1 helpers
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

// Measure response time + up/down
async function measure(domain) {
  const t0 = Date.now();
  let status = 0, up = false;
  try {
    const r = await fetch(`https://${domain}/`, { redirect: "manual", cf: { cacheTtl: 0 } });
    status = r.status; up = true;
  } catch (_) { /* down / handshake failed */ }
  return { ms: Date.now() - t0, status, up };
}

// ---- routes -------------------------------------------------------------

async function handleCheck(url, request, env) {
  const domain = cleanDomain(url.searchParams.get("domain") || "");
  if (!domain) return html(shell("HostCop", homePage()), 400);
  const region = request.cf?.colo || "edge";
  const res = await runCheck(domain, region, env);
  if (!res) return html(shell("HostCop", `<p>Couldn't read <b>${esc(domain)}</b>.</p>`));

  const badge = res.up
    ? `<span class="up">UP</span> · ${res.ms} ms · HTTP ${res.status}`
    : `<span class="down">DOWN</span> · no response`;

  let ssl = `<b>—</b>`;
  if (res.sslExpiry) {
    const days = Math.round((res.sslExpiry - Date.now()) / 86400000);
    const date = new Date(res.sslExpiry).toISOString().slice(0, 10);
    const cls = days < 0 ? "down" : days <= 21 ? "warn" : "up";
    const label = days < 0 ? "expired" : `${days} days left`;
    ssl = `<b><span class="${cls}">${label}</span> · ${date}</b>`;
  }

  return html(shell(`HostCop · ${domain}`, `
    <a class="back" href="/">← check another</a>
    <h1>${esc(domain)}</h1>
    <div class="card">
      <div class="row"><span>Hosted by</span>
        <a href="/host/${encodeURIComponent(res.provider)}"><b>${esc(res.provider)}</b></a></div>
      <div class="row"><span>IP</span><b>${esc(res.ip || "—")}</b></div>
      <div class="row"><span>ASN</span><b>${res.asn ? "AS" + esc(res.asn) : "—"}</b></div>
      <div class="row"><span>Status</span><b>${badge}</b></div>
      <div class="row"><span>SSL cert</span>${ssl}</div>
    </div>
    <p class="muted">Verdict added to the public record for ${esc(res.provider)}.</p>
  `));
}

async function handleProvider(provider, env) {
  const { results } = await env.DB.prepare(
    `SELECT COUNT(*) checks, COUNT(DISTINCT domain) sites,
            ROUND(AVG(response_ms)) avg_ms,
            ROUND(100.0*SUM(up)/COUNT(*),1) uptime
     FROM checks WHERE provider = ?`
  ).bind(provider).all();
  const s = results[0];
  if (!s || !s.checks)
    return html(shell(provider, `<p>No data yet for <b>${esc(provider)}</b>.</p>`));

  return html(shell(`HostCop · ${provider}`, `
    <a class="back" href="/hosts">← all hosts</a>
    <h1>${esc(provider)}</h1>
    <div class="stats">
      <div><b>${s.avg_ms} ms</b><span>avg response</span></div>
      <div><b>${s.uptime}%</b><span>uptime</span></div>
      <div><b>${s.sites}</b><span>sites seen</span></div>
      <div><b>${s.checks}</b><span>total checks</span></div>
    </div>
    <p class="muted">Based only on live measurements from real domain checks — no reviews, no affiliate money.</p>
  `));
}

async function handleLeaderboard(env) {
  const { results } = await env.DB.prepare(
    `SELECT provider, COUNT(DISTINCT domain) sites,
            ROUND(AVG(response_ms)) avg_ms,
            ROUND(100.0*SUM(up)/COUNT(*),1) uptime
     FROM checks WHERE provider != 'Unknown'
     GROUP BY provider HAVING COUNT(*) >= 3
     ORDER BY uptime DESC, avg_ms ASC LIMIT 50`
  ).all();

  const rows = results.map((r, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><a href="/host/${encodeURIComponent(r.provider)}">${esc(r.provider)}</a></td>
      <td>${r.uptime}%</td>
      <td>${r.avg_ms} ms</td>
      <td>${r.sites}</td>
    </tr>`).join("") || `<tr><td colspan="5">No hosts ranked yet — go check a domain.</td></tr>`;

  return html(shell("HostCop · Rankings", `
    <a class="back" href="/">← home</a>
    <h1>Host rankings</h1>
    <p class="muted">Ranked by live measured uptime, then speed. Min 3 checks to appear.</p>
    <table>
      <tr><th>#</th><th>Host</th><th>Uptime</th><th>Avg</th><th>Sites</th></tr>
      ${rows}
    </table>
  `));
}

// ---- html ---------------------------------------------------------------

function homePage() {
  return `
    <div class="hero">
      <h1>Host<span>Cop</span></h1>
      <p>Who really hosts your site — and does it actually perform? Neutral, measured, no fake reviews.</p>
      <form action="/check" method="get">
        <input name="domain" placeholder="yourdomain.com" autofocus autocomplete="off">
        <button>Check</button>
      </form>
      <a class="ranklink" href="/hosts">See host rankings →</a>
    </div>`;
}

function shell(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>
*{box-sizing:border-box}body{font:16px/1.5 system-ui,sans-serif;max-width:640px;margin:0 auto;padding:32px 20px;color:#0f172a;background:#f8fafc}
a{color:#2563eb;text-decoration:none}a:hover{text-decoration:underline}
h1{font-size:2rem;margin:.2em 0}.hero{text-align:center;padding:40px 0}
.hero h1{font-size:2.6rem}.hero h1 span{color:#2563eb}
.hero p{color:#64748b;margin:0 0 24px}
form{display:flex;gap:8px;max-width:420px;margin:0 auto}
input{flex:1;padding:12px 14px;border:1px solid #cbd5e1;border-radius:10px;font-size:16px}
button{padding:12px 20px;border:0;border-radius:10px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
.ranklink{display:inline-block;margin-top:18px;color:#64748b}
.card,.stats{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:18px;margin:16px 0}
.row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f1f5f9}
.row:last-child{border:0}.row span{color:#64748b}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:16px;text-align:center}
.stats div b{display:block;font-size:1.5rem;color:#2563eb}.stats div span{color:#64748b;font-size:.85rem}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e2e8f0;border-radius:14px;overflow:hidden}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #f1f5f9}th{color:#64748b;font-size:.8rem;text-transform:uppercase}
.up{color:#16a34a;font-weight:700}.down{color:#dc2626;font-weight:700}.warn{color:#d97706;font-weight:700}
.muted{color:#94a3b8;font-size:.9rem}.back{display:inline-block;margin-bottom:8px;color:#64748b}
</style></head><body>${body}</body></html>`;
}

const html = (b, status = 200) =>
  new Response(b, { status, headers: { "content-type": "text/html;charset=utf-8" } });

// ---- utils --------------------------------------------------------------

function cleanDomain(d) {
  d = (d || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d) ? d : "";
}
const esc = s => String(s ?? "").replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
