-- HostCop D1 schema

-- Every single check anyone runs gets stored here. This is the whole moat.
CREATE TABLE IF NOT EXISTS checks (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  domain       TEXT NOT NULL,
  ip           TEXT,
  asn          TEXT,
  provider     TEXT,          -- raw ASN org, e.g. "CLOUDFLARENET - Cloudflare, Inc."
  brand        TEXT,          -- clean display/grouping name, e.g. "Cloudflare"
  country      TEXT,          -- ISO country of the IP's network (approx location)
  response_ms  INTEGER,
  http_status  INTEGER,
  up           INTEGER,       -- 1 = responded, 0 = down/error
  ssl_expiry   INTEGER,       -- epoch ms of cert notAfter, null if unknown
  region       TEXT,          -- CF colo the check ran from (or 'cron')
  checked_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_checks_provider ON checks(provider);
CREATE INDEX IF NOT EXISTS idx_checks_domain   ON checks(domain);
CREATE INDEX IF NOT EXISTS idx_checks_time     ON checks(checked_at);

-- Domains we keep re-pinging on the cron so the data stays fresh.
CREATE TABLE IF NOT EXISTS domains (
  domain       TEXT PRIMARY KEY,
  provider     TEXT,
  added_at     INTEGER NOT NULL,
  last_checked INTEGER
);

-- Uptime / SSL monitors — people who asked to be emailed about a domain.
CREATE TABLE IF NOT EXISTS monitors (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  domain       TEXT NOT NULL,
  email        TEXT NOT NULL,
  status       TEXT,                 -- last seen: up | down | unknown
  ssl_alerted  INTEGER DEFAULT 0,    -- 1 = we've already emailed about this cert expiring
  token        TEXT NOT NULL,        -- verify + unsubscribe token
  verified     INTEGER DEFAULT 0,    -- only verified monitors get alerts (anti-abuse)
  created_at   INTEGER NOT NULL,
  last_change  INTEGER,
  UNIQUE(domain, email)
);
CREATE INDEX IF NOT EXISTS idx_monitors_domain ON monitors(domain);
CREATE INDEX IF NOT EXISTS idx_monitors_token  ON monitors(token);

-- Paid plans, keyed by email (same identity as monitors). No accounts needed.
CREATE TABLE IF NOT EXISTS subscriptions (
  email           TEXT PRIMARY KEY,
  plan            TEXT NOT NULL DEFAULT 'free',   -- free | pro
  status          TEXT DEFAULT 'active',          -- active | canceled | past_due
  stripe_customer TEXT,
  stripe_sub      TEXT,
  updated         INTEGER
);
CREATE INDEX IF NOT EXISTS idx_subs_customer ON subscriptions(stripe_customer);
