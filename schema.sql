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
