-- Mother AI — initial schema.
-- Conventions:
--   * ids are prefixed random strings (org_, agt_, pol_, dec_, apr_, ...)
--   * timestamps are ISO-8601 UTC text with milliseconds ("2026-09-14T12:00:00.000Z"),
--     which sort lexicographically
--   * every tenant-owned row carries organization_id and every query filters on it
--   * decision evidence, policy versions and control events are append-only (triggers)

-- ---------------------------------------------------------------------------
-- Tenancy
-- ---------------------------------------------------------------------------
CREATE TABLE organizations (
  id                          TEXT PRIMARY KEY,
  slug                        TEXT NOT NULL UNIQUE,
  display_name                TEXT NOT NULL,
  kind                        TEXT NOT NULL DEFAULT 'customer' CHECK (kind IN ('customer', 'internal')),
  status                      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
  plan                        TEXT NOT NULL DEFAULT 'founding' CHECK (plan IN ('founding', 'team', 'enterprise', 'internal')),
  gateway_enabled             INTEGER NOT NULL DEFAULT 1 CHECK (gateway_enabled IN (0, 1)),
  audit_enabled               INTEGER NOT NULL DEFAULT 1 CHECK (audit_enabled IN (0, 1)),
  require_registered_agents   INTEGER NOT NULL DEFAULT 1 CHECK (require_registered_agents IN (0, 1)),
  default_decision            TEXT NOT NULL DEFAULT 'block' CHECK (default_decision IN ('block', 'review')),
  approval_ttl_seconds        INTEGER NOT NULL DEFAULT 900 CHECK (approval_ttl_seconds BETWEEN 60 AND 86400),
  approval_grant_ttl_seconds  INTEGER NOT NULL DEFAULT 600 CHECK (approval_grant_ttl_seconds BETWEEN 30 AND 86400),
  created_at                  TEXT NOT NULL,
  updated_at                  TEXT NOT NULL
);

CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  display_name  TEXT NOT NULL,
  email         TEXT,
  created_at    TEXT NOT NULL
);

CREATE TABLE memberships (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id),
  user_id          TEXT NOT NULL REFERENCES users(id),
  role             TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'security', 'approver', 'viewer')),
  status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at       TEXT NOT NULL,
  UNIQUE (organization_id, user_id)
);
CREATE INDEX memberships_user ON memberships (user_id);

-- Passkeys (WebAuthn). No passwords are stored anywhere in Mother AI.
CREATE TABLE webauthn_credentials (
  id               TEXT PRIMARY KEY,           -- base64url credential id
  user_id          TEXT NOT NULL REFERENCES users(id),
  public_key       TEXT NOT NULL,              -- base64url COSE public key
  counter          INTEGER NOT NULL DEFAULT 0,
  transports       TEXT,                       -- JSON array
  device_type      TEXT,
  backed_up        INTEGER NOT NULL DEFAULT 0,
  name             TEXT NOT NULL DEFAULT 'Passkey',
  created_at       TEXT NOT NULL,
  last_used_at     TEXT
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id);

CREATE TABLE auth_challenges (
  id          TEXT PRIMARY KEY,
  purpose     TEXT NOT NULL CHECK (purpose IN ('register', 'login')),
  challenge   TEXT NOT NULL,
  invite_id   TEXT,
  user_id     TEXT,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  used_at     TEXT
);

CREATE TABLE sessions (
  id               TEXT PRIMARY KEY,
  token_hash       TEXT NOT NULL UNIQUE,       -- sha256(token), hex
  user_id          TEXT NOT NULL REFERENCES users(id),
  organization_id  TEXT NOT NULL REFERENCES organizations(id),
  created_at       TEXT NOT NULL,
  last_seen_at     TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  revoked_at       TEXT
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE invites (
  id                TEXT PRIMARY KEY,
  organization_id   TEXT NOT NULL REFERENCES organizations(id),
  token_hash        TEXT NOT NULL UNIQUE,      -- sha256(token), hex
  role              TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'security', 'approver', 'viewer')),
  display_name      TEXT NOT NULL,
  email             TEXT,
  created_by        TEXT,                      -- user id, or 'ops' for operator bootstrap
  created_at        TEXT NOT NULL,
  expires_at        TEXT NOT NULL,
  accepted_at       TEXT,
  accepted_user_id  TEXT,
  revoked_at        TEXT
);
CREATE INDEX invites_org ON invites (organization_id, created_at);

-- ---------------------------------------------------------------------------
-- Agent registry and policies
-- ---------------------------------------------------------------------------
CREATE TABLE agents (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id),
  agent_key        TEXT NOT NULL,              -- stable customer-facing id, e.g. billing-agent-prod
  display_name     TEXT NOT NULL,
  description      TEXT NOT NULL DEFAULT '',
  environment      TEXT NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  status           TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  default_mode     TEXT NOT NULL DEFAULT 'inherit' CHECK (default_mode IN ('inherit', 'block', 'review', 'allow')),
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  UNIQUE (organization_id, agent_key),
  -- a production agent may never silently default to allow
  CHECK (NOT (environment = 'production' AND default_mode = 'allow'))
);

CREATE TABLE policies (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id),
  name             TEXT NOT NULL,
  description      TEXT NOT NULL DEFAULT '',
  priority         INTEGER NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 10000),
  enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  effect           TEXT NOT NULL CHECK (effect IN ('allow', 'review', 'block')),
  scope            TEXT NOT NULL DEFAULT 'organization' CHECK (scope IN ('organization', 'agents')),
  conditions       TEXT NOT NULL,              -- JSON ConditionGroup, validated by the engine
  reason_code      TEXT,
  reason           TEXT,
  version          INTEGER NOT NULL DEFAULT 1,
  archived_at      TEXT,
  created_by       TEXT,
  updated_by       TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);
CREATE INDEX policies_org ON policies (organization_id, archived_at, enabled);

CREATE TABLE policy_versions (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL,
  policy_id        TEXT NOT NULL,
  version          INTEGER NOT NULL,
  snapshot         TEXT NOT NULL,              -- JSON of the full policy at this version
  changed_by       TEXT,
  created_at       TEXT NOT NULL,
  UNIQUE (policy_id, version)
);

CREATE TABLE agent_policy_bindings (
  organization_id  TEXT NOT NULL,
  agent_id         TEXT NOT NULL REFERENCES agents(id),
  policy_id        TEXT NOT NULL REFERENCES policies(id),
  created_at       TEXT NOT NULL,
  PRIMARY KEY (agent_id, policy_id)
);
CREATE INDEX agent_policy_bindings_policy ON agent_policy_bindings (policy_id);
CREATE INDEX agent_policy_bindings_org ON agent_policy_bindings (organization_id);

-- ---------------------------------------------------------------------------
-- Gateway credentials
-- ---------------------------------------------------------------------------
CREATE TABLE api_keys (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id),
  name             TEXT NOT NULL,
  key_prefix       TEXT NOT NULL,              -- first characters, safe to display
  key_hash         TEXT NOT NULL UNIQUE,       -- sha256(raw key), hex. Raw key is never stored.
  environment      TEXT NOT NULL CHECK (environment IN ('live', 'test')),
  created_by       TEXT,
  created_at       TEXT NOT NULL,
  last_used_at     TEXT,
  revoked_at       TEXT,
  revoked_by       TEXT
);
CREATE INDEX api_keys_org ON api_keys (organization_id, revoked_at);

-- ---------------------------------------------------------------------------
-- Decision evidence (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE decisions (
  id                   TEXT PRIMARY KEY,
  organization_id      TEXT NOT NULL,
  request_id           TEXT NOT NULL,
  request_fingerprint  TEXT NOT NULL,
  api_key_id           TEXT,
  agent_id             TEXT,
  agent_key            TEXT NOT NULL,
  protocol             TEXT NOT NULL CHECK (protocol IN ('api', 'mcp')),
  capability           TEXT NOT NULL,
  operation            TEXT NOT NULL,
  resource             TEXT,
  destination          TEXT,
  data_class           TEXT,
  environment          TEXT,
  mcp_server           TEXT,
  mcp_tool             TEXT,
  decision             TEXT NOT NULL CHECK (decision IN ('allow', 'review', 'block')),
  reason_code          TEXT NOT NULL,
  reason               TEXT NOT NULL,
  policy_id            TEXT,
  policy_version       INTEGER,
  matched_policies     TEXT NOT NULL DEFAULT '[]',
  context              TEXT,                   -- redacted JSON; NULL when audit capture is disabled
  eval_ms              REAL,
  gateway_ms           REAL,
  engine_version       TEXT NOT NULL,
  created_at           TEXT NOT NULL,
  UNIQUE (organization_id, request_id)
);
CREATE INDEX decisions_org_time ON decisions (organization_id, created_at);
CREATE INDEX decisions_org_agent_time ON decisions (organization_id, agent_id, created_at);
CREATE INDEX decisions_org_decision_time ON decisions (organization_id, decision, created_at);

CREATE TRIGGER decisions_no_update BEFORE UPDATE ON decisions
BEGIN
  SELECT RAISE(ABORT, 'decisions are append-only');
END;
CREATE TRIGGER decisions_no_delete BEFORE DELETE ON decisions
BEGIN
  SELECT RAISE(ABORT, 'decisions are append-only');
END;

CREATE TRIGGER policy_versions_no_update BEFORE UPDATE ON policy_versions
BEGIN
  SELECT RAISE(ABORT, 'policy versions are append-only');
END;
CREATE TRIGGER policy_versions_no_delete BEFORE DELETE ON policy_versions
BEGIN
  SELECT RAISE(ABORT, 'policy versions are append-only');
END;

-- ---------------------------------------------------------------------------
-- Human approval
-- ---------------------------------------------------------------------------
CREATE TABLE approvals (
  id                TEXT PRIMARY KEY,
  organization_id   TEXT NOT NULL,
  decision_id       TEXT NOT NULL UNIQUE REFERENCES decisions(id),
  status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  requested_at      TEXT NOT NULL,
  expires_at        TEXT NOT NULL,
  acted_at          TEXT,
  acted_by          TEXT,
  acted_by_name     TEXT,
  note              TEXT,
  grant_expires_at  TEXT,
  consumed_at       TEXT
);
CREATE INDEX approvals_org_status ON approvals (organization_id, status, expires_at);

-- The only legal transitions are pending -> approved|denied|expired, and a
-- single consumption of an approved grant. Everything else is rejected.
CREATE TRIGGER approvals_transitions BEFORE UPDATE ON approvals
WHEN NOT (
  NEW.id = OLD.id
  AND NEW.organization_id = OLD.organization_id
  AND NEW.decision_id = OLD.decision_id
  AND NEW.requested_at = OLD.requested_at
  AND NEW.expires_at = OLD.expires_at
  AND (
    (OLD.status = 'pending' AND NEW.status IN ('approved', 'denied', 'expired') AND NEW.consumed_at IS NULL)
    OR (
      OLD.status = 'approved' AND NEW.status = 'approved'
      AND OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL
      AND NEW.acted_at IS OLD.acted_at AND NEW.acted_by IS OLD.acted_by
      AND NEW.grant_expires_at IS OLD.grant_expires_at AND NEW.note IS OLD.note
    )
  )
)
BEGIN
  SELECT RAISE(ABORT, 'invalid approval transition');
END;
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals
BEGIN
  SELECT RAISE(ABORT, 'approvals are append-only');
END;

-- ---------------------------------------------------------------------------
-- Control-plane evidence (append-only): policy edits, key lifecycle,
-- approval actions, badge changes, membership changes.
-- ---------------------------------------------------------------------------
CREATE TABLE control_events (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL,
  actor_type       TEXT NOT NULL CHECK (actor_type IN ('user', 'api_key', 'system', 'ops')),
  actor_id         TEXT,
  actor_label      TEXT,
  action           TEXT NOT NULL,
  target_type      TEXT,
  target_id        TEXT,
  detail           TEXT NOT NULL DEFAULT '{}',
  created_at       TEXT NOT NULL
);
CREATE INDEX control_events_org_time ON control_events (organization_id, created_at);

CREATE TRIGGER control_events_no_update BEFORE UPDATE ON control_events
BEGIN
  SELECT RAISE(ABORT, 'control events are append-only');
END;
CREATE TRIGGER control_events_no_delete BEFORE DELETE ON control_events
BEGIN
  SELECT RAISE(ABORT, 'control events are append-only');
END;

-- ---------------------------------------------------------------------------
-- Mother AI Protected badge
-- ---------------------------------------------------------------------------
CREATE TABLE badges (
  id               TEXT PRIMARY KEY,
  organization_id  TEXT NOT NULL REFERENCES organizations(id),
  public_token     TEXT NOT NULL UNIQUE,       -- high-entropy, public; never an internal id
  state            TEXT NOT NULL DEFAULT 'enabled' CHECK (state IN ('enabled', 'suspended', 'revoked')),
  activated_at     TEXT,                       -- first time eligibility was met
  created_at       TEXT NOT NULL,
  suspended_at     TEXT,
  revoked_at       TEXT,
  revoked_reason   TEXT
);
CREATE UNIQUE INDEX badges_one_live_per_org ON badges (organization_id) WHERE state <> 'revoked';

-- ---------------------------------------------------------------------------
-- Founding Access (public marketing form)
-- ---------------------------------------------------------------------------
CREATE TABLE founding_access_requests (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  company      TEXT NOT NULL,
  work_email   TEXT NOT NULL,
  use_case     TEXT NOT NULL,
  agent_count  TEXT NOT NULL CHECK (agent_count IN ('1-5', '6-25', '26-100', '100+', 'unknown')),
  uses_mcp     TEXT NOT NULL CHECK (uses_mcp IN ('yes', 'no', 'evaluating')),
  ip_hash      TEXT,                           -- sha256(ip + daily salt); raw IPs are not stored
  turnstile    TEXT NOT NULL CHECK (turnstile IN ('verified', 'not_configured')),
  status       TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'contacted', 'onboarded', 'declined', 'spam')),
  created_at   TEXT NOT NULL
);
CREATE INDEX founding_access_email ON founding_access_requests (work_email);
CREATE INDEX founding_access_time ON founding_access_requests (created_at);
