-- Mother AI — approval notifications.
--
-- Notifications are a side effect of an approval that already exists. Nothing here
-- is read by the gateway's decision path, and no approval or decision row is ever
-- changed by notification delivery.

-- ---------------------------------------------------------------------------
-- Per-organization delivery destinations. One Slack incoming webhook per org.
-- The webhook URL is a secret: stored only as AES-GCM ciphertext bound to the
-- organization and channel id (so a row copied to another org cannot decrypt),
-- and never returned by any API.
-- ---------------------------------------------------------------------------
CREATE TABLE notification_channels (
  id                 TEXT PRIMARY KEY,           -- nch_
  organization_id    TEXT NOT NULL REFERENCES organizations(id),
  kind               TEXT NOT NULL CHECK (kind IN ('slack_webhook')),
  secret_ciphertext  TEXT NOT NULL,              -- v1.<iv>.<ciphertext>, base64url
  key_version        INTEGER NOT NULL DEFAULT 1,
  configured_by      TEXT,
  configured_by_name TEXT,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  UNIQUE (organization_id, kind)
);

-- ---------------------------------------------------------------------------
-- One row per (approval, event, channel): the durable idempotency marker.
-- Status labels are deliberately literal: SENT_TO_PROVIDER means the provider
-- accepted the HTTP request, not that a human read it.
-- ---------------------------------------------------------------------------
CREATE TABLE approval_notifications (
  id                TEXT PRIMARY KEY,            -- ntf_
  organization_id   TEXT NOT NULL,
  approval_id       TEXT NOT NULL REFERENCES approvals(id),
  event             TEXT NOT NULL CHECK (event IN ('review_required', 'approved', 'denied', 'expired', 'consumed')),
  channel           TEXT NOT NULL CHECK (channel IN ('slack')),
  status            TEXT NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'SENDING', 'SENT_TO_PROVIDER', 'FAILED', 'SKIPPED')),
  attempts          INTEGER NOT NULL DEFAULT 0,
  max_attempts      INTEGER NOT NULL DEFAULT 3,
  queued_at         TEXT NOT NULL,
  next_attempt_at   TEXT NOT NULL,
  lease_until       TEXT,
  last_attempt_at   TEXT,
  completed_at      TEXT,
  last_http_status  INTEGER,
  last_error        TEXT,                        -- short code, e.g. HTTP_429, TIMEOUT; never a URL
  UNIQUE (approval_id, event, channel)
);
CREATE INDEX approval_notifications_due ON approval_notifications (status, next_attempt_at);
CREATE INDEX approval_notifications_org_time ON approval_notifications (organization_id, queued_at);

-- A notification that reached a terminal state is never re-sent or reopened.
CREATE TRIGGER approval_notifications_terminal BEFORE UPDATE ON approval_notifications
WHEN OLD.status IN ('SENT_TO_PROVIDER', 'FAILED', 'SKIPPED')
  OR NEW.id <> OLD.id OR NEW.organization_id <> OLD.organization_id OR NEW.approval_id <> OLD.approval_id
  OR NEW.event <> OLD.event OR NEW.channel <> OLD.channel OR NEW.queued_at <> OLD.queued_at
  OR NEW.attempts < OLD.attempts OR NEW.attempts > NEW.max_attempts
BEGIN
  SELECT RAISE(ABORT, 'invalid notification transition');
END;
CREATE TRIGGER approval_notifications_no_delete BEFORE DELETE ON approval_notifications
BEGIN
  SELECT RAISE(ABORT, 'notification records are retained');
END;

-- Append-only log of every delivery attempt.
CREATE TABLE approval_notification_attempts (
  id               TEXT PRIMARY KEY,             -- nta_
  organization_id  TEXT NOT NULL,
  notification_id  TEXT NOT NULL REFERENCES approval_notifications(id),
  attempt          INTEGER NOT NULL,
  started_at       TEXT NOT NULL,
  finished_at      TEXT NOT NULL,
  outcome          TEXT NOT NULL CHECK (outcome IN ('SENT_TO_PROVIDER', 'FAILED', 'ABANDONED')),
  http_status      INTEGER,
  error            TEXT
);
CREATE INDEX approval_notification_attempts_notification ON approval_notification_attempts (notification_id, attempt);

CREATE TRIGGER approval_notification_attempts_no_update BEFORE UPDATE ON approval_notification_attempts
BEGIN
  SELECT RAISE(ABORT, 'notification attempts are append-only');
END;
CREATE TRIGGER approval_notification_attempts_no_delete BEFORE DELETE ON approval_notification_attempts
BEGIN
  SELECT RAISE(ABORT, 'notification attempts are append-only');
END;
