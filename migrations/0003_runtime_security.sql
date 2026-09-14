-- Mother AI — runtime containment V1 (sessions, runtime evidence, deterministic risk,
-- quarantine, capability leases, incidents, security alerts).
--
-- Additive only. The policy engine and the meaning of existing rows are unchanged:
--   * decisions.decision is the effective decision; risk_evaluations records the policy decision,
--     the runtime risk decision and the effective decision separately, and a CHECK plus a trigger
--     prove the runtime layer can only preserve or restrict the policy decision.
--   * all runtime evidence is append-only; mutable state tables have transition triggers.
--   * every tenant row carries organization_id and triggers reject cross-tenant correlation.

-- ---------------------------------------------------------------------------
-- Organization runtime protection mode and alert opt-in
-- ---------------------------------------------------------------------------
ALTER TABLE organizations ADD COLUMN runtime_protection TEXT NOT NULL DEFAULT 'monitor'
  CHECK (runtime_protection IN ('off', 'monitor', 'enforce'));
ALTER TABLE organizations ADD COLUMN security_alerts_enabled INTEGER NOT NULL DEFAULT 0
  CHECK (security_alerts_enabled IN (0, 1));

-- ---------------------------------------------------------------------------
-- Human vs automation identities. Only humans can clear a quarantine. One-way: an
-- automation identity can never be turned into a human one.
-- ---------------------------------------------------------------------------
ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'human' CHECK (kind IN ('human', 'automation'));
CREATE TRIGGER users_kind_one_way BEFORE UPDATE OF kind ON users
WHEN OLD.kind = 'automation' AND NEW.kind <> 'automation'
BEGIN
  SELECT RAISE(ABORT, 'automation identities cannot become human');
END;

-- ---------------------------------------------------------------------------
-- Agent sessions: the causal tree
-- ---------------------------------------------------------------------------
CREATE TABLE agent_sessions (
  id                 TEXT PRIMARY KEY,                 -- asn_ (console sessions use ses_)
  organization_id    TEXT NOT NULL REFERENCES organizations(id),
  agent_id           TEXT NOT NULL REFERENCES agents(id),
  api_key_id         TEXT NOT NULL REFERENCES api_keys(id),
  parent_session_id  TEXT REFERENCES agent_sessions(id),
  root_session_id    TEXT NOT NULL,
  depth              INTEGER NOT NULL DEFAULT 0 CHECK (depth BETWEEN 0 AND 8),
  principal_type     TEXT NOT NULL DEFAULT 'unknown'
                     CHECK (principal_type IN ('user', 'service', 'schedule', 'agent', 'unknown')),
  principal_ref      TEXT,                             -- asserted by the integration; not verified by Mother
  purpose            TEXT,
  opened_at          TEXT NOT NULL,
  expires_at         TEXT NOT NULL,
  closed_at          TEXT,
  CHECK (expires_at > opened_at),
  CHECK ((parent_session_id IS NULL AND depth = 0 AND root_session_id = id)
      OR (parent_session_id IS NOT NULL AND depth > 0))
);
CREATE INDEX agent_sessions_org_agent ON agent_sessions (organization_id, agent_id, expires_at);
CREATE INDEX agent_sessions_parent ON agent_sessions (parent_session_id, opened_at);
CREATE INDEX agent_sessions_root ON agent_sessions (organization_id, root_session_id);

CREATE TRIGGER agent_sessions_parent_same_tree BEFORE INSERT ON agent_sessions
WHEN NEW.parent_session_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM agent_sessions p
   WHERE p.id = NEW.parent_session_id AND p.organization_id = NEW.organization_id
     AND p.root_session_id = NEW.root_session_id AND p.depth = NEW.depth - 1)
BEGIN
  SELECT RAISE(ABORT, 'invalid parent session');
END;
CREATE TRIGGER agent_sessions_agent_same_org BEFORE INSERT ON agent_sessions
WHEN NOT EXISTS (SELECT 1 FROM agents a WHERE a.id = NEW.agent_id AND a.organization_id = NEW.organization_id)
  OR NOT EXISTS (SELECT 1 FROM api_keys k WHERE k.id = NEW.api_key_id AND k.organization_id = NEW.organization_id)
BEGIN
  SELECT RAISE(ABORT, 'cross-tenant correlation');
END;
CREATE TRIGGER agent_sessions_close_only BEFORE UPDATE ON agent_sessions
WHEN NOT (
  NEW.id = OLD.id AND NEW.organization_id = OLD.organization_id AND NEW.agent_id = OLD.agent_id
  AND NEW.api_key_id = OLD.api_key_id AND NEW.parent_session_id IS OLD.parent_session_id
  AND NEW.root_session_id = OLD.root_session_id AND NEW.depth = OLD.depth
  AND NEW.principal_type = OLD.principal_type AND NEW.principal_ref IS OLD.principal_ref
  AND NEW.purpose IS OLD.purpose AND NEW.opened_at = OLD.opened_at AND NEW.expires_at = OLD.expires_at
  AND OLD.closed_at IS NULL AND NEW.closed_at IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'sessions can only be closed');
END;
CREATE TRIGGER agent_sessions_no_delete BEFORE DELETE ON agent_sessions
BEGIN
  SELECT RAISE(ABORT, 'sessions are retained');
END;

-- ---------------------------------------------------------------------------
-- Decision correlation. Stored only after validation; a rejected claim is kept in
-- risk_evaluations.claimed_session_id / claimed_parent_id instead.
-- ---------------------------------------------------------------------------
ALTER TABLE decisions ADD COLUMN session_id TEXT;
ALTER TABLE decisions ADD COLUMN parent_decision_id TEXT;
CREATE INDEX decisions_org_session_time ON decisions (organization_id, session_id, created_at);

CREATE TRIGGER decisions_correlation_same_org BEFORE INSERT ON decisions
WHEN (NEW.session_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM agent_sessions s WHERE s.id = NEW.session_id AND s.organization_id = NEW.organization_id))
  OR (NEW.parent_decision_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM decisions p WHERE p.id = NEW.parent_decision_id AND p.organization_id = NEW.organization_id))
BEGIN
  SELECT RAISE(ABORT, 'cross-tenant correlation');
END;

-- ---------------------------------------------------------------------------
-- Approvals terminated by containment. Never a human denial: acted_by stays NULL and the
-- reason and incident are recorded. Settable only on the pending -> denied transition.
-- ---------------------------------------------------------------------------
ALTER TABLE approvals ADD COLUMN terminated_reason TEXT CHECK (terminated_reason IS NULL OR terminated_reason = 'quarantine');
ALTER TABLE approvals ADD COLUMN terminated_incident_id TEXT;
CREATE TRIGGER approvals_termination BEFORE UPDATE ON approvals
WHEN (NEW.terminated_reason IS NOT OLD.terminated_reason OR NEW.terminated_incident_id IS NOT OLD.terminated_incident_id)
  AND NOT (OLD.status = 'pending' AND NEW.status = 'denied' AND OLD.terminated_reason IS NULL
           AND NEW.terminated_reason = 'quarantine' AND NEW.terminated_incident_id IS NOT NULL
           AND NEW.acted_by IS NULL)
BEGIN
  SELECT RAISE(ABORT, 'invalid approval termination');
END;

-- ---------------------------------------------------------------------------
-- Runtime events (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE runtime_events (
  id               TEXT PRIMARY KEY,                   -- rte_
  organization_id  TEXT NOT NULL,
  type             TEXT NOT NULL CHECK (type IN (
                     'session.opened', 'session.closed', 'session.refused',
                     'execution.reported', 'lease.issued', 'lease.used', 'lease.refused',
                     'approval.consume_refused', 'runtime.replay_blocked', 'quarantine.enforced', 'quarantine.cleared')),
  source           TEXT NOT NULL CHECK (source IN ('mother', 'integration')),
  outcome          TEXT CHECK (outcome IN ('succeeded', 'failed', 'skipped', 'granted', 'refused')),
  reason_code      TEXT,
  session_id       TEXT,
  agent_id         TEXT,
  api_key_id       TEXT,
  decision_id      TEXT,
  request_id       TEXT,
  approval_id      TEXT,
  lease_id         TEXT,
  incident_id      TEXT,
  detail           TEXT NOT NULL DEFAULT '{}',         -- redacted, bounded, never raw context
  created_at       TEXT NOT NULL
);
CREATE INDEX runtime_events_org_session_time ON runtime_events (organization_id, session_id, created_at);
CREATE INDEX runtime_events_org_agent_time ON runtime_events (organization_id, agent_id, created_at);
CREATE INDEX runtime_events_org_time ON runtime_events (organization_id, created_at);

CREATE TRIGGER runtime_events_same_org BEFORE INSERT ON runtime_events
WHEN (NEW.session_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM agent_sessions s WHERE s.id = NEW.session_id AND s.organization_id = NEW.organization_id))
  OR (NEW.decision_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM decisions d WHERE d.id = NEW.decision_id AND d.organization_id = NEW.organization_id))
  OR (NEW.agent_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM agents a WHERE a.id = NEW.agent_id AND a.organization_id = NEW.organization_id))
BEGIN
  SELECT RAISE(ABORT, 'cross-tenant correlation');
END;
CREATE TRIGGER runtime_events_no_update BEFORE UPDATE ON runtime_events
BEGIN
  SELECT RAISE(ABORT, 'runtime events are append-only');
END;
CREATE TRIGGER runtime_events_no_delete BEFORE DELETE ON runtime_events
BEGIN
  SELECT RAISE(ABORT, 'runtime events are append-only');
END;

-- ---------------------------------------------------------------------------
-- Capability leases (exact resource only) and their uses
-- ---------------------------------------------------------------------------
CREATE TABLE capability_leases (
  id               TEXT PRIMARY KEY,                   -- lse_
  organization_id  TEXT NOT NULL REFERENCES organizations(id),
  agent_id         TEXT NOT NULL REFERENCES agents(id),
  session_id       TEXT NOT NULL REFERENCES agent_sessions(id),
  api_key_id       TEXT NOT NULL REFERENCES api_keys(id),
  decision_id      TEXT NOT NULL UNIQUE REFERENCES decisions(id),
  principal_type   TEXT NOT NULL,
  principal_ref    TEXT,
  capability       TEXT NOT NULL,
  operation        TEXT NOT NULL,
  resource         TEXT,
  destination      TEXT,
  data_class       TEXT,
  policy_id        TEXT,
  policy_version   INTEGER,
  max_uses         INTEGER NOT NULL CHECK (max_uses BETWEEN 1 AND 20),
  uses             INTEGER NOT NULL DEFAULT 0,
  issued_at        TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  revoked_at       TEXT,
  revoked_reason   TEXT,
  CHECK (expires_at > issued_at),
  CHECK (uses BETWEEN 0 AND max_uses)
);
CREATE INDEX capability_leases_org_session ON capability_leases (organization_id, session_id);
CREATE INDEX capability_leases_org_agent_exp ON capability_leases (organization_id, agent_id, expires_at);

CREATE TRIGGER capability_leases_same_org BEFORE INSERT ON capability_leases
WHEN NOT EXISTS (SELECT 1 FROM agent_sessions s WHERE s.id = NEW.session_id AND s.organization_id = NEW.organization_id AND s.agent_id = NEW.agent_id)
  OR NOT EXISTS (SELECT 1 FROM decisions d WHERE d.id = NEW.decision_id AND d.organization_id = NEW.organization_id AND d.decision = 'allow')
BEGIN
  SELECT RAISE(ABORT, 'invalid lease');
END;
CREATE TRIGGER capability_leases_transitions BEFORE UPDATE ON capability_leases
WHEN NOT (
  NEW.id = OLD.id AND NEW.organization_id = OLD.organization_id AND NEW.agent_id = OLD.agent_id
  AND NEW.session_id = OLD.session_id AND NEW.api_key_id = OLD.api_key_id AND NEW.decision_id = OLD.decision_id
  AND NEW.principal_type = OLD.principal_type AND NEW.principal_ref IS OLD.principal_ref
  AND NEW.capability = OLD.capability AND NEW.operation = OLD.operation AND NEW.resource IS OLD.resource
  AND NEW.destination IS OLD.destination AND NEW.data_class IS OLD.data_class
  AND NEW.policy_id IS OLD.policy_id AND NEW.policy_version IS OLD.policy_version
  AND NEW.max_uses = OLD.max_uses AND NEW.issued_at = OLD.issued_at AND NEW.expires_at = OLD.expires_at
  AND (
    (OLD.revoked_at IS NULL AND NEW.revoked_at IS NULL AND NEW.uses = OLD.uses + 1)
    OR (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND NEW.uses = OLD.uses AND NEW.revoked_reason IS NOT NULL)
  ))
BEGIN
  SELECT RAISE(ABORT, 'invalid lease transition');
END;
CREATE TRIGGER capability_leases_no_delete BEFORE DELETE ON capability_leases
BEGIN
  SELECT RAISE(ABORT, 'leases are retained');
END;

CREATE TABLE lease_uses (
  id               TEXT PRIMARY KEY,                   -- lsu_
  organization_id  TEXT NOT NULL,
  lease_id         TEXT NOT NULL REFERENCES capability_leases(id),
  api_key_id       TEXT NOT NULL,
  outcome          TEXT NOT NULL CHECK (outcome IN ('granted', 'refused')),
  refusal_code     TEXT,
  resource         TEXT,
  destination      TEXT,
  data_class       TEXT,
  effective_state  TEXT NOT NULL,
  created_at       TEXT NOT NULL,
  CHECK ((outcome = 'granted' AND refusal_code IS NULL) OR (outcome = 'refused' AND refusal_code IS NOT NULL))
);
CREATE INDEX lease_uses_lease ON lease_uses (lease_id, created_at);
CREATE TRIGGER lease_uses_no_update BEFORE UPDATE ON lease_uses
BEGIN
  SELECT RAISE(ABORT, 'lease uses are append-only');
END;
CREATE TRIGGER lease_uses_no_delete BEFORE DELETE ON lease_uses
BEGIN
  SELECT RAISE(ABORT, 'lease uses are append-only');
END;

-- ---------------------------------------------------------------------------
-- Deterministic risk: subjects (state), signals, transitions, per-decision evaluation
-- ---------------------------------------------------------------------------
CREATE TABLE risk_subjects (
  organization_id       TEXT NOT NULL REFERENCES organizations(id),
  subject_type          TEXT NOT NULL CHECK (subject_type IN ('agent', 'session', 'api_key')),
  subject_id            TEXT NOT NULL,
  state                 TEXT NOT NULL DEFAULT 'normal'
                        CHECK (state IN ('normal', 'elevated', 'review_required', 'quarantined', 'contained', 'cleared')),
  score                 INTEGER NOT NULL DEFAULT 0 CHECK (score >= 0),
  state_since           TEXT NOT NULL,
  signals_since         TEXT NOT NULL,                 -- signals older than this never count (moves forward at clearance)
  containment_epoch_at  TEXT,                          -- authority issued before this is permanently invalid
  incident_id           TEXT,
  cleared_by            TEXT,
  cleared_at            TEXT,
  version               INTEGER NOT NULL DEFAULT 1,
  updated_at            TEXT NOT NULL,
  PRIMARY KEY (subject_type, subject_id),
  CHECK (subject_type <> 'api_key' OR state IN ('normal', 'elevated', 'review_required', 'cleared'))
);
CREATE INDEX risk_subjects_org_state ON risk_subjects (organization_id, state);

CREATE TRIGGER risk_subjects_transitions BEFORE UPDATE ON risk_subjects
WHEN NEW.organization_id <> OLD.organization_id OR NEW.subject_type <> OLD.subject_type
  OR NEW.subject_id <> OLD.subject_id OR NEW.version <> OLD.version + 1
  OR NEW.signals_since < OLD.signals_since
  OR (OLD.containment_epoch_at IS NOT NULL
      AND (NEW.containment_epoch_at IS NULL OR NEW.containment_epoch_at < OLD.containment_epoch_at))
  -- quarantine is sticky: only a clearance leaves it
  OR (OLD.state IN ('quarantined', 'contained') AND NEW.state NOT IN ('quarantined', 'contained', 'cleared'))
  OR (OLD.state = 'contained' AND NEW.state = 'quarantined')
  OR (OLD.state IN ('quarantined', 'contained') AND NEW.state IN ('quarantined', 'contained') AND NEW.incident_id IS NOT OLD.incident_id)
  -- entering quarantine opens an incident and moves the containment epoch forward
  OR (NEW.state = 'quarantined' AND OLD.state NOT IN ('quarantined', 'contained')
      AND (NEW.incident_id IS NULL OR NEW.containment_epoch_at IS NULL
           OR NEW.containment_epoch_at IS OLD.containment_epoch_at))
  -- clearing requires an active human security/admin/owner member of the same organization
  OR (NEW.state = 'cleared' AND OLD.state IN ('quarantined', 'contained') AND (
        NEW.cleared_at IS NULL OR NEW.cleared_at IS OLD.cleared_at OR NEW.signals_since <> NEW.cleared_at
        OR NOT EXISTS (
          SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
           WHERE m.user_id = NEW.cleared_by AND m.organization_id = NEW.organization_id
             AND m.status = 'active' AND m.role IN ('security', 'admin', 'owner') AND u.kind = 'human')))
BEGIN
  SELECT RAISE(ABORT, 'invalid risk transition');
END;
CREATE TRIGGER risk_subjects_no_delete BEFORE DELETE ON risk_subjects
BEGIN
  SELECT RAISE(ABORT, 'risk subjects are retained');
END;

CREATE TABLE risk_signals (
  id               TEXT PRIMARY KEY,                   -- rsg_
  organization_id  TEXT NOT NULL,
  subject_type     TEXT NOT NULL CHECK (subject_type IN ('agent', 'session', 'api_key')),
  subject_id       TEXT NOT NULL,
  signal           TEXT NOT NULL,
  hard             INTEGER NOT NULL CHECK (hard IN (0, 1)),
  points           INTEGER NOT NULL CHECK (points BETWEEN 0 AND 100),
  evidence_key     TEXT NOT NULL,                      -- one signal per subject + key within the window
  evidence         TEXT NOT NULL DEFAULT '{}',         -- ids, counts, thresholds; never raw context
  rule_version     TEXT NOT NULL,
  session_id       TEXT,
  decision_id      TEXT,
  mode             TEXT NOT NULL CHECK (mode IN ('monitor', 'enforce')),
  observed_at      TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  CHECK (expires_at > observed_at)
);
CREATE INDEX risk_signals_subject_time ON risk_signals (subject_type, subject_id, observed_at);
CREATE INDEX risk_signals_org_time ON risk_signals (organization_id, observed_at);
CREATE TRIGGER risk_signals_no_update BEFORE UPDATE ON risk_signals
BEGIN
  SELECT RAISE(ABORT, 'risk signals are append-only');
END;
CREATE TRIGGER risk_signals_no_delete BEFORE DELETE ON risk_signals
BEGIN
  SELECT RAISE(ABORT, 'risk signals are append-only');
END;

CREATE TABLE risk_transitions (
  id               TEXT PRIMARY KEY,                   -- rtr_
  organization_id  TEXT NOT NULL,
  subject_type     TEXT NOT NULL,
  subject_id       TEXT NOT NULL,
  from_state       TEXT NOT NULL,
  to_state         TEXT NOT NULL,
  score            INTEGER NOT NULL,
  cause            TEXT NOT NULL CHECK (cause IN ('signals', 'decay', 'score_quarantine', 'hard_signal_quarantine',
                                                  'manual_quarantine', 'containment_completed', 'clearance')),
  actor_type       TEXT NOT NULL CHECK (actor_type IN ('system', 'user', 'ops')),
  actor_id         TEXT,
  actor_label      TEXT,
  incident_id      TEXT,
  decision_id      TEXT,
  rule_version     TEXT NOT NULL,
  note             TEXT,
  created_at       TEXT NOT NULL
);
CREATE INDEX risk_transitions_subject_time ON risk_transitions (subject_type, subject_id, created_at);
CREATE INDEX risk_transitions_org_time ON risk_transitions (organization_id, created_at);
CREATE TRIGGER risk_transitions_no_update BEFORE UPDATE ON risk_transitions
BEGIN
  SELECT RAISE(ABORT, 'risk transitions are append-only');
END;
CREATE TRIGGER risk_transitions_no_delete BEFORE DELETE ON risk_transitions
BEGIN
  SELECT RAISE(ABORT, 'risk transitions are append-only');
END;

-- One row per decision evaluated under runtime protection. The CHECK is the effective-decision
-- invariant: in monitor mode the effective decision IS the policy decision; in enforce mode it is
-- exactly the most restrictive of the policy and runtime risk decisions, so it can never relax policy.
-- The trigger proves the stored decision row carries that effective decision.
CREATE TABLE risk_evaluations (
  decision_id            TEXT PRIMARY KEY REFERENCES decisions(id),
  organization_id        TEXT NOT NULL,
  engine_version         TEXT NOT NULL,
  mode                   TEXT NOT NULL CHECK (mode IN ('monitor', 'enforce')),
  policy_decision        TEXT NOT NULL CHECK (policy_decision IN ('allow', 'review', 'block')),
  runtime_risk_decision  TEXT NOT NULL CHECK (runtime_risk_decision IN ('allow', 'review', 'block')),
  effective_decision     TEXT NOT NULL CHECK (effective_decision IN ('allow', 'review', 'block')),
  risk_reason_code       TEXT,
  effective_state        TEXT NOT NULL,
  ceiling_subject        TEXT,
  score                  INTEGER NOT NULL DEFAULT 0,
  signal_ids             TEXT NOT NULL DEFAULT '[]',
  claimed_session_id     TEXT,
  claimed_parent_id      TEXT,
  created_at             TEXT NOT NULL,
  CHECK (effective_decision = CASE
    WHEN mode = 'monitor' THEN policy_decision
    WHEN policy_decision = 'block' OR runtime_risk_decision = 'block' THEN 'block'
    WHEN policy_decision = 'review' OR runtime_risk_decision = 'review' THEN 'review'
    ELSE 'allow' END)
);
CREATE INDEX risk_evaluations_org_time ON risk_evaluations (organization_id, created_at);
CREATE TRIGGER risk_evaluations_matches_decision BEFORE INSERT ON risk_evaluations
WHEN NOT EXISTS (
  SELECT 1 FROM decisions d
   WHERE d.id = NEW.decision_id AND d.organization_id = NEW.organization_id AND d.decision = NEW.effective_decision)
BEGIN
  SELECT RAISE(ABORT, 'effective decision does not match the recorded decision');
END;
CREATE TRIGGER risk_evaluations_no_update BEFORE UPDATE ON risk_evaluations
BEGIN
  SELECT RAISE(ABORT, 'risk evaluations are append-only');
END;
CREATE TRIGGER risk_evaluations_no_delete BEFORE DELETE ON risk_evaluations
BEGIN
  SELECT RAISE(ABORT, 'risk evaluations are append-only');
END;

-- Derived from allowed decisions; rebuildable; not evidence.
CREATE TABLE agent_baselines (
  organization_id   TEXT NOT NULL,
  agent_id          TEXT NOT NULL REFERENCES agents(id),
  kind              TEXT NOT NULL CHECK (kind IN ('capability_operation', 'mcp_tool', 'destination')),
  value             TEXT NOT NULL,
  first_allowed_at  TEXT NOT NULL,
  last_allowed_at   TEXT NOT NULL,
  allow_count       INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (agent_id, kind, value)
);

-- The runtime protection mode cannot be lowered while a quarantine is active, so changing the
-- setting is never a way around containment.
CREATE TRIGGER organizations_enforce_sticky BEFORE UPDATE OF runtime_protection ON organizations
WHEN OLD.runtime_protection = 'enforce' AND NEW.runtime_protection <> 'enforce' AND EXISTS (
  SELECT 1 FROM risk_subjects r WHERE r.organization_id = OLD.id AND r.state IN ('quarantined', 'contained'))
BEGIN
  SELECT RAISE(ABORT, 'active quarantine: clear it before leaving enforce');
END;

-- ---------------------------------------------------------------------------
-- Security incidents and their members
-- ---------------------------------------------------------------------------
CREATE TABLE security_incidents (
  id               TEXT PRIMARY KEY,                   -- inc_
  organization_id  TEXT NOT NULL REFERENCES organizations(id),
  subject_type     TEXT NOT NULL CHECK (subject_type IN ('agent', 'session')),
  subject_id       TEXT NOT NULL,
  kind             TEXT NOT NULL DEFAULT 'quarantine' CHECK (kind IN ('quarantine')),
  status           TEXT NOT NULL CHECK (status IN ('open', 'contained', 'cleared')),
  severity         TEXT NOT NULL CHECK (severity IN ('high', 'critical')),
  cause            TEXT NOT NULL CHECK (cause IN ('score_quarantine', 'hard_signal_quarantine', 'manual_quarantine')),
  opened_by_type   TEXT NOT NULL CHECK (opened_by_type IN ('risk_engine', 'user')),
  opened_by        TEXT,
  opened_by_name   TEXT,
  opened_reason    TEXT NOT NULL,
  rule_version     TEXT NOT NULL,
  triggering_decision_id TEXT,
  score            INTEGER NOT NULL DEFAULT 0,
  opened_at        TEXT NOT NULL,
  contained_at     TEXT,
  cleared_at       TEXT,
  cleared_by       TEXT,
  cleared_by_name  TEXT,
  clearance_note   TEXT
);
CREATE INDEX security_incidents_org_status ON security_incidents (organization_id, status, opened_at);
CREATE INDEX security_incidents_subject ON security_incidents (subject_type, subject_id);

CREATE TRIGGER security_incidents_transitions BEFORE UPDATE ON security_incidents
WHEN NOT (
  NEW.id = OLD.id AND NEW.organization_id = OLD.organization_id AND NEW.subject_type = OLD.subject_type
  AND NEW.subject_id = OLD.subject_id AND NEW.kind = OLD.kind AND NEW.cause = OLD.cause
  AND NEW.opened_at = OLD.opened_at AND NEW.opened_reason = OLD.opened_reason
  AND NEW.triggering_decision_id IS OLD.triggering_decision_id
  AND (
    (OLD.status = 'open' AND NEW.status = 'contained' AND NEW.contained_at IS NOT NULL AND NEW.cleared_at IS NULL)
    OR (OLD.status IN ('open', 'contained') AND NEW.status = 'cleared' AND NEW.cleared_at IS NOT NULL
        AND NEW.contained_at IS OLD.contained_at
        AND length(trim(COALESCE(NEW.clearance_note, ''))) >= 10
        AND EXISTS (SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
                     WHERE m.user_id = NEW.cleared_by AND m.organization_id = NEW.organization_id
                       AND m.status = 'active' AND m.role IN ('security', 'admin', 'owner') AND u.kind = 'human'))
  ))
BEGIN
  SELECT RAISE(ABORT, 'invalid incident transition');
END;
CREATE TRIGGER security_incidents_no_delete BEFORE DELETE ON security_incidents
BEGIN
  SELECT RAISE(ABORT, 'incidents are retained');
END;

CREATE TABLE incident_members (
  incident_id      TEXT NOT NULL REFERENCES security_incidents(id),
  organization_id  TEXT NOT NULL,
  member_type      TEXT NOT NULL CHECK (member_type IN ('agent', 'session', 'lease', 'approval', 'decision', 'signal')),
  member_id        TEXT NOT NULL,
  relation         TEXT NOT NULL CHECK (relation IN ('subject', 'scope_session', 'child_agent', 'triggering_decision',
                                                     'triggering_signal', 'revoked_lease', 'cancelled_approval', 'invalidated_grant')),
  created_at       TEXT NOT NULL,
  PRIMARY KEY (incident_id, member_type, member_id, relation)
);
CREATE TRIGGER incident_members_no_update BEFORE UPDATE ON incident_members
BEGIN
  SELECT RAISE(ABORT, 'incident members are append-only');
END;
CREATE TRIGGER incident_members_no_delete BEFORE DELETE ON incident_members
BEGIN
  SELECT RAISE(ABORT, 'incident members are append-only');
END;

-- ---------------------------------------------------------------------------
-- Security alerts: same destination (notification_channels) and sender as approval alerts,
-- separate queue. Queued only when the organization has opted in.
-- ---------------------------------------------------------------------------
CREATE TABLE security_notifications (
  id                TEXT PRIMARY KEY,                  -- snt_
  organization_id   TEXT NOT NULL,
  transition_id     TEXT NOT NULL REFERENCES risk_transitions(id),
  incident_id       TEXT,
  event             TEXT NOT NULL CHECK (event IN ('risk_elevated', 'review_required', 'quarantined',
                                                   'containment_completed', 'cleared')),
  channel           TEXT NOT NULL CHECK (channel IN ('slack')),
  status            TEXT NOT NULL DEFAULT 'QUEUED'
                    CHECK (status IN ('QUEUED', 'SENDING', 'SENT_TO_PROVIDER', 'FAILED', 'SKIPPED')),
  attempts          INTEGER NOT NULL DEFAULT 0,
  max_attempts      INTEGER NOT NULL DEFAULT 3,
  queued_at         TEXT NOT NULL,
  next_attempt_at   TEXT NOT NULL,
  lease_until       TEXT,
  last_attempt_at   TEXT,
  completed_at      TEXT,
  last_http_status  INTEGER,
  last_error        TEXT,
  UNIQUE (transition_id, channel)
);
CREATE INDEX security_notifications_due ON security_notifications (status, next_attempt_at);
CREATE INDEX security_notifications_org_time ON security_notifications (organization_id, queued_at);
CREATE TRIGGER security_notifications_terminal BEFORE UPDATE ON security_notifications
WHEN OLD.status IN ('SENT_TO_PROVIDER', 'FAILED', 'SKIPPED')
  OR NEW.id <> OLD.id OR NEW.organization_id <> OLD.organization_id OR NEW.transition_id <> OLD.transition_id
  OR NEW.event <> OLD.event OR NEW.channel <> OLD.channel OR NEW.queued_at <> OLD.queued_at
  OR NEW.attempts < OLD.attempts OR NEW.attempts > NEW.max_attempts
BEGIN
  SELECT RAISE(ABORT, 'invalid notification transition');
END;
CREATE TRIGGER security_notifications_no_delete BEFORE DELETE ON security_notifications
BEGIN
  SELECT RAISE(ABORT, 'notification records are retained');
END;

CREATE TABLE security_notification_attempts (
  id               TEXT PRIMARY KEY,                   -- sna_
  organization_id  TEXT NOT NULL,
  notification_id  TEXT NOT NULL REFERENCES security_notifications(id),
  attempt          INTEGER NOT NULL,
  started_at       TEXT NOT NULL,
  finished_at      TEXT NOT NULL,
  outcome          TEXT NOT NULL CHECK (outcome IN ('SENT_TO_PROVIDER', 'FAILED', 'ABANDONED')),
  http_status      INTEGER,
  error            TEXT
);
CREATE INDEX security_notification_attempts_notification ON security_notification_attempts (notification_id, attempt);
CREATE TRIGGER security_notification_attempts_no_update BEFORE UPDATE ON security_notification_attempts
BEGIN
  SELECT RAISE(ABORT, 'notification attempts are append-only');
END;
CREATE TRIGGER security_notification_attempts_no_delete BEFORE DELETE ON security_notification_attempts
BEGIN
  SELECT RAISE(ABORT, 'notification attempts are append-only');
END;
