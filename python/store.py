#!/usr/bin/env python3
# ============================================================================
#  store.py — SQLite persistence layer for the Phase-1 platform.
#  ---------------------------------------------------------------------------
#  - deterministic migrations with versioning (schema_version)
#  - WAL mode, foreign keys ON, busy timeout
#  - ALL queries parameterized (no string interpolation of values)
#  - transactions via context manager (commit/rollback)
#  - bounded result retrieval (LIMIT enforced)
#  - safe connection handling (per-operation connections, always closed)
#  - compatible with a future PostgreSQL port: plain SQL, no ORM
#  - NO secrets ever stored; callers must sanitize before insert
# ============================================================================

from __future__ import annotations

import json
from contextlib import closing
import os
import sqlite3

import errors

MIGRATIONS = [
    # v1 — initial schema
    """
    CREATE TABLE organizations (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
      status      TEXT NOT NULL,
      created_at  TEXT NOT NULL,
      updated_at  TEXT NOT NULL
    );
    CREATE TABLE projects (
      id          TEXT PRIMARY KEY,
      org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      status      TEXT NOT NULL,
      scope_json  TEXT NOT NULL DEFAULT '{}',
      created_at  TEXT NOT NULL,
      updated_at  TEXT NOT NULL,
      UNIQUE(org_id, name)
    );
    CREATE INDEX idx_projects_org ON projects(org_id);
    CREATE TABLE assets (
      id          TEXT PRIMARY KEY,
      project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      asset_type  TEXT NOT NULL,
      value       TEXT NOT NULL,
      display     TEXT NOT NULL DEFAULT '',
      metadata    TEXT NOT NULL DEFAULT '{}',
      status      TEXT NOT NULL,
      first_seen  TEXT NOT NULL,
      last_seen   TEXT NOT NULL,
      UNIQUE(project_id, asset_type, value)
    );
    CREATE INDEX idx_assets_project ON assets(project_id);
    CREATE INDEX idx_assets_type ON assets(asset_type);
    CREATE TABLE scans (
      id          TEXT PRIMARY KEY,
      project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      profile     TEXT NOT NULL,
      scope_ref   TEXT NOT NULL DEFAULT '',
      status      TEXT NOT NULL,
      created_at  TEXT NOT NULL,
      started_at  TEXT NOT NULL DEFAULT '',
      finished_at TEXT NOT NULL DEFAULT '',
      initiator   TEXT NOT NULL DEFAULT '{}',
      progress    REAL NOT NULL DEFAULT 0.0,
      stages      TEXT NOT NULL DEFAULT '[]',
      summary     TEXT NOT NULL DEFAULT '{}',
      error       TEXT NOT NULL DEFAULT '{}',
      raw         TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX idx_scans_project ON scans(project_id);
    CREATE INDEX idx_scans_status ON scans(status);
    CREATE TABLE findings (
      id           TEXT PRIMARY KEY,
      scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      asset_id     TEXT REFERENCES assets(id) ON DELETE SET NULL,
      title        TEXT NOT NULL DEFAULT '',
      description  TEXT NOT NULL DEFAULT '',
      severity     TEXT NOT NULL,
      confidence   TEXT NOT NULL DEFAULT 'medium',
      category     TEXT NOT NULL DEFAULT 'other',
      source       TEXT NOT NULL DEFAULT '',
      rule_id      TEXT NOT NULL DEFAULT '',
      template_id  TEXT NOT NULL DEFAULT '',
      cwe          TEXT NOT NULL DEFAULT '',
      cve          TEXT NOT NULL DEFAULT '',
      cvss         TEXT NOT NULL DEFAULT '{}',
      remediation  TEXT NOT NULL DEFAULT '',
      evidence     TEXT NOT NULL DEFAULT '[]',
      raw          TEXT NOT NULL DEFAULT '{}',
      lifecycle    TEXT NOT NULL DEFAULT 'open',
      fingerprint  TEXT NOT NULL,
      first_detected  TEXT NOT NULL,
      last_detected   TEXT NOT NULL,
      resolved_at  TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_findings_project ON findings(project_id);
    CREATE INDEX idx_findings_scan ON findings(scan_id);
    CREATE INDEX idx_findings_asset ON findings(asset_id);
    CREATE INDEX idx_findings_fp ON findings(fingerprint);
    CREATE INDEX idx_findings_sev ON findings(severity);
    CREATE TABLE evidence (
      id            TEXT PRIMARY KEY,
      finding_id    TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      evidence_type TEXT NOT NULL,
      url           TEXT NOT NULL DEFAULT '',
      method        TEXT NOT NULL DEFAULT '',
      status_code   TEXT NOT NULL DEFAULT '',
      request_snippet  TEXT NOT NULL DEFAULT '',
      response_snippet TEXT NOT NULL DEFAULT '',
      detection_reason TEXT NOT NULL DEFAULT '',
      scanner       TEXT NOT NULL DEFAULT '',
      rule_id       TEXT NOT NULL DEFAULT '',
      captured_at   TEXT NOT NULL
    );
    CREATE INDEX idx_evidence_finding ON evidence(finding_id);
    CREATE TABLE audit_events (
      id          TEXT PRIMARY KEY,
      ts          TEXT NOT NULL,
      action      TEXT NOT NULL,
      actor       TEXT NOT NULL DEFAULT 'cli',
      object_type TEXT NOT NULL DEFAULT '',
      object_id   TEXT NOT NULL DEFAULT '',
      org_id      TEXT NOT NULL DEFAULT '',
      project_id  TEXT NOT NULL DEFAULT '',
      metadata    TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX idx_audit_ts ON audit_events(ts);
    CREATE INDEX idx_audit_project ON audit_events(project_id);
    CREATE INDEX idx_audit_action ON audit_events(action);
    """,
    # v2 — Phase 2 identity: users, roles, memberships, API credentials,
    # sessions, password resets + tamper-evident audit chain columns.
    # Existing Phase-1 data is preserved; audit rows written before this
    # migration simply have empty chain hashes (treated as legacy/unguarded).
    """
    CREATE TABLE users (
      id             TEXT PRIMARY KEY,
      org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      username       TEXT NOT NULL,
      email          TEXT NOT NULL COLLATE NOCASE,
      display_name   TEXT NOT NULL DEFAULT '',
      status         TEXT NOT NULL DEFAULT 'active',
      password_hash  TEXT NOT NULL DEFAULT '',
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until   TEXT NOT NULL DEFAULT '',
      created_at     TEXT NOT NULL,
      updated_at     TEXT NOT NULL,
      last_auth_at   TEXT NOT NULL DEFAULT '',
      UNIQUE(org_id, username),
      UNIQUE(email)
    );
    CREATE INDEX idx_users_org ON users(org_id);
    CREATE INDEX idx_users_status ON users(status);
    CREATE TABLE user_roles (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role    TEXT NOT NULL,
      PRIMARY KEY (user_id, role)
    );
    CREATE INDEX idx_user_roles_role ON user_roles(role);
    CREATE TABLE project_members (
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      role       TEXT NOT NULL,
      PRIMARY KEY (user_id, project_id)
    );
    CREATE INDEX idx_members_project ON project_members(project_id);
    CREATE INDEX idx_members_user ON project_members(user_id);
    CREATE TABLE api_credentials (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      project_id   TEXT REFERENCES projects(id) ON DELETE CASCADE,
      name         TEXT NOT NULL,
      key_prefix   TEXT NOT NULL,
      verifier     TEXT NOT NULL,
      scopes       TEXT NOT NULL DEFAULT '[]',
      status       TEXT NOT NULL DEFAULT 'active',
      created_by   TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL,
      last_used_at TEXT NOT NULL DEFAULT '',
      expires_at   TEXT NOT NULL DEFAULT ''
    );
    CREATE UNIQUE INDEX idx_creds_verifier ON api_credentials(verifier);
    CREATE INDEX idx_creds_org ON api_credentials(org_id);
    CREATE INDEX idx_creds_status ON api_credentials(status);
    CREATE TABLE sessions (
      id           TEXT PRIMARY KEY,
      user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash   TEXT NOT NULL UNIQUE,
      ip           TEXT NOT NULL DEFAULT '',
      user_agent   TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      expires_at   TEXT NOT NULL,
      revoked_at   TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_sessions_user ON sessions(user_id);
    CREATE TABLE password_resets (
      id         TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at    TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_resets_user ON password_resets(user_id);
    ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';
    ALTER TABLE audit_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT '';
    """,
    # v3 — Phase 3 orchestration: persistent job queue, stage checkpoints,
    # worker registry. Jobs survive process restart; claiming is atomic via
    # guarded UPDATE (see jobs.py). No secrets in payload columns.
    """
    CREATE TABLE jobs (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      scan_id       TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      job_type      TEXT NOT NULL,
      profile       TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT 'created',
      priority      INTEGER NOT NULL DEFAULT 3,
      attempt       INTEGER NOT NULL DEFAULT 0,
      max_attempts  INTEGER NOT NULL DEFAULT 3,
      active_enabled INTEGER NOT NULL DEFAULT 0,
      timeout_seconds INTEGER NOT NULL DEFAULT 300,
      created_at    TEXT NOT NULL,
      queued_at     TEXT NOT NULL DEFAULT '',
      started_at    TEXT NOT NULL DEFAULT '',
      finished_at   TEXT NOT NULL DEFAULT '',
      heartbeat_at  TEXT NOT NULL DEFAULT '',
      lease_until   TEXT NOT NULL DEFAULT '',
      retry_at      TEXT NOT NULL DEFAULT '',
      worker_id     TEXT NOT NULL DEFAULT '',
      actor_id      TEXT NOT NULL DEFAULT '',
      error_code    TEXT NOT NULL DEFAULT '',
      error_message TEXT NOT NULL DEFAULT '',
      payload       TEXT NOT NULL DEFAULT '{}',
      result_reference TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_jobs_status ON jobs(status);
    CREATE INDEX idx_jobs_org ON jobs(org_id);
    CREATE INDEX idx_jobs_project ON jobs(project_id);
    CREATE INDEX idx_jobs_scan ON jobs(scan_id);
    CREATE INDEX idx_jobs_queue ON jobs(status, priority, queued_at);
    CREATE TABLE scan_stages (
      id           TEXT PRIMARY KEY,
      scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      job_id       TEXT NOT NULL DEFAULT '',
      stage        TEXT NOT NULL,
      status       TEXT NOT NULL DEFAULT 'pending',
      attempt      INTEGER NOT NULL DEFAULT 0,
      started_at   TEXT NOT NULL DEFAULT '',
      finished_at  TEXT NOT NULL DEFAULT '',
      result_reference TEXT NOT NULL DEFAULT '',
      error_code   TEXT NOT NULL DEFAULT '',
      error_message TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL,
      UNIQUE(scan_id, stage)
    );
    CREATE INDEX idx_stages_scan ON scan_stages(scan_id);
    CREATE INDEX idx_stages_status ON scan_stages(status);
    CREATE TABLE workers (
      id            TEXT PRIMARY KEY,
      hostname      TEXT NOT NULL DEFAULT '',
      pid           INTEGER NOT NULL DEFAULT 0,
      status        TEXT NOT NULL DEFAULT 'stopped',
      started_at    TEXT NOT NULL DEFAULT '',
      last_heartbeat TEXT NOT NULL DEFAULT '',
      stopped_at    TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_workers_status ON workers(status);
    """,
    # v4 — Phase 4 intelligence layer (additive only; existing rows stay):
    # asset intelligence (observations/relations), finding canonical identity
    # + lifecycle metadata, confidence/risk, correlation/root-cause/clusters,
    # remediation groups, risk snapshots, scan baselines & diffs.
    # All new writes are parameterized; identifiers are server-side only.
    """
    ALTER TABLE assets ADD COLUMN criticality TEXT NOT NULL DEFAULT 'unknown';
    ALTER TABLE assets ADD COLUMN exposure TEXT NOT NULL DEFAULT 'unknown';
    ALTER TABLE assets ADD COLUMN exposure_reason TEXT NOT NULL DEFAULT '';
    ALTER TABLE assets ADD COLUMN business_impact TEXT NOT NULL DEFAULT '{}';
    ALTER TABLE findings ADD COLUMN confidence_score REAL NOT NULL DEFAULT 0.0;
    ALTER TABLE findings ADD COLUMN confidence_level TEXT NOT NULL DEFAULT 'unverified';
    ALTER TABLE findings ADD COLUMN confidence_reasons TEXT NOT NULL DEFAULT '{}';
    ALTER TABLE findings ADD COLUMN risk_score REAL NOT NULL DEFAULT 0.0;
    ALTER TABLE findings ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'info';
    ALTER TABLE findings ADD COLUMN risk_factors TEXT NOT NULL DEFAULT '{}';
    ALTER TABLE findings ADD COLUMN calc_version TEXT NOT NULL DEFAULT '';
    ALTER TABLE findings ADD COLUMN priority TEXT NOT NULL DEFAULT 'P4';
    ALTER TABLE findings ADD COLUMN priority_order INTEGER NOT NULL DEFAULT 4;
    ALTER TABLE findings ADD COLUMN canonical_key TEXT NOT NULL DEFAULT '';
    ALTER TABLE findings ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE findings ADD COLUMN suppressed_until TEXT NOT NULL DEFAULT '';
    ALTER TABLE findings ADD COLUMN dismissed_reason TEXT NOT NULL DEFAULT '';
    ALTER TABLE findings ADD COLUMN dismissed_by TEXT NOT NULL DEFAULT '';
    ALTER TABLE findings ADD COLUMN reopened_at TEXT NOT NULL DEFAULT '';
    ALTER TABLE findings ADD COLUMN business_impact TEXT NOT NULL DEFAULT '{}';
    ALTER TABLE findings ADD COLUMN exploitability TEXT NOT NULL DEFAULT 'unknown';
    CREATE INDEX idx_findings_canonical ON findings(project_id, canonical_key);
    CREATE UNIQUE INDEX uq_findings_canonical ON findings(project_id, canonical_key)
      WHERE canonical_key <> '';
    CREATE INDEX idx_findings_risk ON findings(project_id, risk_score);
    CREATE INDEX idx_assets_crit ON assets(project_id, criticality);
    CREATE TABLE asset_observations (
      id          TEXT PRIMARY KEY,
      asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      obs_type    TEXT NOT NULL,
      obs_key     TEXT NOT NULL DEFAULT '',
      obs_value   TEXT NOT NULL,
      source      TEXT NOT NULL DEFAULT '',
      confidence  REAL NOT NULL DEFAULT 0.5,
      scan_id     TEXT NOT NULL DEFAULT '',
      extra       TEXT NOT NULL DEFAULT '{}',
      first_seen  TEXT NOT NULL,
      last_seen   TEXT NOT NULL,
      UNIQUE(asset_id, obs_type, obs_key, obs_value, source)
    );
    CREATE INDEX idx_obs_asset ON asset_observations(asset_id);
    CREATE INDEX idx_obs_project_type ON asset_observations(project_id, obs_type);
    CREATE TABLE asset_observation_events (
      id          TEXT PRIMARY KEY,
      asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      obs_type    TEXT NOT NULL,
      obs_key     TEXT NOT NULL DEFAULT '',
      old_value   TEXT NOT NULL DEFAULT '',
      new_value   TEXT NOT NULL,
      source      TEXT NOT NULL DEFAULT '',
      scan_id     TEXT NOT NULL DEFAULT '',
      ts          TEXT NOT NULL
    );
    CREATE INDEX idx_obsevents_asset ON asset_observation_events(asset_id, ts);
    CREATE TABLE asset_relations (
      id          TEXT PRIMARY KEY,
      project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      from_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      to_asset_id   TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      rel_type    TEXT NOT NULL,
      source      TEXT NOT NULL DEFAULT '',
      confidence  REAL NOT NULL DEFAULT 0.5,
      status      TEXT NOT NULL DEFAULT 'active',
      first_seen  TEXT NOT NULL,
      last_seen   TEXT NOT NULL,
      UNIQUE(project_id, from_asset_id, rel_type, to_asset_id, source)
    );
    CREATE INDEX idx_relations_from ON asset_relations(from_asset_id);
    CREATE INDEX idx_relations_to ON asset_relations(to_asset_id);
    CREATE TABLE finding_observations (
      id           TEXT PRIMARY KEY,
      finding_id   TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      scan_id      TEXT NOT NULL DEFAULT '',
      source       TEXT NOT NULL DEFAULT '',
      source_finding_id TEXT NOT NULL DEFAULT '',
      first_seen   TEXT NOT NULL,
      last_seen    TEXT NOT NULL,
      count        INTEGER NOT NULL DEFAULT 1,
      UNIQUE(finding_id, scan_id, source, source_finding_id)
    );
    CREATE INDEX idx_fobs_finding ON finding_observations(finding_id);
    CREATE TABLE risk_snapshots (
      id           TEXT PRIMARY KEY,
      finding_id   TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      ts           TEXT NOT NULL,
      risk_score   REAL NOT NULL,
      risk_level   TEXT NOT NULL,
      severity     TEXT NOT NULL,
      confidence   REAL NOT NULL,
      asset_criticality TEXT NOT NULL DEFAULT 'unknown',
      exposure     TEXT NOT NULL DEFAULT 'unknown',
      calc_version TEXT NOT NULL,
      factors      TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX idx_snapshots_finding ON risk_snapshots(finding_id, ts);
    CREATE TABLE finding_links (
      id           TEXT PRIMARY KEY,
      project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      finding_a_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      finding_b_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      relation_type TEXT NOT NULL,
      rule_id      TEXT NOT NULL DEFAULT '',
      confidence   REAL NOT NULL DEFAULT 0.5,
      created_at   TEXT NOT NULL,
      UNIQUE(finding_a_id, relation_type, finding_b_id, rule_id)
    );
    CREATE INDEX idx_links_a ON finding_links(finding_a_id);
    CREATE INDEX idx_links_b ON finding_links(finding_b_id);
    CREATE TABLE root_causes (
      id           TEXT PRIMARY KEY,
      project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      root_type    TEXT NOT NULL,
      key_value    TEXT NOT NULL DEFAULT '',
      asset_id     TEXT NOT NULL DEFAULT '',
      confidence   REAL NOT NULL DEFAULT 0.5,
      title        TEXT NOT NULL DEFAULT '',
      first_seen   TEXT NOT NULL,
      updated_at   TEXT NOT NULL,
      UNIQUE(project_id, root_type, key_value, asset_id)
    );
    CREATE INDEX idx_roots_project ON root_causes(project_id);
    CREATE TABLE root_cause_findings (
      root_cause_id TEXT NOT NULL REFERENCES root_causes(id) ON DELETE CASCADE,
      finding_id    TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      PRIMARY KEY(root_cause_id, finding_id)
    );
    CREATE TABLE clusters (
      id           TEXT PRIMARY KEY,
      project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      cluster_type TEXT NOT NULL,
      key_value    TEXT NOT NULL DEFAULT '',
      title        TEXT NOT NULL DEFAULT '',
      confidence   REAL NOT NULL DEFAULT 0.5,
      risk_score   REAL NOT NULL DEFAULT 0.0,
      risk_level   TEXT NOT NULL DEFAULT 'info',
      first_seen   TEXT NOT NULL,
      updated_at   TEXT NOT NULL,
      UNIQUE(project_id, cluster_type, key_value)
    );
    CREATE INDEX idx_clusters_project ON clusters(project_id);
    CREATE TABLE cluster_members (
      cluster_id TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
      finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      asset_id   TEXT NOT NULL DEFAULT '',
      PRIMARY KEY(cluster_id, finding_id)
    );
    CREATE TABLE evidence_relations (
      id           TEXT PRIMARY KEY,
      project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      from_type    TEXT NOT NULL,
      from_id      TEXT NOT NULL,
      rel_type     TEXT NOT NULL,
      to_type      TEXT NOT NULL,
      to_id        TEXT NOT NULL,
      confidence   REAL NOT NULL DEFAULT 0.5,
      source       TEXT NOT NULL DEFAULT '',
      reason       TEXT NOT NULL DEFAULT '',
      ts           TEXT NOT NULL,
      UNIQUE(project_id, from_type, from_id, rel_type, to_type, to_id)
    );
    CREATE INDEX idx_evrel_project ON evidence_relations(project_id);
    CREATE INDEX idx_evrel_from ON evidence_relations(from_type, from_id);
    CREATE INDEX idx_evrel_to ON evidence_relations(to_type, to_id);
    CREATE TABLE remediation_groups (
      id          TEXT PRIMARY KEY,
      project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      component   TEXT NOT NULL,
      title       TEXT NOT NULL DEFAULT '',
      first_seen  TEXT NOT NULL,
      updated_at  TEXT NOT NULL,
      UNIQUE(project_id, component)
    );
    CREATE INDEX idx_regroup_project ON remediation_groups(project_id);
    CREATE TABLE remediation_group_findings (
      group_id    TEXT NOT NULL REFERENCES remediation_groups(id) ON DELETE CASCADE,
      finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      PRIMARY KEY(group_id, finding_id)
    );
    CREATE TABLE project_baselines (
      project_id      TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
      baseline_scan_id TEXT NOT NULL,
      current_scan_id TEXT NOT NULL DEFAULT '',
      updated_at      TEXT NOT NULL,
      payload         TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE scan_diffs (
      id         TEXT PRIMARY KEY,
      project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      baseline_scan_id TEXT NOT NULL,
      current_scan_id  TEXT NOT NULL,
      calc_version TEXT NOT NULL,
      summary    TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      UNIQUE(project_id, baseline_scan_id, current_scan_id, calc_version)
    );
    CREATE INDEX idx_diffs_project ON scan_diffs(project_id);
    """,
    # v5 — Phase 5 continuous monitoring (additive only; existing rows stay):
    # monitoring policies + deterministic scheduler executions, monitoring
    # health (separate from security risk), security change events, alert
    # rules/alerts/occurrences/history, notifications + attempts, remediation
    # tickets/history/verification. All new writes parameterized; every new
    # object carries org_id + project_id so tenant isolation walks the chain.
    """
    CREATE TABLE monitoring_policies (
      id              TEXT PRIMARY KEY,
      project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      org_id          TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name            TEXT NOT NULL,
      enabled         INTEGER NOT NULL DEFAULT 1,
      scan_profile    TEXT NOT NULL,
      schedule_type   TEXT NOT NULL,
      interval_minutes INTEGER NOT NULL DEFAULT 0,
      daily_time      TEXT NOT NULL DEFAULT '',
      weekly_day      INTEGER NOT NULL DEFAULT 0,
      weekly_time     TEXT NOT NULL DEFAULT '',
      targets         TEXT NOT NULL DEFAULT '[]',
      scope_json      TEXT NOT NULL DEFAULT '{}',
      active_scan_permitted INTEGER NOT NULL DEFAULT 0,
      priority        TEXT NOT NULL DEFAULT 'normal',
      timeout_minutes INTEGER NOT NULL DEFAULT 0,
      missed_policy   TEXT NOT NULL DEFAULT 'skip',
      max_concurrent  INTEGER NOT NULL DEFAULT 1,
      last_run        TEXT NOT NULL DEFAULT '',
      last_success    TEXT NOT NULL DEFAULT '',
      last_failure    TEXT NOT NULL DEFAULT '',
      consecutive_failures INTEGER NOT NULL DEFAULT 0,
      next_run        TEXT NOT NULL DEFAULT '',
      created_at      TEXT NOT NULL,
      updated_at      TEXT NOT NULL,
      UNIQUE(project_id, name)
    );
    CREATE INDEX idx_policies_project ON monitoring_policies(project_id);
    CREATE INDEX idx_policies_due ON monitoring_policies(enabled, next_run);
    CREATE TABLE monitoring_config (
      project_id   TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
      org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      max_concurrent_scans_per_project INTEGER NOT NULL DEFAULT 2,
      max_concurrent_scans_per_policy  INTEGER NOT NULL DEFAULT 1,
      created_at   TEXT NOT NULL,
      updated_at   TEXT NOT NULL
    );
    CREATE TABLE scheduler_executions (
      id          TEXT PRIMARY KEY,
      project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      policy_id   TEXT NOT NULL REFERENCES monitoring_policies(id) ON DELETE CASCADE,
      scheduled_window TEXT NOT NULL,
      scan_id     TEXT NOT NULL DEFAULT '',
      status      TEXT NOT NULL DEFAULT 'scheduled',
      reason      TEXT NOT NULL DEFAULT '',
      created_at  TEXT NOT NULL,
      finished_at TEXT NOT NULL DEFAULT '',
      UNIQUE(policy_id, scheduled_window)
    );
    CREATE INDEX idx_exec_scan ON scheduler_executions(scan_id);
    CREATE INDEX idx_exec_policy ON scheduler_executions(policy_id, created_at);
    CREATE TABLE monitoring_health (
      project_id     TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
      org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      health         TEXT NOT NULL DEFAULT 'healthy',
      score          REAL NOT NULL DEFAULT 0.0,
      dimensions     TEXT NOT NULL DEFAULT '{}',
      last_success   TEXT NOT NULL DEFAULT '',
      last_failure   TEXT NOT NULL DEFAULT '',
      consecutive_failures INTEGER NOT NULL DEFAULT 0,
      last_change    TEXT NOT NULL DEFAULT '',
      last_alert     TEXT NOT NULL DEFAULT '',
      next_expected_run TEXT NOT NULL DEFAULT '',
      updated_at     TEXT NOT NULL
    );
    CREATE TABLE monitoring_health_history (
      id          TEXT PRIMARY KEY,
      project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      ts          TEXT NOT NULL,
      health      TEXT NOT NULL,
      score       REAL NOT NULL DEFAULT 0.0
    );
    CREATE INDEX idx_health_hist ON monitoring_health_history(project_id, ts);
    CREATE TABLE security_events (
      id            TEXT PRIMARY KEY,
      project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      asset_id      TEXT NOT NULL DEFAULT '',
      event_type    TEXT NOT NULL,
      source        TEXT NOT NULL DEFAULT '',
      ts            TEXT NOT NULL,
      previous_state TEXT NOT NULL DEFAULT '{}',
      new_state     TEXT NOT NULL DEFAULT '{}',
      confidence    REAL NOT NULL DEFAULT 0.5,
      scan_id       TEXT NOT NULL DEFAULT '',
      state_key     TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_events_project ON security_events(project_id, ts);
    CREATE INDEX idx_events_type ON security_events(event_type);
    CREATE TABLE alert_rules (
      id               TEXT PRIMARY KEY,
      project_id       TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      org_id           TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name             TEXT NOT NULL,
      enabled          INTEGER NOT NULL DEFAULT 1,
      event_type       TEXT NOT NULL DEFAULT '',
      condition        TEXT NOT NULL DEFAULT '{}',
      severity         TEXT NOT NULL DEFAULT 'medium',
      cooldown_minutes INTEGER NOT NULL DEFAULT 60,
      group_by         TEXT NOT NULL DEFAULT 'none',
      notify           INTEGER NOT NULL DEFAULT 1,
      created_at       TEXT NOT NULL,
      updated_at       TEXT NOT NULL
    );
    CREATE INDEX idx_rules_project ON alert_rules(project_id, enabled);
    CREATE TABLE alerts (
      id              TEXT PRIMARY KEY,
      project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      org_id          TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      rule_id         TEXT NOT NULL DEFAULT '',
      identity_key    TEXT NOT NULL,
      event_type      TEXT NOT NULL DEFAULT '',
      asset_id        TEXT NOT NULL DEFAULT '',
      finding_id      TEXT NOT NULL DEFAULT '',
      fingerprint     TEXT NOT NULL DEFAULT '',
      group_key       TEXT NOT NULL DEFAULT '',
      title           TEXT NOT NULL DEFAULT '',
      severity        TEXT NOT NULL DEFAULT 'medium',
      state           TEXT NOT NULL DEFAULT 'open',
      occurrence_count INTEGER NOT NULL DEFAULT 1,
      first_seen      TEXT NOT NULL,
      last_seen       TEXT NOT NULL,
      last_notified_at TEXT NOT NULL DEFAULT '',
      cooldown_until  TEXT NOT NULL DEFAULT '',
      suppressed_until TEXT NOT NULL DEFAULT '',
      resolved_at     TEXT NOT NULL DEFAULT '',
      created_at      TEXT NOT NULL,
      updated_at      TEXT NOT NULL,
      UNIQUE(identity_key)
    );
    CREATE INDEX idx_alerts_project ON alerts(project_id, state);
    CREATE INDEX idx_alerts_fp ON alerts(fingerprint);
    CREATE TABLE alert_occurrences (
      id           TEXT PRIMARY KEY,
      alert_id     TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
      event_id     TEXT NOT NULL DEFAULT '',
      occurrence_number INTEGER NOT NULL DEFAULT 1,
      ts           TEXT NOT NULL,
      state_snapshot TEXT NOT NULL DEFAULT '{}',
      UNIQUE(alert_id, event_id)
    );
    CREATE INDEX idx_alertocc_alert ON alert_occurrences(alert_id, ts);
    CREATE TABLE alert_events (
      id         TEXT PRIMARY KEY,
      alert_id   TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
      actor      TEXT NOT NULL DEFAULT '',
      action     TEXT NOT NULL,
      ts         TEXT NOT NULL,
      reason     TEXT NOT NULL DEFAULT '',
      metadata   TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX idx_alertev_alert ON alert_events(alert_id, ts);
    CREATE TABLE notification_settings (
      project_id     TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
      org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      email_enabled  INTEGER NOT NULL DEFAULT 0,
      email_to       TEXT NOT NULL DEFAULT '',
      webhook_enabled INTEGER NOT NULL DEFAULT 0,
      webhook_url    TEXT NOT NULL DEFAULT '',
      webhook_secret TEXT NOT NULL DEFAULT '',
      updated_at     TEXT NOT NULL
    );
    CREATE TABLE notifications (
      id            TEXT PRIMARY KEY,
      project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      alert_id      TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
      occurrence_event_id TEXT NOT NULL DEFAULT '',
      channel       TEXT NOT NULL,
      provider_key  TEXT NOT NULL DEFAULT '',
      status        TEXT NOT NULL DEFAULT 'pending',
      attempts      INTEGER NOT NULL DEFAULT 0,
      next_retry_at TEXT NOT NULL DEFAULT '',
      last_error    TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL,
      updated_at    TEXT NOT NULL,
      sent_at       TEXT NOT NULL DEFAULT '',
      UNIQUE(project_id, occurrence_event_id, channel)
    );
    CREATE INDEX idx_notif_status ON notifications(status, next_retry_at);
    CREATE INDEX idx_notif_alert ON notifications(alert_id);
    CREATE TABLE notification_attempts (
      id             TEXT PRIMARY KEY,
      notification_id TEXT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
      attempt_n      INTEGER NOT NULL DEFAULT 1,
      ts             TEXT NOT NULL,
      outcome        TEXT NOT NULL DEFAULT '',
      error          TEXT NOT NULL DEFAULT '',
      duration_ms    REAL NOT NULL DEFAULT 0.0,
      UNIQUE(notification_id, attempt_n)
    );
    CREATE INDEX idx_natt_notif ON notification_attempts(notification_id);
    CREATE TABLE remediation_tickets (
      id              TEXT PRIMARY KEY,
      project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      org_id          TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      remediation_group_id TEXT NOT NULL DEFAULT '',
      title           TEXT NOT NULL DEFAULT '',
      owner_type      TEXT NOT NULL DEFAULT '',
      owner_id        TEXT NOT NULL DEFAULT '',
      owner_name      TEXT NOT NULL DEFAULT '',
      status          TEXT NOT NULL DEFAULT 'open',
      priority        TEXT NOT NULL DEFAULT 'P4',
      due_at          TEXT NOT NULL DEFAULT '',
      created_at      TEXT NOT NULL,
      updated_at      TEXT NOT NULL,
      resolved_at     TEXT NOT NULL DEFAULT '',
      verification_status TEXT NOT NULL DEFAULT 'pending',
      verification_scan_id TEXT NOT NULL DEFAULT '',
      verification_attempts INTEGER NOT NULL DEFAULT 0,
      UNIQUE(finding_id)
    );
    CREATE INDEX idx_tickets_project ON remediation_tickets(project_id, status);
    CREATE INDEX idx_tickets_due ON remediation_tickets(status, due_at);
    CREATE TABLE remediation_history (
      id        TEXT PRIMARY KEY,
      ticket_id TEXT NOT NULL REFERENCES remediation_tickets(id) ON DELETE CASCADE,
      actor     TEXT NOT NULL DEFAULT '',
      action    TEXT NOT NULL,
      ts        TEXT NOT NULL,
      detail    TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX idx_thist_ticket ON remediation_history(ticket_id, ts);
    CREATE TABLE verification_requests (
      id            TEXT PRIMARY KEY,
      ticket_id     TEXT NOT NULL REFERENCES remediation_tickets(id) ON DELETE CASCADE,
      scan_id       TEXT NOT NULL DEFAULT '',
      requested_by  TEXT NOT NULL DEFAULT '',
      requested_at  TEXT NOT NULL,
      completed_at  TEXT NOT NULL DEFAULT '',
      status        TEXT NOT NULL DEFAULT 'pending',
      note          TEXT NOT NULL DEFAULT '',
      UNIQUE(ticket_id, scan_id)
    );
    CREATE INDEX idx_vreq_ticket ON verification_requests(ticket_id);
    CREATE INDEX idx_vreq_scan ON verification_requests(scan_id);
    CREATE TABLE remediation_sla (
      project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
      org_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      sla_json   TEXT NOT NULL DEFAULT '{}',
      updated_at TEXT NOT NULL
    );
    """,
    # ------------------------------------------------------------------
    # Phase 6 — reporting + compliance-evidence layer (snapshot based).
    # report_runs: report metadata + integrity fields only (payloads are
    # stored intentionally, see report_payloads). compliance_evidence rows
    # carry provenance for every evidence mapping; the immutable evidence
    # SNAPSHOTS live in report_payloads (immutable=1) and are never touched
    # by retention. No secrets anywhere in these tables.
    # ------------------------------------------------------------------
    """
    CREATE TABLE report_runs (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      report_type   TEXT NOT NULL,
      title         TEXT NOT NULL DEFAULT '',
      status        TEXT NOT NULL DEFAULT 'generated',
      schema_version TEXT NOT NULL DEFAULT '',
      risk_version  TEXT NOT NULL DEFAULT '',
      data_cutoff   TEXT NOT NULL DEFAULT '',
      report_hash   TEXT NOT NULL DEFAULT '',
      generated_at  TEXT NOT NULL,
      generated_by  TEXT NOT NULL DEFAULT '',
      truncated     INTEGER NOT NULL DEFAULT 0,
      truncation_reason TEXT NOT NULL DEFAULT '',
      original_count    INTEGER NOT NULL DEFAULT 0,
      included_count    INTEGER NOT NULL DEFAULT 0,
      byte_size     INTEGER NOT NULL DEFAULT 0,
      immutable     INTEGER NOT NULL DEFAULT 0,
      created_at    TEXT NOT NULL
    );
    CREATE INDEX idx_report_runs_project ON report_runs(project_id, created_at);
    CREATE INDEX idx_report_runs_type ON report_runs(report_type, created_at);
    CREATE TABLE report_payloads (
      report_id    TEXT PRIMARY KEY REFERENCES report_runs(id) ON DELETE CASCADE,
      payload      TEXT NOT NULL,
      payload_hash TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL
    );
    CREATE TABLE compliance_evidence (
      id             TEXT PRIMARY KEY,
      org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      control_category TEXT NOT NULL,
      source_type    TEXT NOT NULL,
      source_id      TEXT NOT NULL DEFAULT '',
      evidence_ts    TEXT NOT NULL DEFAULT '',
      data_cutoff    TEXT NOT NULL DEFAULT '',
      description    TEXT NOT NULL DEFAULT '',
      status         TEXT NOT NULL,
      counts         TEXT NOT NULL DEFAULT '{}',
      evidence_hash  TEXT NOT NULL DEFAULT '',
      created_at     TEXT NOT NULL,
      updated_at     TEXT NOT NULL,
      UNIQUE(project_id, control_category, source_type, source_id)
    );
    CREATE INDEX idx_evidence_project ON compliance_evidence(project_id,
                                                             control_category);
    """,
    # v14 — Phase 7 DevSecOps: security gates, CI runs, gate results.
    # NOTE on immutability: gate_results.run_id/gate_id are PLAIN TEXT (no
    # FK + no cascade) — deleting a gate or retaining/sweeping CI runs must
    # never cascade into historical result snapshots. Gate results are
    # immutable evidence (policy frozen at evaluation time).
    """
    CREATE TABLE security_gates (
      id             TEXT PRIMARY KEY,
      project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name           TEXT NOT NULL,
      enabled        INTEGER NOT NULL DEFAULT 1,
      policy         TEXT NOT NULL DEFAULT '{}',
      policy_version INTEGER NOT NULL DEFAULT 1,
      policy_hash    TEXT NOT NULL DEFAULT '',
      created_by     TEXT NOT NULL DEFAULT '',
      created_at     TEXT NOT NULL,
      updated_at     TEXT NOT NULL
    );
    CREATE INDEX idx_gates_project ON security_gates(project_id, enabled);
    CREATE TABLE ci_runs (
      id             TEXT PRIMARY KEY,
      project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      gate_id        TEXT NOT NULL DEFAULT '',
      provider       TEXT NOT NULL,
      repository     TEXT NOT NULL DEFAULT '',
      branch         TEXT NOT NULL DEFAULT '',
      commit_sha     TEXT NOT NULL DEFAULT '',
      commit_ref     TEXT NOT NULL DEFAULT '',
      pipeline_id    TEXT NOT NULL DEFAULT '',
      pipeline_url   TEXT NOT NULL DEFAULT '',
      actor          TEXT NOT NULL DEFAULT '',
      trigger        TEXT NOT NULL DEFAULT 'manual',
      profile        TEXT NOT NULL DEFAULT '',
      target         TEXT NOT NULL DEFAULT '',
      idempotency_key TEXT NOT NULL UNIQUE,
      status         TEXT NOT NULL DEFAULT 'created',
      scan_id        TEXT NOT NULL DEFAULT '',
      job_id         TEXT NOT NULL DEFAULT '',
      result_id      TEXT NOT NULL DEFAULT '',
      error          TEXT NOT NULL DEFAULT '',
      started_at     TEXT NOT NULL DEFAULT '',
      finished_at    TEXT NOT NULL DEFAULT '',
      created_at     TEXT NOT NULL
    );
    CREATE INDEX idx_ci_runs_project ON ci_runs(project_id, created_at);
    CREATE INDEX idx_ci_runs_gate ON ci_runs(gate_id, created_at);
    CREATE TABLE gate_results (
      id             TEXT PRIMARY KEY,
      run_id         TEXT NOT NULL DEFAULT '',
      gate_id        TEXT NOT NULL DEFAULT '',
      project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      scan_id        TEXT NOT NULL DEFAULT '',
      status         TEXT NOT NULL,
      reason         TEXT NOT NULL DEFAULT '',
      summary        TEXT NOT NULL DEFAULT '{}',
      violations     TEXT NOT NULL DEFAULT '[]',
      annotations    TEXT NOT NULL DEFAULT '[]',
      policy         TEXT NOT NULL DEFAULT '{}',
      policy_version INTEGER NOT NULL DEFAULT 1,
      policy_hash    TEXT NOT NULL DEFAULT '',
      result_hash    TEXT NOT NULL DEFAULT '',
      result_version TEXT NOT NULL DEFAULT 'gate-v1',
      ci_context     TEXT NOT NULL DEFAULT '{}',
      created_at     TEXT NOT NULL,
      immutable      INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX idx_gate_results_project ON gate_results(project_id, created_at);
    CREATE INDEX idx_gate_results_run ON gate_results(run_id);
    CREATE INDEX idx_gate_results_status ON gate_results(status, created_at);
    """,
    # v15 — Phase 8 enterprise identity: MFA, recovery codes, SSO (OIDC/SAML),
    # SCIM provisioning, identity lifecycle + session hardening + telemetry.
    # Extends existing users/sessions (ALTER) — no new identity model is
    # created; every new row references the EXISTING users/organizations.
    # Secrets at rest follow the existing convention (notify._encrypt_secret
    # key-file wrap for TOTP seeds / SSO client secrets; SCIM credentials are
    # verifier-only like API credentials).
    """
    ALTER TABLE users ADD COLUMN login_count INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN last_mfa_at TEXT NOT NULL DEFAULT '';
    ALTER TABLE users ADD COLUMN deactivated_at TEXT NOT NULL DEFAULT '';
    ALTER TABLE users ADD COLUMN mfa_reenroll_required INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sessions ADD COLUMN auth_method TEXT NOT NULL DEFAULT '';
    ALTER TABLE sessions ADD COLUMN mfa_status TEXT NOT NULL DEFAULT 'none';
    ALTER TABLE sessions ADD COLUMN step_up_until TEXT NOT NULL DEFAULT '';
    ALTER TABLE sessions ADD COLUMN idp_subject TEXT NOT NULL DEFAULT '';
    ALTER TABLE sessions ADD COLUMN provider_id TEXT NOT NULL DEFAULT '';
    ALTER TABLE sessions ADD COLUMN absolute_expires_at TEXT NOT NULL DEFAULT '';
    ALTER TABLE sessions ADD COLUMN revoke_reason TEXT NOT NULL DEFAULT '';
    ALTER TABLE api_credentials ADD COLUMN purpose TEXT NOT NULL DEFAULT '';
    CREATE INDEX idx_sessions_expires ON sessions(expires_at);
    CREATE INDEX idx_sessions_status ON sessions(revoked_at, expires_at);

    CREATE TABLE mfa_secrets (
      user_id        TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      seed_enc       TEXT NOT NULL,
      digits         INTEGER NOT NULL DEFAULT 6,
      step           INTEGER NOT NULL DEFAULT 30,
      algorithm      TEXT NOT NULL DEFAULT 'SHA1',
      label          TEXT NOT NULL DEFAULT '',
      last_used_step INTEGER NOT NULL DEFAULT -1,
      attempts       INTEGER NOT NULL DEFAULT 0,
      locked_until   TEXT NOT NULL DEFAULT '',
      enabled        INTEGER NOT NULL DEFAULT 0,
      created_at     TEXT NOT NULL,
      verified_at    TEXT NOT NULL DEFAULT '',
      updated_at     TEXT NOT NULL,
      created_by     TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_mfa_org ON mfa_secrets(org_id, enabled);

    CREATE TABLE mfa_recovery_codes (
      id         TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      salt       TEXT NOT NULL,
      code_hmac  TEXT NOT NULL,
      used_at    TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );
    CREATE INDEX idx_recovery_user ON mfa_recovery_codes(user_id, used_at);

    CREATE TABLE mfa_policy (
      org_id            TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
      mode              TEXT NOT NULL DEFAULT 'optional',
      roles             TEXT NOT NULL DEFAULT '[]',
      step_up_ttl       INTEGER NOT NULL DEFAULT 600,
      require_recent    INTEGER NOT NULL DEFAULT 900,
      version           INTEGER NOT NULL DEFAULT 1,
      updated_at        TEXT NOT NULL,
      updated_by        TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE sso_providers (
      id             TEXT PRIMARY KEY,
      org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      provider_type  TEXT NOT NULL,
      enabled        INTEGER NOT NULL DEFAULT 0,
      display_name   TEXT NOT NULL,
      config         TEXT NOT NULL DEFAULT '{}',
      version        INTEGER NOT NULL DEFAULT 1,
      jit            INTEGER NOT NULL DEFAULT 0,
      default_roles  TEXT NOT NULL DEFAULT '[]',
      created_at     TEXT NOT NULL,
      updated_at     TEXT NOT NULL,
      created_by     TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_sso_providers_org ON sso_providers(org_id, enabled);

    CREATE TABLE sso_provider_history (
      id          TEXT PRIMARY KEY,
      provider_id TEXT NOT NULL,
      org_id      TEXT NOT NULL,
      version     INTEGER NOT NULL,
      change_type TEXT NOT NULL,
      diff        TEXT NOT NULL DEFAULT '{}',
      changed_by  TEXT NOT NULL DEFAULT '',
      changed_at  TEXT NOT NULL
    );
    CREATE INDEX idx_sso_history ON sso_provider_history(provider_id, version);

    CREATE TABLE sso_domains (
      id         TEXT PRIMARY KEY,
      org_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      provider_id TEXT NOT NULL DEFAULT '',
      domain     TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      created_by TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_sso_domains_org ON sso_domains(org_id);

    CREATE TABLE sso_identities (
      id         TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      org_id     TEXT NOT NULL,
      provider_id TEXT NOT NULL,
      subject    TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      last_login_at TEXT NOT NULL DEFAULT '',
      UNIQUE(provider_id, subject),
      UNIQUE(user_id, provider_id)
    );
    CREATE INDEX idx_sso_identities_user ON sso_identities(user_id);
    CREATE INDEX idx_sso_identities_org ON sso_identities(org_id);

    CREATE TABLE idp_state (
      state         TEXT PRIMARY KEY,
      provider_id   TEXT NOT NULL,
      org_id        TEXT NOT NULL,
      nonce         TEXT NOT NULL,
      code_challenge TEXT NOT NULL DEFAULT '',
      code_method   TEXT NOT NULL DEFAULT '',
      redirect_uri  TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL,
      expires_at    TEXT NOT NULL,
      used_at       TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_idp_state_expires ON idp_state(expires_at);

    CREATE TABLE group_role_mappings (
      id          TEXT PRIMARY KEY,
      org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      provider_id TEXT NOT NULL DEFAULT '',
      idp_group   TEXT NOT NULL,
      role        TEXT NOT NULL,
      created_at  TEXT NOT NULL,
      updated_at  TEXT NOT NULL,
      created_by  TEXT NOT NULL DEFAULT '',
      UNIQUE(org_id, provider_id, idp_group)
    );
    CREATE INDEX idx_grm_org ON group_role_mappings(org_id);
    CREATE INDEX idx_grm_provider ON group_role_mappings(provider_id);

    CREATE TABLE scim_credentials (
      id          TEXT PRIMARY KEY,
      org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      key_prefix  TEXT NOT NULL,
      verifier    TEXT NOT NULL,
      max_role    TEXT NOT NULL DEFAULT 'analyst',
      status      TEXT NOT NULL DEFAULT 'active',
      created_by  TEXT NOT NULL DEFAULT '',
      created_at  TEXT NOT NULL,
      last_used_at TEXT NOT NULL DEFAULT '',
      expires_at  TEXT NOT NULL DEFAULT '',
      revoked_at  TEXT NOT NULL DEFAULT '',
      revoked_by  TEXT NOT NULL DEFAULT ''
    );
    CREATE UNIQUE INDEX idx_scim_verifier ON scim_credentials(verifier);
    CREATE INDEX idx_scim_org ON scim_credentials(org_id, status);

    CREATE TABLE identity_events (
      id         TEXT PRIMARY KEY,
      org_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      actor      TEXT NOT NULL DEFAULT '',
      event_type TEXT NOT NULL,
      detail     TEXT NOT NULL DEFAULT '{}',
      ts         TEXT NOT NULL
    );
    CREATE INDEX idx_identity_events_org ON identity_events(org_id, ts);
    CREATE INDEX idx_identity_events_type ON identity_events(event_type, ts);

    CREATE TABLE saml_replay (
      id       TEXT PRIMARY KEY,
      digest   TEXT NOT NULL UNIQUE,
      ts       TEXT NOT NULL
    );
    CREATE INDEX idx_saml_replay_ts ON saml_replay(ts);
    """,
    # v16 — Phase 8 SCIM 2.0 resources: tenant-scoped external-identifier
    # bindings. SCIM reuses the EXISTING users / user_roles tables (no second
    # user or group model); these tables only bind a client's external ids to
    # platform rows and track optimistic versions.
    """
    CREATE TABLE scim_users (
      org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      external_id TEXT NOT NULL,
      user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      version     INTEGER NOT NULL DEFAULT 1,
      created_at  TEXT NOT NULL,
      updated_at  TEXT NOT NULL,
      PRIMARY KEY (org_id, external_id)
    );
    CREATE INDEX idx_scim_users_user ON scim_users(user_id);
    CREATE TABLE scim_groups (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      external_id  TEXT NOT NULL,
      display_name TEXT NOT NULL,
      role         TEXT NOT NULL,
      version      INTEGER NOT NULL DEFAULT 1,
      created_at   TEXT NOT NULL,
      updated_at   TEXT NOT NULL,
      UNIQUE(org_id, external_id)
    );
    CREATE INDEX idx_scim_groups_org ON scim_groups(org_id);
    CREATE TABLE scim_group_members (
      group_id TEXT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
      user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (group_id, user_id)
    );
    CREATE INDEX idx_scim_members_user ON scim_group_members(user_id);
    """,
    # v11 (list slot) — Phase 8 break-glass administration: explicitly
    # invoked, reason-required, short-lived emergency access grants. A grant
    # is a token (hashed at rest, revocable, single-active-per-actor+org)
    # bound to (actor, org) that acts as a verified step-up context; it
    # NEVER grants permissions the actor does not already hold and is fully
    # audited. New list entry (not appended to #10) so existing databases
    # at schema_version 10 apply it via the standard migration loop.
    """
    CREATE TABLE break_glass_grants (
      id                 TEXT PRIMARY KEY,
      org_id             TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason             TEXT NOT NULL,
      token_hash         TEXT NOT NULL,
      created_at         TEXT NOT NULL,
      expires_at         TEXT NOT NULL,
      last_seen_at       TEXT NOT NULL DEFAULT '',
      ended_at           TEXT NOT NULL DEFAULT '',
      end_reason         TEXT NOT NULL DEFAULT '',
      created_by_session TEXT NOT NULL DEFAULT ''
    );
    CREATE UNIQUE INDEX idx_bg_hash ON break_glass_grants(token_hash);
    CREATE INDEX idx_bg_org ON break_glass_grants(org_id, ended_at);
    CREATE INDEX idx_bg_user ON break_glass_grants(user_id, ended_at);
    """,
    # v11 — Phase 9 cloud/container/Kubernetes/IaC security. Only the
    # REGISTRATION entities are new; every discovered asset, finding,
    # evidence, risk and remediation reuses the EXISTING tables (no second
    # asset/finding model). All rows are tenant-bound (org_id cascade).
    """
    CREATE TABLE cloud_accounts (
      id               TEXT PRIMARY KEY,
      org_id           TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      provider         TEXT NOT NULL,
      account_identifier TEXT NOT NULL,
      display_name     TEXT NOT NULL DEFAULT '',
      enabled          INTEGER NOT NULL DEFAULT 1,
      region_scope     TEXT NOT NULL DEFAULT '[]',
      credential_ref   TEXT NOT NULL DEFAULT '',
      credential_enc   TEXT NOT NULL DEFAULT '',
      credential_hint  TEXT NOT NULL DEFAULT '',
      status           TEXT NOT NULL DEFAULT 'active',
      last_inventory_at TEXT NOT NULL DEFAULT '',
      last_scan_at     TEXT NOT NULL DEFAULT '',
      created_by       TEXT NOT NULL DEFAULT '',
      created_at       TEXT NOT NULL,
      updated_at       TEXT NOT NULL,
      UNIQUE(org_id, provider, account_identifier)
    );
    CREATE INDEX idx_cloud_acct_org ON cloud_accounts(org_id, enabled);

    CREATE TABLE container_images (
      id          TEXT PRIMARY KEY,
      org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      registry    TEXT NOT NULL DEFAULT '',
      repository  TEXT NOT NULL,
      digest      TEXT NOT NULL,
      tags        TEXT NOT NULL DEFAULT '[]',
      metadata    TEXT NOT NULL DEFAULT '{}',
      package_count INTEGER NOT NULL DEFAULT 0,
      vuln_count  INTEGER NOT NULL DEFAULT 0,
      created_at  TEXT NOT NULL,
      scanned_at  TEXT NOT NULL DEFAULT '',
      UNIQUE(org_id, repository, digest)
    );
    CREATE INDEX idx_container_org ON container_images(org_id, repository);

    CREATE TABLE kubernetes_clusters (
      id          TEXT PRIMARY KEY,
      org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      provider    TEXT NOT NULL DEFAULT 'k8s',
      api_ref     TEXT NOT NULL DEFAULT '',
      context     TEXT NOT NULL DEFAULT '{}',
      created_at  TEXT NOT NULL,
      scanned_at  TEXT NOT NULL DEFAULT '',
      UNIQUE(org_id, name)
    );
    CREATE INDEX idx_k8s_org ON kubernetes_clusters(org_id, name);

    CREATE TABLE iac_scans (
      id             TEXT PRIMARY KEY,
      org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      scan_id        TEXT NOT NULL DEFAULT '',
      source_name    TEXT NOT NULL DEFAULT '',
      file_name      TEXT NOT NULL DEFAULT '',
      format         TEXT NOT NULL DEFAULT 'auto',
      files_parsed   INTEGER NOT NULL DEFAULT 0,
      resource_count INTEGER NOT NULL DEFAULT 0,
      secret_count   INTEGER NOT NULL DEFAULT 0,
      finding_count  INTEGER NOT NULL DEFAULT 0,
      status         TEXT NOT NULL DEFAULT 'completed',
      error_code     TEXT NOT NULL DEFAULT '',
      created_by     TEXT NOT NULL DEFAULT '',
      created_at     TEXT NOT NULL
    );
    CREATE INDEX idx_iac_org ON iac_scans(org_id, created_at);
    CREATE INDEX idx_iac_project ON iac_scans(project_id, created_at);
    """,
    # v12 — Phase 10 Security Operations / Threat Intelligence: IOC catalog,
    # IOC-match ledger, investigation cases, case references & timeline,
    # threat clusters. Every row is tenant-scoped (org_id / project_id
    # columns + FK cascade). Threat matches reference EXISTING findings
    # (this is a correlation ledger, not a second finding system);
    # cases reference existing findings/assets/observations/IOCs/evidence/
    # alerts/remediation — no duplicated evidence.
    """
    CREATE TABLE threat_indicators (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      indicator    TEXT NOT NULL,
      ioc_type     TEXT NOT NULL,
      source       TEXT NOT NULL,
      confidence   REAL NOT NULL DEFAULT 0.5,
      confidence_level TEXT NOT NULL DEFAULT 'unknown',
      status       TEXT NOT NULL DEFAULT 'active',
      first_seen   TEXT NOT NULL,
      last_seen    TEXT NOT NULL,
      valid_from   TEXT NOT NULL DEFAULT '',
      valid_until  TEXT NOT NULL DEFAULT '',
      reference    TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL,
      updated_at   TEXT NOT NULL,
      UNIQUE(org_id, ioc_type, indicator, source)
    );
    CREATE INDEX idx_ti_org ON threat_indicators(org_id, status);
    CREATE INDEX idx_ti_value ON threat_indicators(indicator, ioc_type);
    CREATE INDEX idx_ti_type ON threat_indicators(ioc_type, status);
    CREATE INDEX idx_ti_expiry ON threat_indicators(valid_until);

    CREATE TABLE threat_matches (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      indicator_id TEXT NOT NULL REFERENCES threat_indicators(id)
                   ON DELETE CASCADE,
      finding_id   TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
      asset_id     TEXT NOT NULL DEFAULT '',
      ioc_type     TEXT NOT NULL,
      matched_on   TEXT NOT NULL DEFAULT '',
      fingerprint  TEXT NOT NULL,
      first_seen   TEXT NOT NULL,
      last_seen    TEXT NOT NULL,
      match_count  INTEGER NOT NULL DEFAULT 1,
      status       TEXT NOT NULL DEFAULT 'active',
      UNIQUE(indicator_id, finding_id)
    );
    CREATE INDEX idx_tm_finding ON threat_matches(finding_id);
    CREATE INDEX idx_tm_indicator ON threat_matches(indicator_id, status);
    CREATE INDEX idx_tm_org ON threat_matches(org_id, first_seen);
    CREATE INDEX idx_tm_asset ON threat_matches(asset_id);

    CREATE TABLE investigation_cases (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      title         TEXT NOT NULL,
      description   TEXT NOT NULL DEFAULT '',
      status        TEXT NOT NULL DEFAULT 'open',
      priority      TEXT NOT NULL DEFAULT 'medium',
      owner         TEXT NOT NULL DEFAULT '',
      created_by    TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL,
      updated_at    TEXT NOT NULL,
      closed_at     TEXT NOT NULL DEFAULT '',
      closed_reason TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_cases_org ON investigation_cases(org_id, status);
    CREATE INDEX idx_cases_project ON investigation_cases(project_id,
                                                          updated_at);
    CREATE INDEX idx_cases_owner ON investigation_cases(owner, status);

    CREATE TABLE case_refs (
      id         TEXT PRIMARY KEY,
      case_id    TEXT NOT NULL REFERENCES investigation_cases(id)
                 ON DELETE CASCADE,
      org_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      ref_type   TEXT NOT NULL,
      ref_id     TEXT NOT NULL,
      note       TEXT NOT NULL DEFAULT '',
      created_by TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      UNIQUE(case_id, ref_type, ref_id)
    );
    CREATE INDEX idx_case_refs_case ON case_refs(case_id);
    CREATE INDEX idx_case_refs_ref ON case_refs(ref_type, ref_id);

    CREATE TABLE case_timeline (
      id         TEXT PRIMARY KEY,
      case_id    TEXT NOT NULL REFERENCES investigation_cases(id)
                 ON DELETE CASCADE,
      org_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      entry_type TEXT NOT NULL,
      entry      TEXT NOT NULL DEFAULT '',
      ref_type   TEXT NOT NULL DEFAULT '',
      ref_id     TEXT NOT NULL DEFAULT '',
      actor      TEXT NOT NULL DEFAULT 'system',
      ts         TEXT NOT NULL
    );
    CREATE INDEX idx_ct_case ON case_timeline(case_id, ts);
    CREATE INDEX idx_ct_org ON case_timeline(org_id, ts);

    CREATE TABLE threat_clusters (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id)
                   ON DELETE CASCADE,
      project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      cluster_key  TEXT NOT NULL,
      label        TEXT NOT NULL,
      kind         TEXT NOT NULL DEFAULT 'related_activity',
      member_count INTEGER NOT NULL DEFAULT 0,
      first_seen   TEXT NOT NULL,
      last_seen    TEXT NOT NULL,
      created_at   TEXT NOT NULL,
      updated_at   TEXT NOT NULL,
      UNIQUE(project_id, cluster_key)
    );
    CREATE INDEX idx_tc_org ON threat_clusters(org_id, last_seen);

    CREATE TABLE threat_cluster_members (
      id         TEXT PRIMARY KEY,
      cluster_id TEXT NOT NULL REFERENCES threat_clusters(id)
                 ON DELETE CASCADE,
      org_id     TEXT NOT NULL REFERENCES organizations(id)
                 ON DELETE CASCADE,
      ref_type   TEXT NOT NULL,
      ref_id     TEXT NOT NULL,
      added_at   TEXT NOT NULL,
      UNIQUE(cluster_id, ref_type, ref_id)
    );
    CREATE INDEX idx_tcm_cluster ON threat_cluster_members(cluster_id);
    CREATE INDEX idx_tcm_ref ON threat_cluster_members(ref_type, ref_id);
    """,
    # v13 — Phase 11 data protection / privacy / governance. Additive only
    # (no existing table is altered). All rows tenant-scoped; every write
    # surface reuses the EXISTING audit chain (no second audit system).
    # NOTE: secrets_registry NEVER stores secret material — only a search
    # hash (sha256) for deterministic dedup, clearly distinguished from the
    # platform's existing decryptable credential storage (notify.py
    # encryption, scim creds, cloud credential_enc columns).
    """
    CREATE TABLE data_classifications (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL DEFAULT '',
      project_id   TEXT NOT NULL DEFAULT '',
      object_type  TEXT NOT NULL,
      object_id    TEXT NOT NULL DEFAULT '',
      field_name   TEXT NOT NULL DEFAULT '',
      classification TEXT NOT NULL,
      provenance   TEXT NOT NULL DEFAULT 'manual',
      created_by   TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL,
      updated_at   TEXT NOT NULL,
      UNIQUE(org_id, project_id, object_type, object_id, field_name)
    );
    CREATE INDEX idx_class_org ON data_classifications(org_id, object_type);
    CREATE INDEX idx_class_obj ON data_classifications(object_type, object_id);

    CREATE TABLE secrets_registry (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id)
                   ON DELETE CASCADE,
      project_id   TEXT NOT NULL DEFAULT '',
      kind         TEXT NOT NULL,
      name         TEXT NOT NULL DEFAULT '',
      reference    TEXT NOT NULL DEFAULT '',
      search_hash  TEXT NOT NULL,
      status       TEXT NOT NULL DEFAULT 'active',
      created_by   TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL,
      last_used_at TEXT NOT NULL DEFAULT '',
      expires_at   TEXT NOT NULL DEFAULT '',
      rotation_due_at TEXT NOT NULL DEFAULT '',
      revoked_at   TEXT NOT NULL DEFAULT '',
      updated_at   TEXT NOT NULL,
      UNIQUE(org_id, kind, search_hash)
    );
    CREATE INDEX idx_secrets_org ON secrets_registry(org_id, status);
    CREATE INDEX idx_secrets_expiry ON secrets_registry(org_id, expires_at);
    CREATE INDEX idx_secrets_rotation ON secrets_registry(org_id,
                                                          rotation_due_at);

    CREATE TABLE retention_policies (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id)
                   ON DELETE CASCADE,
      project_id   TEXT NOT NULL DEFAULT '',
      kind         TEXT NOT NULL,
      days         INTEGER NOT NULL,
      enabled      INTEGER NOT NULL DEFAULT 1,
      created_by   TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL,
      updated_at   TEXT NOT NULL,
      UNIQUE(org_id, project_id, kind)
    );
    CREATE INDEX idx_retpol_org ON retention_policies(org_id, kind, enabled);

    CREATE TABLE retention_holds (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id)
                   ON DELETE CASCADE,
      project_id   TEXT NOT NULL DEFAULT '',
      object_type  TEXT NOT NULL,
      object_id    TEXT NOT NULL DEFAULT '',
      kind         TEXT NOT NULL DEFAULT 'other',
      reason       TEXT NOT NULL DEFAULT '',
      created_by   TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL,
      expires_at   TEXT NOT NULL DEFAULT '',
      released_at  TEXT NOT NULL DEFAULT '',
      released_by  TEXT NOT NULL DEFAULT '',
      release_reason TEXT NOT NULL DEFAULT '',
      updated_at   TEXT NOT NULL,
      UNIQUE(org_id, object_type, object_id, kind)
    );
    CREATE INDEX idx_holds_active ON retention_holds(org_id, released_at);
    CREATE INDEX idx_holds_obj ON retention_holds(object_type, object_id);

    CREATE TABLE retention_runs (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id)
                   ON DELETE CASCADE,
      project_id   TEXT NOT NULL DEFAULT '',
      kind         TEXT NOT NULL,
      mode         TEXT NOT NULL DEFAULT 'preview',
      status       TEXT NOT NULL DEFAULT 'completed',
      actor        TEXT NOT NULL DEFAULT '',
      before_count INTEGER NOT NULL DEFAULT 0,
      deleted_count INTEGER NOT NULL DEFAULT 0,
      held_count   INTEGER NOT NULL DEFAULT 0,
      error_count  INTEGER NOT NULL DEFAULT 0,
      metadata     TEXT NOT NULL DEFAULT '{}',
      started_at   TEXT NOT NULL,
      finished_at  TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_retrun_org ON retention_runs(org_id, started_at);

    CREATE TABLE privacy_requests (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id)
                   ON DELETE CASCADE,
      project_id   TEXT NOT NULL DEFAULT '',
      request_type TEXT NOT NULL,
      subject_ref  TEXT NOT NULL DEFAULT '',
      scope        TEXT NOT NULL DEFAULT '{}',
      status       TEXT NOT NULL DEFAULT 'submitted',
      requester    TEXT NOT NULL DEFAULT '',
      reviewer     TEXT NOT NULL DEFAULT '',
      failure_reason TEXT NOT NULL DEFAULT '',
      completion_evidence TEXT NOT NULL DEFAULT '{}',
      created_at   TEXT NOT NULL,
      updated_at   TEXT NOT NULL,
      completed_at TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_privacy_org ON privacy_requests(org_id, status);
    CREATE UNIQUE INDEX idx_privacy_ident ON privacy_requests(
      org_id, request_type, subject_ref, requester, status);

    CREATE TABLE data_exports (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id)
                   ON DELETE CASCADE,
      project_id   TEXT NOT NULL DEFAULT '',
      scope        TEXT NOT NULL DEFAULT '{}',
      format       TEXT NOT NULL DEFAULT 'json',
      item_count   INTEGER NOT NULL DEFAULT 0,
      byte_size    INTEGER NOT NULL DEFAULT 0,
      sha256       TEXT NOT NULL DEFAULT '',
      created_by   TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL,
      expires_at   TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_exports_org ON data_exports(org_id, created_at);

    CREATE TABLE policy_exceptions (
      id           TEXT PRIMARY KEY,
      org_id       TEXT NOT NULL REFERENCES organizations(id)
                   ON DELETE CASCADE,
      project_id   TEXT NOT NULL DEFAULT '',
      policy       TEXT NOT NULL,
      scope        TEXT NOT NULL DEFAULT '',
      reason       TEXT NOT NULL DEFAULT '',
      created_by   TEXT NOT NULL DEFAULT '',
      approved_by  TEXT NOT NULL DEFAULT '',
      created_at   TEXT NOT NULL,
      expires_at   TEXT NOT NULL DEFAULT '',
      status       TEXT NOT NULL DEFAULT 'active',
      revoked_at   TEXT NOT NULL DEFAULT '',
      revoked_by   TEXT NOT NULL DEFAULT '',
      updated_at   TEXT NOT NULL
    );
    CREATE INDEX idx_exceptions_org ON policy_exceptions(org_id, status);
    CREATE INDEX idx_exceptions_exp ON policy_exceptions(expires_at);
    """,
    # v14 — Phase 12 federation / evidence exchange / bulk operations /
    # external integrations. Additive only (no existing table altered).
    # All rows tenant-scoped (org_id); every write surface reuses the
    # EXISTING audit chain, rate limiter, job engine and retention engine.
    # NOTE: federation_packages.payload holds ONLY minimized + redacted
    # package objects (never secret material — the package builder runs
    # the Phase-11 redaction engine before serialization). external_
    # integrations store an endpoint URL (https-only, SSRF-validated at
    # send time by the EXISTING notify.validate_webhook_url) and NEVER
    # credential material.
    """
    CREATE TABLE federation_peers (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      peer_org_id   TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      name          TEXT NOT NULL,
      purpose       TEXT NOT NULL DEFAULT '',
      direction     TEXT NOT NULL DEFAULT 'outbound',
      status        TEXT NOT NULL DEFAULT 'pending',
      created_by    TEXT NOT NULL DEFAULT '',
      approved_by   TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL,
      updated_at    TEXT NOT NULL,
      expires_at    TEXT NOT NULL DEFAULT '',
      suspended_at  TEXT NOT NULL DEFAULT '',
      revoked_at    TEXT NOT NULL DEFAULT '',
      revoked_by    TEXT NOT NULL DEFAULT '',
      revoke_reason TEXT NOT NULL DEFAULT '',
      UNIQUE(org_id, peer_org_id, name)
    );
    CREATE INDEX idx_fedpeers_org ON federation_peers(org_id, status);
    CREATE INDEX idx_fedpeers_peer ON federation_peers(peer_org_id, status);
    CREATE INDEX idx_fedpeers_exp ON federation_peers(expires_at);

    CREATE TABLE federation_policies (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      peer_id       TEXT NOT NULL REFERENCES federation_peers(id)
                    ON DELETE CASCADE,
      project_id    TEXT NOT NULL DEFAULT '',
      name          TEXT NOT NULL,
      allowed_object_types TEXT NOT NULL DEFAULT '[]',
      allowed_classifications TEXT NOT NULL DEFAULT '[]',
      allowed_fields TEXT NOT NULL DEFAULT '{}',
      max_objects   INTEGER NOT NULL DEFAULT 1000,
      explicit_sensitive INTEGER NOT NULL DEFAULT 0,
      status        TEXT NOT NULL DEFAULT 'active',
      created_by    TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL,
      updated_at    TEXT NOT NULL,
      expires_at    TEXT NOT NULL DEFAULT '',
      disabled_at   TEXT NOT NULL DEFAULT '',
      UNIQUE(org_id, peer_id, name)
    );
    CREATE INDEX idx_fedpolicies_org ON federation_policies(org_id, status);
    CREATE INDEX idx_fedpolicies_peer ON federation_policies(peer_id);
    CREATE INDEX idx_fedpolicies_exp ON federation_policies(expires_at);

    CREATE TABLE federation_packages (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      project_id    TEXT NOT NULL DEFAULT '',
      peer_id       TEXT NOT NULL DEFAULT '',
      policy_id     TEXT NOT NULL DEFAULT '',
      destination_org_id TEXT NOT NULL DEFAULT '',
      schema_version TEXT NOT NULL,
      classification TEXT NOT NULL DEFAULT 'internal',
      object_count  INTEGER NOT NULL DEFAULT 0,
      byte_size     INTEGER NOT NULL DEFAULT 0,
      integrity_algorithm TEXT NOT NULL DEFAULT 'sha256',
      integrity_hash TEXT NOT NULL,
      trust_mode    TEXT NOT NULL DEFAULT 'integrity_verified',
      external_signature_ref TEXT NOT NULL DEFAULT '',
      payload       TEXT NOT NULL DEFAULT '{}',
      status        TEXT NOT NULL DEFAULT 'created',
      created_by    TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL,
      expires_at    TEXT NOT NULL DEFAULT '',
      purged_at     TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_fedpackages_org ON federation_packages(org_id,
                                                             created_at);
    CREATE INDEX idx_fedpackages_dest ON
      federation_packages(destination_org_id, created_at);
    CREATE INDEX idx_fedpackages_peer ON federation_packages(peer_id);

    CREATE TABLE federation_imports (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      package_id    TEXT NOT NULL DEFAULT '',
      package_hash  TEXT NOT NULL,
      source_org_id TEXT NOT NULL DEFAULT '',
      peer_id       TEXT NOT NULL DEFAULT '',
      policy_id     TEXT NOT NULL DEFAULT '',
      target_project_id TEXT NOT NULL DEFAULT '',
      status        TEXT NOT NULL DEFAULT 'completed',
      collision_strategy TEXT NOT NULL DEFAULT 'skip',
      object_count  INTEGER NOT NULL DEFAULT 0,
      imported_count INTEGER NOT NULL DEFAULT 0,
      skipped_count INTEGER NOT NULL DEFAULT 0,
      linked_count  INTEGER NOT NULL DEFAULT 0,
      detail_json   TEXT NOT NULL DEFAULT '{}',
      error         TEXT NOT NULL DEFAULT '',
      created_by    TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL,
      updated_at    TEXT NOT NULL,
      UNIQUE(org_id, package_hash)
    );
    CREATE INDEX idx_fedimports_org ON federation_imports(org_id, created_at);
    CREATE INDEX idx_fedimports_status ON federation_imports(status);

    CREATE TABLE external_integrations (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      project_id    TEXT NOT NULL DEFAULT '',
      name          TEXT NOT NULL,
      kind          TEXT NOT NULL,
      endpoint_url  TEXT NOT NULL DEFAULT '',
      status        TEXT NOT NULL DEFAULT 'enabled',
      created_by    TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL,
      updated_at    TEXT NOT NULL,
      disabled_at   TEXT NOT NULL DEFAULT '',
      last_delivery_at TEXT NOT NULL DEFAULT '',
      UNIQUE(org_id, project_id, name)
    );
    CREATE INDEX idx_integrations_org ON external_integrations(org_id,
                                                               status);

    CREATE TABLE integration_events (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      project_id    TEXT NOT NULL DEFAULT '',
      integration_id TEXT NOT NULL REFERENCES external_integrations(id)
                    ON DELETE CASCADE,
      event_type    TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT 'sent',
      payload_sha256 TEXT NOT NULL DEFAULT '',
      byte_size     INTEGER NOT NULL DEFAULT 0,
      provider_outcome TEXT NOT NULL DEFAULT '',
      error         TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL
    );
    CREATE INDEX idx_integration_events_org ON integration_events(org_id,
                                                                  created_at);
    CREATE INDEX idx_integration_events_iid ON
      integration_events(integration_id, created_at);
    """,
    # v15 — Phase 13 enterprise security integrations & external event
    # pipeline. MINIMUM schema expansion, decided after full inspection of
    # the Phase-12 tables:
    #   * NO second connection table — external_integrations already owns
    #     connection identity (org/project/name/kind/endpoint/status); it is
    #     EXTENDED IN PLACE via ALTER ADD COLUMN with constant defaults only
    #     (safe on existing rows; every Phase-12 read/write path in
    #     federation.py uses explicit column lists, verified). credential_ref
    #     points at the Phase-11 secrets_registry (reference semantics, like
    #     its own `reference` column) — NO plaintext secret material is ever
    #     stored here or in any table below.
    #   * integration_events REMAINS the canonical high-level emission record
    #     (unchanged). integration_deliveries is created because it is a
    #     distinct lifecycle: job-backed outbound delivery state machine with
    #     attempts/retry scheduling/error taxonomy (mirrors jobs column
    #     naming) — not a duplicate event body.
    #   * integration_inbound_events persists the inbound ingestion lifecycle
    #     (provider-facing event identity, normalization reference). Payload
    #     BODIES are never stored — only payload_sha256 (canonical hash
    #     column name from integration_events) + bounded byte_size.
    #   * integration_replay_claims provides the DB-ENFORCED idempotency
    #     boundary UNIQUE(provider, integration_id, external_event_id,
    #     payload_sha256). The existing saml_replay table (id/digest/ts) is
    #     SAML-assertion specific and cannot express this boundary. org_id is
    #     deliberately NOT part of the UNIQUE: integration_id is a globally
    #     unique PRIMARY KEY already org-scoped via its FK, so including
    #     org_id would only WEAKEN dedup (same tuple claimable under two
    #     orgs); cross-tenant safety comes from tenant resolution at the
    #     service boundary (tenant is never self-selected by the request) +
    #     the org_id NOT NULL FK cascade below. status distinguishes the
    #     four §19 states: INSERT success = new claim; UNIQUE conflict +
    #     completed_at set = duplicate completed; conflict + both timestamps
    #     empty = duplicate in-progress; conflict + failed_at set =
    #     previously failed. Non-empty status values are restricted by the
    #     service layer to the closed models.INTEGRATION_INBOUND_STATUSES
    #     subset ('accepted' = completed, 'failed' = failed); '' is the
    #     repo-standard absent sentinel (precedent: provider_outcome
    #     DEFAULT '') meaning in-progress — the store never invents states.
    #   * Circuit-breaker columns live on external_integrations (bounded
    #     local state, cascade-deleted with the integration): circuit_state
    #     defaults to 'closed' from models.CIRCUIT_BREAKER_STATES.
    #   * Optional relations follow the established convention: plain TEXT
    #     NOT NULL DEFAULT '' without FK (precedent: federation_packages
    #     .peer_id); required relations get REFERENCES ... ON DELETE CASCADE.
    #   * Indexes are bounded to real access patterns (org listing,
    #     per-integration health, retry scan, job linkage); the replay UNIQUE
    #     already covers provider/integration/external-event lookups, so no
    #     redundant index is created for them.
    """
    ALTER TABLE external_integrations ADD COLUMN
      connector_kind TEXT NOT NULL DEFAULT '';
    ALTER TABLE external_integrations ADD COLUMN
      provider TEXT NOT NULL DEFAULT '';
    ALTER TABLE external_integrations ADD COLUMN
      auth_mode TEXT NOT NULL DEFAULT '';
    ALTER TABLE external_integrations ADD COLUMN
      credential_ref TEXT NOT NULL DEFAULT '';
    ALTER TABLE external_integrations ADD COLUMN
      config_json TEXT NOT NULL DEFAULT '{}';
    ALTER TABLE external_integrations ADD COLUMN
      health_state TEXT NOT NULL DEFAULT '';
    ALTER TABLE external_integrations ADD COLUMN
      last_health_check_at TEXT NOT NULL DEFAULT '';
    ALTER TABLE external_integrations ADD COLUMN
      circuit_state TEXT NOT NULL DEFAULT 'closed';
    ALTER TABLE external_integrations ADD COLUMN
      circuit_opened_at TEXT NOT NULL DEFAULT '';
    ALTER TABLE external_integrations ADD COLUMN
      circuit_failure_count INTEGER NOT NULL DEFAULT 0;

    CREATE TABLE integration_deliveries (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      project_id    TEXT NOT NULL DEFAULT '',
      integration_id TEXT NOT NULL REFERENCES external_integrations(id)
                    ON DELETE CASCADE,
      event_id      TEXT NOT NULL DEFAULT '',
      external_event_id TEXT NOT NULL DEFAULT '',
      status        TEXT NOT NULL DEFAULT 'queued',
      attempt       INTEGER NOT NULL DEFAULT 0,
      max_attempts  INTEGER NOT NULL DEFAULT 1,
      queued_at     TEXT NOT NULL DEFAULT '',
      started_at    TEXT NOT NULL DEFAULT '',
      completed_at  TEXT NOT NULL DEFAULT '',
      next_attempt_at TEXT NOT NULL DEFAULT '',
      payload_sha256 TEXT NOT NULL DEFAULT '',
      byte_size     INTEGER NOT NULL DEFAULT 0,
      provider_outcome TEXT NOT NULL DEFAULT '',
      error_code    TEXT NOT NULL DEFAULT '',
      error_class   TEXT NOT NULL DEFAULT '',
      retryable     INTEGER NOT NULL DEFAULT 0,
      job_id        TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL,
      updated_at    TEXT NOT NULL
    );
    CREATE INDEX idx_intdeliveries_org ON integration_deliveries(org_id,
                                                                 created_at);
    CREATE INDEX idx_intdeliveries_iid ON
      integration_deliveries(integration_id, status);
    CREATE INDEX idx_intdeliveries_retry ON
      integration_deliveries(status, next_attempt_at);
    CREATE INDEX idx_intdeliveries_job ON integration_deliveries(job_id);

    CREATE TABLE integration_inbound_events (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      project_id    TEXT NOT NULL DEFAULT '',
      integration_id TEXT NOT NULL REFERENCES external_integrations(id)
                    ON DELETE CASCADE,
      provider      TEXT NOT NULL DEFAULT '',
      external_event_id TEXT NOT NULL DEFAULT '',
      event_type    TEXT NOT NULL,
      event_time    TEXT NOT NULL DEFAULT '',
      received_at   TEXT NOT NULL,
      payload_sha256 TEXT NOT NULL DEFAULT '',
      byte_size     INTEGER NOT NULL DEFAULT 0,
      status        TEXT NOT NULL DEFAULT 'accepted',
      source_reference TEXT NOT NULL DEFAULT '',
      normalized_reference TEXT NOT NULL DEFAULT '',
      error         TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL
    );
    CREATE INDEX idx_intinbound_org ON
      integration_inbound_events(org_id, received_at);
    CREATE INDEX idx_intinbound_iid ON
      integration_inbound_events(integration_id, received_at);

    CREATE TABLE integration_replay_claims (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      provider      TEXT NOT NULL,
      integration_id TEXT NOT NULL REFERENCES external_integrations(id)
                    ON DELETE CASCADE,
      external_event_id TEXT NOT NULL,
      payload_sha256 TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT '',
      claimed_at    TEXT NOT NULL,
      completed_at  TEXT NOT NULL DEFAULT '',
      failed_at     TEXT NOT NULL DEFAULT '',
      result_reference TEXT NOT NULL DEFAULT '',
      created_at    TEXT NOT NULL,
      updated_at    TEXT NOT NULL,
      UNIQUE(provider, integration_id, external_event_id, payload_sha256)
    );
    CREATE INDEX idx_intclaims_org ON integration_replay_claims(org_id,
                                                                created_at);
    CREATE INDEX idx_intclaims_iid ON
      integration_replay_claims(integration_id, created_at);
    """,
    # v16 — HTTP idempotency records for customer-facing write endpoints.
    # The client key is SHA-256 hashed, response bodies contain only safe
    # resource references, and expired records are bounded by the service.
    """
    CREATE TABLE api_idempotency_records (
      id            TEXT PRIMARY KEY,
      org_id        TEXT NOT NULL REFERENCES organizations(id)
                    ON DELETE CASCADE,
      scope         TEXT NOT NULL,
      key_hash      TEXT NOT NULL,
      request_hash  TEXT NOT NULL,
      state         TEXT NOT NULL DEFAULT 'in_progress',
      status_code   INTEGER NOT NULL DEFAULT 0,
      response_json TEXT NOT NULL DEFAULT '{}',
      created_at    TEXT NOT NULL,
      updated_at    TEXT NOT NULL,
      expires_at    TEXT NOT NULL,
      UNIQUE(org_id, scope, key_hash)
    );
    CREATE INDEX idx_api_idempotency_expiry
      ON api_idempotency_records(expires_at);
    CREATE INDEX idx_api_idempotency_scope
      ON api_idempotency_records(org_id, scope, created_at);
    """,
    # v17 — persisted customer organization locale/timezone preferences.
    # Defaults remain explicit in the service when no preference row exists.
    """
    CREATE TABLE organization_preferences (
      org_id     TEXT PRIMARY KEY REFERENCES organizations(id)
                 ON DELETE CASCADE,
      timezone   TEXT NOT NULL DEFAULT 'UTC',
      locale     TEXT NOT NULL DEFAULT 'en',
      updated_at TEXT NOT NULL
    );
    """,
]


class Database:
    """Small, safe SQLite wrapper. One connection per operation (context
    managers close them); transactions are explicit context managers."""

    def __init__(self, path: str):
        self.path = str(path)
        if not self.path:
            raise errors.ConfigurationError("Database path is empty")
        self._check_sqlite_file()

    def _check_sqlite_file(self):
        """Be sure the target is a regular file (or placeholder) — never an
        arbitrary path (SSRF/FS-tamper guard at the storage layer)."""
        if os.path.exists(self.path) and not os.path.isfile(self.path):
            raise errors.PersistenceError(
                f"Database path is not a regular file: {self.path}")

    def connect(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(self.path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA busy_timeout = 10000")
            return conn
        except sqlite3.Error as e:
            raise errors.PersistenceError(f"Cannot open database: {e}") from e

    def migrate(self):
        """Apply pending migrations, tracked in schema_version."""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".",
                        exist_ok=True)
            with closing(self.connect()) as conn:
                with conn:
                    conn.execute(
                        "CREATE TABLE IF NOT EXISTS schema_version "
                        "(version INTEGER NOT NULL)")
                    row = conn.execute(
                        "SELECT MAX(version) AS v FROM schema_version").fetchone()
                    current = row["v"] or 0
                    for i, sql in enumerate(MIGRATIONS, start=1):
                        if i > current:
                            conn.executescript(sql)
                            conn.execute(
                                "INSERT INTO schema_version(version) VALUES (?)",
                                (i,))
        except sqlite3.Error as e:
            raise errors.PersistenceError(f"Migration failed: {e}") from e

    def transaction(self):
        return _Tx(self)

    # --- generic helpers -----------------------------------------------------
    def execute(self, sql: str, params: tuple = ()):
        with closing(self.connect()) as conn:
            with conn:
                cur = conn.execute(sql, params)
                return cur.lastrowid

    def execute_affected(self, sql: str, params: tuple = ()) -> int:
        """Execute and return the affected row count — used for atomic
        guarded transitions (e.g. job claiming). Raises on failure."""
        with closing(self.connect()) as conn:
            with conn:
                cur = conn.execute(sql, params)
                return cur.rowcount

    def query(self, sql: str, params: tuple = (), limit: int | None = None):
        if limit is not None:
            if not isinstance(limit, int) or limit < 1 or limit > 10000:
                raise errors.ValidationError(
                    f"Invalid query limit: {limit}")
            sql = sql.rstrip().rstrip(";")
            low = sql.lower()
            if " limit " not in low:
                sql += " LIMIT ?"
                params = tuple(params) + (limit,)
        with closing(self.connect()) as conn:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def query_one(self, sql: str, params: tuple = ()):
        rows = self.query(sql, params, limit=2)
        if not rows:
            raise errors.NotFoundError(f"No record for: {sql[:60]}")
        if len(rows) > 1:
            raise errors.PersistenceError("Expected one row, found multiple")
        return rows[0]

    def upsert(self, table: str, record: dict) -> str:
        """INSERT ... ON CONFLICT(id) DO UPDATE — idempotent writes."""
        cols = list(record.keys())
        placeholders = ",".join("?" for _ in cols)
        updates = ",".join(f"{c}=excluded.{c}" for c in cols if c != "id")
        sql = (f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders}) "
               f"ON CONFLICT(id) DO UPDATE SET {updates}")
        with closing(self.connect()) as conn:
            with conn:
                conn.execute(sql, tuple(record.values()))
        return record["id"]

    def delete(self, table: str, record_id: str):
        with closing(self.connect()) as conn:
            with conn:
                conn.execute(f"DELETE FROM {table} WHERE id = ?", (record_id,))


class _Tx:
    """Explicit transaction context manager."""

    def __init__(self, db: Database):
        self.db = db

    def __enter__(self):
        self.conn = self.db.connect()
        self.conn.execute("BEGIN")
        return self.conn

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
        finally:
            self.conn.close()
        return False


# ---------------------------------------------------------------------------
# JSON column helpers (safe encoders — no secrets decision here, callers
# pass already-sanitized structures; `store` must never invent data)
# ---------------------------------------------------------------------------
def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str, separators=(",", ":"))


def loads(text: str, default=None):
    if not text:
        return default if default is not None else {}
    try:
        return json.loads(text)
    except Exception:
        return default if default is not None else {}

