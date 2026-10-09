import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactElement } from "react";
import { ApiError, apiClient, newIdempotencyKey } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useWorkspace } from "../app/App";

interface Envelope<T> {
  data: T;
  count?: number;
}

interface ScanProfile {
  name: string;
  description: string;
  stages: string[];
  active_required: boolean;
  timeout: number;
  in_process: boolean;
  permissions_required: string[];
  api_supported: boolean;
}

interface ScanJob {
  id: string;
  status: string;
  attempt: number;
  max_attempts: number;
  error_code: string;
  created_at: string;
  started_at: string;
  finished_at: string;
}

interface ScanRow {
  id: string;
  project_id: string;
  profile: string;
  scope_ref: string;
  status: string;
  created_at: string;
  started_at: string;
  finished_at: string;
  progress: number;
  stages: Array<{ stage: string; status: string; error_code: string }>;
  summary: Record<string, string | number | boolean>;
  error_code: string;
  jobs: ScanJob[];
}

interface ListPanel<T> {
  rows: T[];
  error: string;
}

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "The request could not be completed.";
}

function dateTime(value: string): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function statusClass(value: string): string {
  const normalized = value.toLowerCase().replace(/[^a-z0-9_-]/g, "");
  return `status-pill status-${normalized || "unknown"}`;
}

function boundedProgress(value: number): number {
  return Number.isFinite(value) ? Math.round(Math.max(0, Math.min(1, value)) * 100) : 0;
}

export function ScansPage(): ReactElement {
  const { project } = useWorkspace();
  const { hasPermission } = useAuth();
  const [profiles, setProfiles] = useState<ListPanel<ScanProfile>>({ rows: [], error: "" });
  const [scans, setScans] = useState<ListPanel<ScanRow>>({ rows: [], error: "" });
  const [profilesLoading, setProfilesLoading] = useState(true);
  const [scansLoading, setScansLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("");
  const [profileName, setProfileName] = useState("");
  const [target, setTarget] = useState("");
  const [payloadText, setPayloadText] = useState("{}");
  const [activeEnabled, setActiveEnabled] = useState(false);
  const [selectedId, setSelectedId] = useState("");
  const [selectedScan, setSelectedScan] = useState<ScanRow | null>(null);
  const [selectedError, setSelectedError] = useState("");
  const [formError, setFormError] = useState("");
  const [actionError, setActionError] = useState("");
  const [creating, setCreating] = useState(false);
  const [actionBusy, setActionBusy] = useState("");

  const supportedProfiles = useMemo(() => profiles.rows.filter((profile) => profile.api_supported), [profiles.rows]);
  const selectedProfile = supportedProfiles.find((profile) => profile.name === profileName) ?? null;

  const loadProfiles = useCallback(async (signal?: AbortSignal): Promise<void> => {
    setProfilesLoading(true);
    try {
      const result = await apiClient.get<Envelope<ScanProfile[]>>("/api/v1/scan-profiles", signal ? { signal } : {});
      const rows = Array.isArray(result.data) ? result.data : [];
      setProfiles({ rows, error: "" });
      setProfileName((current) => rows.some((profile) => profile.name === current && profile.api_supported)
        ? current
        : (rows.find((profile) => profile.api_supported)?.name ?? ""));
    } catch (error) {
      if (!signal?.aborted) setProfiles({ rows: [], error: errorMessage(error) });
    } finally {
      if (!signal?.aborted) setProfilesLoading(false);
    }
  }, []);

  const loadScans = useCallback(async (signal?: AbortSignal): Promise<void> => {
    const query = new URLSearchParams({ limit: "100" });
    if (statusFilter) query.set("status", statusFilter);
    try {
      const result = await apiClient.get<Envelope<ScanRow[]>>(
        `/api/v1/projects/${encodeURIComponent(project.id)}/scans?${query.toString()}`,
        signal ? { signal } : {},
      );
      setScans({ rows: Array.isArray(result.data) ? result.data : [], error: "" });
    } catch (error) {
      if (!signal?.aborted) setScans({ rows: [], error: errorMessage(error) });
    } finally {
      if (!signal?.aborted) setScansLoading(false);
    }
  }, [project.id, statusFilter]);

  useEffect(() => {
    const controller = new AbortController();
    void loadProfiles(controller.signal);
    return () => controller.abort();
  }, [loadProfiles]);

  useEffect(() => {
    const controller = new AbortController();
    void loadScans(controller.signal);
    const interval = window.setInterval(() => void loadScans(controller.signal), 10_000);
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [loadScans]);

  async function createScan(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!selectedProfile) {
      setFormError("Choose a profile exposed by the current scan API.");
      return;
    }
    setCreating(true);
    setFormError("");
    try {
      let payload: unknown;
      try {
        payload = JSON.parse(payloadText) as unknown;
      } catch {
        setFormError("Payload must be valid JSON.");
        return;
      }
      if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
        setFormError("Payload must be a JSON object.");
        return;
      }
      const requestBody: Record<string, unknown> = {
        profile: selectedProfile.name,
        payload,
        active_enabled: selectedProfile.active_required ? activeEnabled : false,
        max_attempts: 3,
        timeout_seconds: Math.max(1, Math.min(selectedProfile.timeout || 60, 3600)),
      };
      if (!selectedProfile.in_process) requestBody["target"] = target.trim();
      await apiClient.post(
        `/api/v1/projects/${encodeURIComponent(project.id)}/scans`,
        requestBody,
        { idempotencyKey: newIdempotencyKey() },
      );
      setTarget("");
      setPayloadText("{}");
      setActiveEnabled(false);
      await loadScans();
    } catch (error) {
      setFormError(errorMessage(error));
    } finally {
      setCreating(false);
    }
  }

  async function inspectScan(scanId: string): Promise<void> {
    setSelectedId(scanId);
    setSelectedScan(null);
    setSelectedError("");
    try {
      const response = await apiClient.get<Envelope<ScanRow>>(`/api/v1/scans/${encodeURIComponent(scanId)}`);
      setSelectedScan(response.data);
    } catch (error) {
      setSelectedScan(null);
      setSelectedError(errorMessage(error));
    }
  }

  async function performAction(scan: ScanRow, action: "pause" | "resume" | "cancel"): Promise<void> {
    setActionBusy(scan.id + action);
    setActionError("");
    try {
      await apiClient.post(`/api/v1/scans/${encodeURIComponent(scan.id)}/${action}`, {});
      await loadScans();
      if (selectedId === scan.id) await inspectScan(scan.id);
    } catch (error) {
      setActionError(errorMessage(error));
    } finally {
      setActionBusy("");
    }
  }

  const allowedStatuses = ["pending", "queued", "running", "paused", "cancelling", "completed", "failed", "cancelled"];

  return (
    <div className="page-stack">
      <section className="page-heading page-heading-row">
        <div><p className="eyebrow">Scan operations</p><h1>Scans</h1><p className="muted">Queue work through the existing scanner and job engine for <strong>{project.name}</strong>.</p></div>
        <button className="button button-secondary" disabled={scansLoading} onClick={() => void loadScans()} type="button">{scansLoading ? "Refreshing…" : "Refresh list"}</button>
      </section>

      <section className="surface-card scan-create-card">
        <div className="section-title-row"><div><p className="eyebrow">Start an assessment</p><h2>Create a scan</h2></div><span className="permission-note">Server authorization · project scope checked</span></div>
        {profiles.error ? <div className="panel-error" role="alert">{profiles.error}</div> : !hasPermission("scan.create") ? (
          <div className="notice">Your current server-issued role does not include <code>scan.create</code>.</div>
        ) : (
          <form className="scan-form" onSubmit={(event) => void createScan(event)}>
            <label>Profile
              <select disabled={profilesLoading || supportedProfiles.length === 0} onChange={(event) => { setProfileName(event.target.value); setActiveEnabled(false); }} value={profileName}>
                {supportedProfiles.length === 0 && <option value="">No API-supported profiles</option>}
                {supportedProfiles.map((profile) => <option key={profile.name} value={profile.name}>{profile.name}</option>)}
              </select>
            </label>
            {selectedProfile && <div className="profile-description"><strong>{selectedProfile.name}</strong><span>{selectedProfile.description || "No description supplied by the scan registry."}</span><small>{selectedProfile.stages.join(" · ") || "Stages are defined by the existing registry"}</small></div>}
            {selectedProfile && !selectedProfile.in_process && <label className="scan-target-field">Authorized target<input autoComplete="off" maxLength={512} onChange={(event) => setTarget(event.target.value)} placeholder="https://app.example.com" required value={target} /></label>}
            <label className="payload-field">Additional payload <span className="optional">JSON object</span><textarea autoCapitalize="off" autoComplete="off" className="code-input" maxLength={12000} onChange={(event) => setPayloadText(event.target.value)} rows={3} spellCheck={false} value={payloadText} /></label>
            {selectedProfile?.active_required && <label className="checkbox-row active-consent"><input checked={activeEnabled} onChange={(event) => setActiveEnabled(event.target.checked)} type="checkbox" /><span><strong>Authorize active testing for this run</strong><small>Required active profiles are refused unless explicitly authorized and in scope.</small></span></label>}
            {formError && <div className="inline-error" role="alert">{formError}</div>}
            <div className="form-actions"><span className="muted">Jobs are created asynchronously. Status is refreshed every 10 seconds.</span><button className="button button-primary" disabled={creating || !selectedProfile || (selectedProfile.active_required && !activeEnabled)} type="submit">{creating ? "Queueing…" : "Queue scan"}</button></div>
          </form>
        )}
      </section>

      <section className="surface-card table-card">
        <div className="section-title-row"><div><p className="eyebrow">Job history</p><h2>Project scan queue</h2></div><label className="filter-label" htmlFor="scan-status-filter">Status<select id="scan-status-filter" onChange={(event) => setStatusFilter(event.target.value)} value={statusFilter}><option value="">All statuses</option>{allowedStatuses.map((status) => <option key={status} value={status}>{status}</option>)}</select></label></div>
        {actionError && <div className="inline-error" role="alert">{actionError}</div>}
        {scans.error ? <div className="panel-error" role="alert">{scans.error}</div> : scansLoading && scans.rows.length === 0 ? <div className="loading-line"><span className="spinner" aria-hidden="true" />Loading scans…</div> : scans.rows.length === 0 ? <div className="empty-state"><div className="empty-icon">◷</div><strong>No scans found</strong><p>Choose a supported scan profile above. A scan is only queued after server-side scope checks succeed.</p></div> : (
          <div className="table-wrap"><table className="data-table"><thead><tr><th>Scan / profile</th><th>Status</th><th>Progress</th><th>Jobs</th><th>Created</th><th>Actions</th></tr></thead><tbody>
            {scans.rows.map((scan) => {
              const canCancel = hasPermission("scan.cancel") && ["pending", "queued", "running", "paused", "cancelling"].includes(scan.status);
              const canPause = hasPermission("scan.pause") && ["queued", "running"].includes(scan.status);
              const canResume = hasPermission("scan.start") && scan.status === "paused";
              return (
                <tr className={selectedId === scan.id ? "selected-row" : ""} key={scan.id}>
                  <td><button className="table-link-button" onClick={() => void inspectScan(scan.id)} type="button"><strong>{scan.profile}</strong><small>{scan.id.slice(0, 12)}</small></button></td>
                  <td><span className={statusClass(scan.status)}>{scan.status}</span>{scan.error_code && <small className="error-code">{scan.error_code}</small>}</td>
                  <td><div className="progress-cell"><span className="progress-track"><i style={{ width: `${boundedProgress(scan.progress)}%` }} /></span><small>{boundedProgress(scan.progress)}%</small></div></td>
                  <td>{scan.jobs.length}</td><td>{dateTime(scan.created_at)}</td>
                  <td><div className="row-actions"><button aria-label={`Details for ${scan.profile}`} className="icon-button" onClick={() => void inspectScan(scan.id)} title="Details" type="button">↗</button>{canPause && <button className="mini-action" disabled={actionBusy === scan.id + "pause"} onClick={() => void performAction(scan, "pause")} type="button">Pause</button>}{canResume && <button className="mini-action" disabled={actionBusy === scan.id + "resume"} onClick={() => void performAction(scan, "resume")} type="button">Resume</button>}{canCancel && <button className="mini-action mini-danger" disabled={actionBusy === scan.id + "cancel"} onClick={() => void performAction(scan, "cancel")} type="button">Cancel</button>}</div></td>
                </tr>
              );
            })}
          </tbody></table></div>
        )}
      </section>

      {selectedId && <ScanDetails scan={selectedScan} error={selectedError} onClose={() => { setSelectedId(""); setSelectedScan(null); setSelectedError(""); }} />}
    </div>
  );
}

function ScanDetails({ scan, error, onClose }: { scan: ScanRow | null; error: string; onClose: () => void }): ReactElement {
  return (
    <div aria-label="Scan details" aria-modal="true" className="drawer-backdrop" onClick={onClose} role="dialog">
      <aside className="detail-drawer" onClick={(event) => event.stopPropagation()}>
        <div className="drawer-header"><div><p className="eyebrow">Scan record</p><h2>Details</h2></div><button aria-label="Close details" className="icon-button" onClick={onClose} type="button">×</button></div>
        {error ? <div className="panel-error" role="alert">{error}</div> : !scan ? <div className="loading-line"><span className="spinner" aria-hidden="true" />Loading scan details…</div> : (
          <div className="drawer-content">
            <div className="drawer-id">{scan.id}</div>
            <div className="detail-status-row"><span className={statusClass(scan.status)}>{scan.status}</span><span>{scan.profile}</span></div>
            <div className="detail-progress"><div className="progress-cell"><span className="progress-track"><i style={{ width: `${boundedProgress(scan.progress)}%` }} /></span><small>{boundedProgress(scan.progress)}%</small></div></div>
            <dl className="detail-list"><div><dt>Created</dt><dd>{dateTime(scan.created_at)}</dd></div><div><dt>Started</dt><dd>{dateTime(scan.started_at)}</dd></div><div><dt>Finished</dt><dd>{dateTime(scan.finished_at)}</dd></div><div><dt>Scope reference</dt><dd>{scan.scope_ref || "Project scope"}</dd></div><div><dt>Safe error code</dt><dd>{scan.error_code || "—"}</dd></div></dl>
            <section><h3>Stages</h3>{scan.stages.length === 0 ? <p className="muted">No stage records are available.</p> : <div className="stage-list">{scan.stages.map((stage) => <div className="stage-row" key={stage.stage}><span>{stage.stage}</span><span className={statusClass(stage.status)}>{stage.status}</span>{stage.error_code && <small>{stage.error_code}</small>}</div>)}</div>}</section>
            <section><h3>Jobs</h3>{scan.jobs.length === 0 ? <p className="muted">No job records are available.</p> : <div className="stage-list">{scan.jobs.map((job) => <div className="job-detail" key={job.id}><div><span className="job-id">{job.id.slice(0, 14)}</span><span className={statusClass(job.status)}>{job.status}</span></div><small>Attempt {job.attempt} of {job.max_attempts}{job.error_code ? ` · ${job.error_code}` : ""}</small></div>)}</div>}</section>
            {Object.keys(scan.summary).length > 0 && <section><h3>Summary</h3><dl className="detail-list">{Object.entries(scan.summary).map(([key, value]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{String(value)}</dd></div>)}</dl></section>}
          </div>
        )}
      </aside>
    </div>
  );
}
