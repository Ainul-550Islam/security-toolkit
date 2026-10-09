import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactElement } from "react";
import { ApiError, apiClient } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useWorkspace } from "../app/App";

interface Envelope<T> {
  data: T;
  count?: number;
}

interface FindingRow {
  id: string;
  scan_id: string;
  project_id: string;
  asset_id: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  category: string;
  source: string;
  rule_id: string;
  cwe: string;
  cve: string;
  remediation: string;
  lifecycle: string;
  fingerprint: string;
  first_detected: string;
  last_detected: string;
}

interface EvidenceRow {
  id: string;
  finding_id: string;
  evidence_type: string;
  url: string;
  method: string;
  status_code: string;
  detection_reason: string;
  scanner: string;
  rule_id: string;
  captured_at: string;
}

interface TicketingIntegration {
  id: string;
  name: string;
  connector_kind: string;
  provider: string;
  status: string;
  project_id: string;
}

const LIFECYCLES = ["open", "acknowledged", "confirmed", "in_review", "resolved", "remediated", "false_positive", "accepted_risk", "reopened"];
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

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

function canTransition(status: string, hasPermission: (permission: string) => boolean): boolean {
  if (!hasPermission("finding.update")) return false;
  if (status === "accepted_risk") return hasPermission("finding.accept_risk");
  if (["resolved", "remediated", "false_positive"].includes(status)) return hasPermission("finding.resolve");
  return true;
}

export function FindingsPage(): ReactElement {
  const { tenant, project } = useWorkspace();
  const { hasPermission } = useAuth();
  const [rows, setRows] = useState<FindingRow[]>([]);
  const [integrations, setIntegrations] = useState<TicketingIntegration[]>([]);
  const [listError, setListError] = useState("");
  const [integrationError, setIntegrationError] = useState("");
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [lifecycleFilter, setLifecycleFilter] = useState("");
  const [sortOrder, setSortOrder] = useState("recent");
  const [selected, setSelected] = useState<FindingRow | null>(null);
  const [detailError, setDetailError] = useState("");
  const [evidence, setEvidence] = useState<EvidenceRow[]>([]);
  const [evidenceError, setEvidenceError] = useState("");
  const [evidenceDetail, setEvidenceDetail] = useState<EvidenceRow | null>(null);
  const [nextLifecycle, setNextLifecycle] = useState("");
  const [savingLifecycle, setSavingLifecycle] = useState(false);
  const [ticketBusy, setTicketBusy] = useState(false);
  const [workflowMessage, setWorkflowMessage] = useState("");
  const [workflowError, setWorkflowError] = useState("");
  const [selectedIntegrationId, setSelectedIntegrationId] = useState("");

  const load = useCallback(async (signal?: AbortSignal): Promise<void> => {
    setLoading(true);
    const query = new URLSearchParams({ limit: "500" });
    if (severityFilter) query.set("severity", severityFilter);
    if (lifecycleFilter) query.set("lifecycle", lifecycleFilter);
    try {
      const response = await apiClient.get<Envelope<FindingRow[]>>(
        `/api/v1/projects/${encodeURIComponent(project.id)}/findings?${query.toString()}`,
        signal ? { signal } : {},
      );
      if (!signal?.aborted) {
        setRows(Array.isArray(response.data) ? response.data : []);
        setListError("");
      }
    } catch (error) {
      if (!signal?.aborted) {
        setRows([]);
        setListError(errorMessage(error));
      }
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, [lifecycleFilter, project.id, severityFilter]);

  const loadTicketing = useCallback(async (signal?: AbortSignal): Promise<void> => {
    if (!hasPermission("integration.read")) {
      setIntegrations([]);
      setIntegrationError("Ticketing integrations are not visible to this role.");
      return;
    }
    const query = new URLSearchParams({
      project_id: project.id,
      connector_kind: "ticketing",
      status: "enabled",
      limit: "100",
    });
    try {
      const response = await apiClient.get<Envelope<TicketingIntegration[]>>(
        `/api/v1/tenants/${encodeURIComponent(tenant.id)}/integrations?${query.toString()}`,
        signal ? { signal } : {},
      );
      if (signal?.aborted) return;
      const enabled = Array.isArray(response.data) ? response.data : [];
      setIntegrations(enabled);
      setSelectedIntegrationId((current) => enabled.some((item) => item.id === current)
        ? current
        : (enabled[0]?.id ?? ""));
      setIntegrationError("");
    } catch (error) {
      if (!signal?.aborted) {
        setIntegrations([]);
        setIntegrationError(errorMessage(error));
      }
    }
  }, [hasPermission, project.id, tenant.id]);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  useEffect(() => {
    const controller = new AbortController();
    void loadTicketing(controller.signal);
    return () => controller.abort();
  }, [loadTicketing]);

  const filteredRows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const result = rows.filter((row) => !needle || [row.title, row.category, row.asset_id, row.cve, row.cwe].some((value) => value.toLowerCase().includes(needle)));
    const severityRank: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    return result.sort((left, right) => {
      if (sortOrder === "severity") return (severityRank[left.severity] ?? 99) - (severityRank[right.severity] ?? 99);
      return right.last_detected.localeCompare(left.last_detected);
    });
  }, [rows, search, sortOrder]);

  async function openFinding(finding: FindingRow): Promise<void> {
    setSelected(finding);
    setNextLifecycle(finding.lifecycle);
    setDetailError("");
    setEvidence([]);
    setEvidenceError("");
    setEvidenceDetail(null);
    setWorkflowError("");
    setWorkflowMessage("");
    try {
      const [detail, evidenceResponse] = await Promise.all([
        apiClient.get<Envelope<FindingRow>>(`/api/v1/findings/${encodeURIComponent(finding.id)}`),
        apiClient.get<Envelope<EvidenceRow[]>>(`/api/v1/findings/${encodeURIComponent(finding.id)}/evidence?limit=100`),
      ]);
      setSelected(detail.data);
      setNextLifecycle(detail.data.lifecycle);
      setEvidence(Array.isArray(evidenceResponse.data) ? evidenceResponse.data : []);
    } catch (error) {
      setDetailError(errorMessage(error));
      setEvidenceError(errorMessage(error));
    }
  }

  async function openEvidence(evidenceId: string): Promise<void> {
    setEvidenceDetail(null);
    setEvidenceError("");
    try {
      const response = await apiClient.get<Envelope<EvidenceRow>>(`/api/v1/evidence/${encodeURIComponent(evidenceId)}`);
      setEvidenceDetail(response.data);
    } catch (error) {
      setEvidenceError(errorMessage(error));
    }
  }

  async function saveLifecycle(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!selected || !nextLifecycle || nextLifecycle === selected.lifecycle) return;
    if (!canTransition(nextLifecycle, hasPermission)) {
      setDetailError("Your server-issued permissions do not allow this lifecycle transition.");
      return;
    }
    setSavingLifecycle(true);
    setDetailError("");
    try {
      const response = await apiClient.patch<Envelope<FindingRow>>(
        `/api/v1/findings/${encodeURIComponent(selected.id)}`,
        { lifecycle: nextLifecycle },
      );
      setSelected(response.data);
      await load();
    } catch (error) {
      setDetailError(errorMessage(error));
    } finally {
      setSavingLifecycle(false);
    }
  }

  async function sendTicket(action: "upsert" | "close"): Promise<void> {
    if (!selected || !selectedIntegrationId) return;
    setTicketBusy(true);
    setWorkflowError("");
    setWorkflowMessage("");
    try {
      const suffix = action === "upsert" ? "ticket" : "ticket/close";
      const response = await apiClient.post<Envelope<{ provider: string; key: string; url: string; operation: string }>>(
        `/api/v1/projects/${encodeURIComponent(project.id)}/findings/${encodeURIComponent(selected.id)}/${suffix}`,
        { integration_id: selectedIntegrationId },
      );
      setWorkflowMessage(`${response.data.provider} ${response.data.operation}: ${response.data.key} · ${response.data.url}`);
    } catch (error) {
      setWorkflowError(errorMessage(error));
    } finally {
      setTicketBusy(false);
    }
  }

  return (
    <div className="page-stack">
      <section className="page-heading page-heading-row">
        <div><p className="eyebrow">Risk triage</p><h1>Findings</h1><p className="muted">{project.name} · Server-filtered, tenant-scoped security findings.</p></div>
        <button className="button button-secondary" disabled={loading} onClick={() => void load()} type="button">{loading ? "Refreshing…" : "Refresh"}</button>
      </section>

      <section className="surface-card findings-toolbar">
        <label className="search-field"><span className="sr-only">Search findings</span><span className="search-icon">⌕</span><input autoComplete="off" onChange={(event) => setSearch(event.target.value)} placeholder="Search title, category, asset or CVE…" value={search} /></label>
        <label className="filter-label" htmlFor="finding-severity">Severity<select id="finding-severity" onChange={(event) => setSeverityFilter(event.target.value)} value={severityFilter}><option value="">All severities</option>{SEVERITIES.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
        <label className="filter-label" htmlFor="finding-lifecycle">Lifecycle<select id="finding-lifecycle" onChange={(event) => setLifecycleFilter(event.target.value)} value={lifecycleFilter}><option value="">All lifecycle states</option>{LIFECYCLES.map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}</select></label>
        <label className="filter-label" htmlFor="finding-sort">Sort by<select id="finding-sort" onChange={(event) => setSortOrder(event.target.value)} value={sortOrder}><option value="recent">Most recent</option><option value="severity">Severity</option></select></label>
        <span className="result-count">{loading ? "Loading…" : `${filteredRows.length} shown`}</span>
      </section>

      <section className="surface-card table-card">
        {listError ? <div className="panel-error" role="alert">{listError}</div> : loading && rows.length === 0 ? <div className="loading-line"><span className="spinner" aria-hidden="true" />Loading findings…</div> : filteredRows.length === 0 ? <div className="empty-state"><div className="empty-icon">◇</div><strong>{rows.length === 0 ? "No findings recorded" : "No matches"}</strong><p>{rows.length === 0 ? "Findings appear when an authorized scan or import records them." : "Try a broader search or change the selected filters."}</p></div> : (
          <div className="table-wrap"><table className="data-table findings-table"><thead><tr><th>Finding</th><th>Severity</th><th>Lifecycle</th><th>Category</th><th>Last detected</th><th /></tr></thead><tbody>
            {filteredRows.map((finding) => <tr key={finding.id}>
              <td><button className="table-link-button finding-title-button" onClick={() => void openFinding(finding)} type="button"><strong>{finding.title}</strong><small>{finding.id.slice(0, 12)} · {finding.asset_id || "No asset reference"}</small></button></td>
              <td><span className={`severity-label severity-${finding.severity.toLowerCase()}`}><i />{finding.severity}</span></td>
              <td><span className={statusClass(finding.lifecycle)}>{finding.lifecycle.replaceAll("_", " ")}</span></td>
              <td>{finding.category || "—"}</td><td>{dateTime(finding.last_detected)}</td>
              <td><button aria-label={`Open ${finding.title}`} className="icon-button" onClick={() => void openFinding(finding)} type="button">↗</button></td>
            </tr>)}
          </tbody></table></div>
        )}
      </section>

      {selected && <FindingDrawer
        evidence={evidence}
        evidenceDetail={evidenceDetail}
        evidenceError={evidenceError}
        finding={selected}
        detailError={detailError}
        integrationError={integrationError}
        integrations={integrations}
        lifecycle={nextLifecycle}
        savingLifecycle={savingLifecycle}
        ticketBusy={ticketBusy}
        workflowError={workflowError}
        workflowMessage={workflowMessage}
        selectedIntegrationId={selectedIntegrationId}
        onClose={() => { setSelected(null); setEvidenceDetail(null); }}
        onEvidence={openEvidence}
        onIntegrationChange={setSelectedIntegrationId}
        onLifecycleChange={setNextLifecycle}
        onSaveLifecycle={(event) => void saveLifecycle(event)}
        onTicket={(action) => void sendTicket(action)}
        hasPermission={hasPermission}
      />}
    </div>
  );
}

interface FindingDrawerProps {
  finding: FindingRow;
  evidence: EvidenceRow[];
  evidenceDetail: EvidenceRow | null;
  evidenceError: string;
  detailError: string;
  integrationError: string;
  integrations: TicketingIntegration[];
  lifecycle: string;
  savingLifecycle: boolean;
  ticketBusy: boolean;
  workflowError: string;
  workflowMessage: string;
  selectedIntegrationId: string;
  onClose: () => void;
  onEvidence: (id: string) => Promise<void>;
  onIntegrationChange: (id: string) => void;
  onLifecycleChange: (status: string) => void;
  onSaveLifecycle: (event: FormEvent<HTMLFormElement>) => void;
  onTicket: (action: "upsert" | "close") => void;
  hasPermission: (permission: string) => boolean;
}

function FindingDrawer(props: FindingDrawerProps): ReactElement {
  const { finding } = props;
  return (
    <div aria-label="Finding detail" aria-modal="true" className="drawer-backdrop" onClick={props.onClose} role="dialog">
      <aside className="detail-drawer finding-drawer" onClick={(event) => event.stopPropagation()}>
        <div className="drawer-header"><div><p className="eyebrow">Finding record</p><h2>Risk detail</h2></div><button aria-label="Close finding details" className="icon-button" onClick={props.onClose} type="button">×</button></div>
        {props.detailError && <div className="panel-error" role="alert">{props.detailError}</div>}
        <div className="drawer-content">
          <span className={`severity-label severity-${finding.severity.toLowerCase()}`}><i />{finding.severity}</span>
          <h2 className="detail-finding-title">{finding.title}</h2>
          <div className="drawer-id">{finding.id}</div>
          <div className="detail-status-row"><span className={statusClass(finding.lifecycle)}>{finding.lifecycle.replaceAll("_", " ")}</span><span>{finding.category || "Uncategorized"}</span></div>
          <dl className="detail-list"><div><dt>First detected</dt><dd>{dateTime(finding.first_detected)}</dd></div><div><dt>Last detected</dt><dd>{dateTime(finding.last_detected)}</dd></div><div><dt>Asset</dt><dd>{finding.asset_id || "No asset reference"}</dd></div><div><dt>Scan</dt><dd>{finding.scan_id || "Imported record"}</dd></div><div><dt>Source</dt><dd>{finding.source || "—"}</dd></div><div><dt>Rule</dt><dd>{finding.rule_id || "—"}</dd></div>{finding.cve && <div><dt>CVE</dt><dd>{finding.cve}</dd></div>}{finding.cwe && <div><dt>CWE</dt><dd>{finding.cwe}</dd></div>}</dl>
          <section><h3>Description</h3><p className="detail-paragraph">{finding.description || "No description supplied."}</p></section>
          <section><h3>Remediation guidance</h3><p className="detail-paragraph">{finding.remediation || "No remediation guidance was supplied."}</p></section>

          {props.hasPermission("finding.update") && <section className="workflow-section"><h3>Lifecycle workflow</h3><form className="inline-form" onSubmit={props.onSaveLifecycle}><select aria-label="Finding lifecycle" onChange={(event) => props.onLifecycleChange(event.target.value)} value={props.lifecycle}>{LIFECYCLES.map((status) => <option disabled={!canTransition(status, props.hasPermission)} key={status} value={status}>{status.replaceAll("_", " ")}</option>)}</select><button className="button button-secondary button-small" disabled={props.savingLifecycle || props.lifecycle === finding.lifecycle || !canTransition(props.lifecycle, props.hasPermission)} type="submit">{props.savingLifecycle ? "Saving…" : "Update status"}</button></form><p className="muted small-note">The server validates lifecycle edges and elevated permissions. Assignment and ticket ownership endpoints are not exposed by the current API.</p></section>}

          <section className="workflow-section"><div className="section-title-row"><h3>Ticketing</h3><span className="privacy-note">External action · audited</span></div>
            {props.integrationError ? <p className="muted small-note">{props.integrationError}</p> : props.integrations.length === 0 ? <p className="muted small-note">No enabled ticketing integration is available for this project.</p> : (
              <>
                <label className="drawer-label">Ticketing integration<select onChange={(event) => props.onIntegrationChange(event.target.value)} value={props.selectedIntegrationId}>{props.integrations.map((integration) => <option key={integration.id} value={integration.id}>{integration.name} · {integration.provider}</option>)}</select></label>
                {props.hasPermission("integration.send") ? <div className="drawer-action-row"><button className="button button-secondary button-small" disabled={props.ticketBusy || !props.selectedIntegrationId} onClick={() => props.onTicket("upsert")} type="button">{props.ticketBusy ? "Working…" : "Create / update ticket"}</button><button className="button button-quiet button-small" disabled={props.ticketBusy || !props.selectedIntegrationId} onClick={() => props.onTicket("close")} type="button">Close linked ticket</button></div> : <p className="muted small-note">Your current role cannot send data to external ticketing providers.</p>}
              </>
            )}
            {props.workflowError && <div className="inline-error" role="alert">{props.workflowError}</div>}
            {props.workflowMessage && <div className="inline-success" role="status">{props.workflowMessage}</div>}
          </section>

          <section><div className="section-title-row"><h3>Evidence</h3><span className="count-badge">{props.evidence.length}</span></div>
            {props.evidenceError ? <div className="panel-error" role="alert">{props.evidenceError}</div> : props.evidence.length === 0 ? <p className="muted small-note">No evidence metadata is available for this finding.</p> : <div className="evidence-list">{props.evidence.map((item) => <div className="evidence-row" key={item.id}><div><strong>{item.evidence_type || "Evidence"}</strong><small>{item.method} {item.status_code} · {dateTime(item.captured_at)}</small><code>{item.url || item.detection_reason || "No URL metadata"}</code></div><button className="text-link-button" onClick={() => void props.onEvidence(item.id)} type="button">View metadata</button></div>)}</div>}
            {props.evidenceDetail && <div className="evidence-detail"><strong>Evidence metadata</strong><dl className="detail-list"><div><dt>Evidence ID</dt><dd>{props.evidenceDetail.id}</dd></div><div><dt>Scanner</dt><dd>{props.evidenceDetail.scanner || "—"}</dd></div><div><dt>Rule</dt><dd>{props.evidenceDetail.rule_id || "—"}</dd></div><div><dt>Detection reason</dt><dd>{props.evidenceDetail.detection_reason || "—"}</dd></div><div><dt>Captured</dt><dd>{dateTime(props.evidenceDetail.captured_at)}</dd></div></dl></div>}
          </section>
        </div>
      </aside>
    </div>
  );
}
