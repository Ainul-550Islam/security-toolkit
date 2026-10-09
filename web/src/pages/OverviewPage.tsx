import { useCallback, useEffect, useState, type CSSProperties, type ReactElement } from "react";
import { Link } from "react-router-dom";
import { ApiError, apiClient } from "../lib/api";
import { useWorkspace } from "../app/App";

interface Envelope<T> {
  data: T;
  count?: number;
}

interface DashboardBundle {
  posture?: { score?: number; level?: string };
  kpis?: { open_total?: number; open_critical?: number; open_high?: number };
  risk?: { count?: number; by_severity?: Record<string, number> };
  assets?: { total?: number; internet_facing?: number; recently_discovered_30d?: number };
  monitoring?: { health?: { health?: string; score?: number } };
}

interface ScanRow {
  id: string;
  profile: string;
  status: string;
  created_at: string;
  progress: number;
}

interface AssetRow {
  id: string;
  asset_type: string;
  value: string;
  display: string;
  status: string;
  first_seen: string;
  last_seen: string;
}

interface FindingRow {
  id: string;
  title: string;
  severity: string;
  lifecycle: string;
  last_detected: string;
}

interface IntegrationHealth {
  total?: number;
  items?: Array<{ id: string; name: string; connector_kind: string; health_state: string; status: string }>;
  states?: Record<string, number>;
}

interface AuditRow {
  id: string;
  ts: string;
  action: string;
  actor: string;
  object_type: string;
}

interface Panel<T> {
  data: T | null;
  error: string;
}

interface OverviewSnapshot {
  dashboard: Panel<DashboardBundle>;
  scans: Panel<ScanRow[]>;
  assets: Panel<AssetRow[]>;
  findings: Panel<FindingRow[]>;
  integrations: Panel<IntegrationHealth>;
  activity: Panel<AuditRow[]>;
  loading: boolean;
  loaded: boolean;
  refreshedAt: string;
}

function safeMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return "This data is unavailable right now.";
}

async function panel<T>(request: Promise<Envelope<T>>): Promise<Panel<T>> {
  try {
    const response = await request;
    return { data: response.data, error: "" };
  } catch (error) {
    return { data: null, error: safeMessage(error) };
  }
}

function count(value: number | undefined): string {
  return typeof value === "number" && Number.isFinite(value) ? new Intl.NumberFormat().format(value) : "—";
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

function PanelError({ message }: { message: string }): ReactElement {
  return <div className="panel-error" role="status">{message}</div>;
}

export function OverviewPage(): ReactElement {
  const { tenant, project } = useWorkspace();
  const [snapshot, setSnapshot] = useState<OverviewSnapshot>({
    dashboard: { data: null, error: "" },
    scans: { data: null, error: "" },
    assets: { data: null, error: "" },
    findings: { data: null, error: "" },
    integrations: { data: null, error: "" },
    activity: { data: null, error: "" },
    loading: true,
    loaded: false,
    refreshedAt: "",
  });

  const refresh = useCallback(async (signal?: AbortSignal): Promise<void> => {
    setSnapshot((current) => ({ ...current, loading: !current.loaded }));
    const requestOptions = signal ? { signal } : {};
    const projectPath = `/api/v1/projects/${encodeURIComponent(project.id)}`;
    const tenantPath = `/api/v1/tenants/${encodeURIComponent(tenant.id)}`;
    const [dashboard, scans, assets, findings, integrations, activity] = await Promise.all([
      panel(apiClient.get<Envelope<DashboardBundle>>(`${projectPath}/dashboard`, requestOptions)),
      panel(apiClient.get<Envelope<ScanRow[]>>(`${projectPath}/scans?limit=10`, requestOptions)),
      panel(apiClient.get<Envelope<AssetRow[]>>(`${projectPath}/assets?limit=8`, requestOptions)),
      panel(apiClient.get<Envelope<FindingRow[]>>(`${projectPath}/findings?limit=8`, requestOptions)),
      panel(apiClient.get<Envelope<IntegrationHealth>>(`${tenantPath}/integration-health?limit=8`, requestOptions)),
      panel(apiClient.get<Envelope<AuditRow[]>>(`${tenantPath}/audit-events?limit=8&offset=0`, requestOptions)),
    ]);
    if (signal?.aborted) return;
    setSnapshot({
      dashboard,
      scans,
      assets,
      findings,
      integrations,
      activity,
      loading: false,
      loaded: true,
      refreshedAt: new Date().toISOString(),
    });
  }, [project.id, tenant.id]);

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    const interval = window.setInterval(() => void refresh(), 30_000);
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [refresh]);

  const bundle = snapshot.dashboard.data;
  const kpis = bundle?.kpis;
  const risk = bundle?.risk;
  const severity = risk?.by_severity ?? {};
  const highestSeverityCount = Math.max(1, ...Object.values(severity).filter(Number.isFinite));
  const recentScans = snapshot.scans.data ?? [];
  const recentAssets = snapshot.assets.data ?? [];
  const recentFindings = snapshot.findings.data ?? [];
  const healthItems = snapshot.integrations.data?.items ?? [];
  const recentActivity = snapshot.activity.data ?? [];
  const postureScore = bundle?.posture?.score;
  const postureValue = typeof postureScore === "number" && Number.isFinite(postureScore) ? Math.round(postureScore) : null;

  return (
    <div className="page-stack">
      <section className="page-heading page-heading-row">
        <div>
          <p className="eyebrow">Security overview</p>
          <h1>{project.name}</h1>
          <p className="muted">Your authorized security picture for <strong>{tenant.name}</strong>.</p>
        </div>
        <div className="heading-actions">
          {snapshot.refreshedAt && <span className="last-updated">Updated {dateTime(snapshot.refreshedAt)}</span>}
          <button className="button button-secondary" disabled={snapshot.loading} onClick={() => void refresh()} type="button">{snapshot.loading ? "Refreshing…" : "Refresh"}</button>
          <Link className="button button-primary" to="/scans">New scan <span aria-hidden="true">↗</span></Link>
        </div>
      </section>

      <section aria-label="Security summary" className="metric-grid">
        <article className="metric-card metric-posture">
          <div className="metric-card-top"><span>Security posture</span><span className="metric-kicker">LOCAL SCORE</span></div>
          {snapshot.dashboard.error ? <PanelError message={snapshot.dashboard.error} /> : (
            <div className="posture-row">
              <div className="posture-ring" style={{ "--score": `${postureValue ?? 0}%` } as CSSProperties}>
                <div className="posture-ring-inner"><strong>{postureValue ?? "—"}</strong><span>/ 100</span></div>
              </div>
              <div><strong className="posture-level">{bundle?.posture?.level ?? "Waiting for data"}</strong><p className="metric-footnote">Versioned program posture, not an external benchmark.</p></div>
            </div>
          )}
        </article>
        <MetricCard label="Open findings" value={count(kpis?.open_total)} detail="Active lifecycle states" icon="◇" accent="blue" error={snapshot.dashboard.error} />
        <MetricCard label="Critical findings" value={count(kpis?.open_critical)} detail={`${count(kpis?.open_high)} high severity`} icon="!" accent="rose" error={snapshot.dashboard.error} />
        <MetricCard label="Known assets" value={count(bundle?.assets?.total)} detail={`${count(bundle?.assets?.internet_facing)} internet-facing`} icon="⌘" accent="mint" error={snapshot.dashboard.error} />
      </section>

      <section className="content-grid overview-main-grid">
        <article className="surface-card risk-card">
          <div className="section-title-row"><div><p className="eyebrow">Current exposure</p><h2>Findings by severity</h2></div><Link className="text-link" to="/findings">View findings <span aria-hidden="true">→</span></Link></div>
          {snapshot.dashboard.error ? <PanelError message={snapshot.dashboard.error} /> : (
            <div className="severity-list">
              {["Critical", "High", "Medium", "Low", "Info"].map((level) => {
                const value = severity[level] ?? 0;
                const ratio = Math.min(100, Math.max(0, (value / highestSeverityCount) * 100));
                return (
                  <div className="severity-row" key={level}>
                    <span className={`severity-label severity-${level.toLowerCase()}`}><i />{level}</span>
                    <div className="bar-track"><span className={`bar-fill bar-${level.toLowerCase()}`} style={{ width: `${ratio}%` }} /></div>
                    <strong>{count(value)}</strong>
                  </div>
                );
              })}
            </div>
          )}
          <div className="risk-summary-strip"><div><span className="summary-dot dot-critical" /><span>Weighted risk</span><strong>{count(risk?.count)}</strong></div><div><span className="summary-dot dot-blue" /><span>New assets · 30 days</span><strong>{count(bundle?.assets?.recently_discovered_30d)}</strong></div><div><span className="summary-dot dot-blue" /><span>Platform health</span><strong><span className={statusClass(bundle?.monitoring?.health?.health ?? "unavailable")}>{bundle?.monitoring?.health?.health ?? "unavailable"}</span></strong></div></div>
        </article>

        <article className="surface-card integration-card">
          <div className="section-title-row"><div><p className="eyebrow">Connected services</p><h2>Integration health</h2></div><Link className="text-link" to="/settings">Manage <span aria-hidden="true">→</span></Link></div>
          {snapshot.integrations.error ? <PanelError message={snapshot.integrations.error} /> : healthItems.length === 0 ? (
            <div className="empty-state compact-empty"><div className="empty-icon">⌁</div><strong>No integrations registered</strong><p>Provider status appears here after an integration is configured.</p></div>
          ) : (
            <div className="integration-list">
              {healthItems.slice(0, 5).map((item) => (
                <div className="integration-row" key={item.id}>
                  <span className="integration-mark">{item.connector_kind.slice(0, 1).toUpperCase()}</span>
                  <div className="integration-copy"><strong>{item.name}</strong><span>{item.connector_kind.replaceAll("_", " ")}</span></div>
                  <span className={statusClass(item.health_state || item.status)}>{item.health_state || item.status || "unchecked"}</span>
                </div>
              ))}
            </div>
          )}
        </article>
      </section>

      <section className="content-grid overview-lower-grid">
        <article className="surface-card table-card">
          <div className="section-title-row"><div><p className="eyebrow">Operations</p><h2>Recent scans</h2></div><Link className="text-link" to="/scans">All scans <span aria-hidden="true">→</span></Link></div>
          {snapshot.scans.error ? <PanelError message={snapshot.scans.error} /> : recentScans.length === 0 ? <EmptyLine message="No scans have been queued for this project." /> : (
            <div className="compact-table-wrap"><table className="data-table"><thead><tr><th>Profile</th><th>Status</th><th>Progress</th><th>Created</th></tr></thead><tbody>
              {recentScans.slice(0, 5).map((scan) => <tr key={scan.id}><td><span className="table-primary">{scan.profile}</span><span className="table-sub">{scan.id.slice(0, 10)}</span></td><td><span className={statusClass(scan.status)}>{scan.status}</span></td><td><Progress value={scan.progress} /></td><td>{dateTime(scan.created_at)}</td></tr>)}
            </tbody></table></div>
          )}
        </article>
        <article className="surface-card table-card">
          <div className="section-title-row"><div><p className="eyebrow">Latest signals</p><h2>Recent findings</h2></div><Link className="text-link" to="/findings">Open queue <span aria-hidden="true">→</span></Link></div>
          {snapshot.findings.error ? <PanelError message={snapshot.findings.error} /> : recentFindings.length === 0 ? <EmptyLine message="No findings are recorded for this project yet." /> : (
            <div className="finding-preview-list">
              {recentFindings.slice(0, 5).map((finding) => <Link className="finding-preview" key={finding.id} to="/findings"><span className={`severity-marker marker-${finding.severity.toLowerCase()}`} /><span className="finding-preview-copy"><strong>{finding.title}</strong><small>{finding.lifecycle.replaceAll("_", " ")} · {dateTime(finding.last_detected)}</small></span><span className={statusClass(finding.severity)}>{finding.severity}</span></Link>)}
            </div>
          )}
        </article>
        <article className="surface-card table-card">
          <div className="section-title-row"><div><p className="eyebrow">Inventory</p><h2>Recent assets</h2></div><span className="privacy-note">Project-scoped asset metadata</span></div>
          {snapshot.assets.error ? <PanelError message={snapshot.assets.error} /> : !snapshot.loaded ? <div className="loading-line"><span className="spinner" aria-hidden="true" />Loading assets…</div> : recentAssets.length === 0 ? <EmptyLine message="No assets are recorded for this project yet." /> : (
            <div className="compact-table-wrap"><table className="data-table"><thead><tr><th>Asset</th><th>Type</th><th>Status</th><th>Last seen</th></tr></thead><tbody>
              {recentAssets.slice(0, 6).map((asset) => <tr key={asset.id}><td><span className="table-primary">{asset.display || asset.value}</span><span className="table-sub">{asset.id.slice(0, 12)}</span></td><td>{asset.asset_type.replaceAll("_", " ")}</td><td><span className={statusClass(asset.status)}>{asset.status}</span></td><td>{dateTime(asset.last_seen)}</td></tr>)}
            </tbody></table></div>
          )}
        </article>
      </section>

      <section className="surface-card table-card activity-card">
        <div className="section-title-row"><div><p className="eyebrow">Change history</p><h2>Recent activity</h2></div><span className="privacy-note">Tenant-filtered audit data</span></div>
        {snapshot.activity.error ? <PanelError message={snapshot.activity.error} /> : recentActivity.length === 0 ? <EmptyLine message="Audit activity will appear here as actions are recorded." /> : (
          <div className="compact-table-wrap"><table className="data-table activity-table"><thead><tr><th>Action</th><th>Actor</th><th>Object</th><th>Time</th></tr></thead><tbody>
            {recentActivity.slice(0, 6).map((entry) => <tr key={entry.id}><td><span className="action-badge">{entry.action}</span></td><td>{entry.actor}</td><td>{entry.object_type}</td><td>{dateTime(entry.ts)}</td></tr>)}
          </tbody></table></div>
        )}
      </section>
    </div>
  );
}

function MetricCard({ label, value, detail, icon, accent, error }: { label: string; value: string; detail: string; icon: string; accent: string; error: string }): ReactElement {
  return (
    <article className={`metric-card metric-${accent}`}>
      <div className="metric-card-top"><span>{label}</span><span className="metric-icon">{icon}</span></div>
      {error ? <PanelError message={error} /> : <><strong className="metric-value">{value}</strong><span className="metric-footnote">{detail}</span></>}
    </article>
  );
}

function EmptyLine({ message }: { message: string }): ReactElement {
  return <div className="empty-line"><span className="empty-line-mark">—</span><span>{message}</span></div>;
}

function Progress({ value }: { value: number }): ReactElement {
  const percent = Math.round(Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0)) * 100);
  return <div aria-label={`${percent}%`} className="progress-cell"><span className="progress-track"><i style={{ width: `${percent}%` }} /></span><small>{percent}%</small></div>;
}
