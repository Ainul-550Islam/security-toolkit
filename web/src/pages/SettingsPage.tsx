import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactElement } from "react";
import { ApiError, apiClient } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useWorkspace, type Tenant } from "../app/App";

interface Envelope<T> {
  data: T;
  count?: number;
  total?: number;
}

interface Panel<T> {
  data: T | null;
  error: string;
}

interface UserRow {
  id: string;
  username: string;
  email: string;
  display_name: string;
  roles: string[];
  status: string;
  created_at: string;
  last_auth_at: string;
}

interface SessionRow {
  id: string;
  user_id: string;
  username: string;
  auth_method: string;
  mfa_status: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  revoked_at: string;
}

interface Catalog {
  connector_kinds?: string[];
  auth_modes?: string[];
  capabilities?: Record<string, string[]>;
}

interface IntegrationRow {
  id: string;
  name: string;
  project_id: string;
  connector_kind: string;
  provider: string;
  auth_mode: string;
  endpoint_url: string;
  status: string;
  health_state: string;
  circuit_state: string;
  created_by: string;
}

interface NotificationSettings {
  project_id: string;
  email_enabled: boolean;
  email_to: string;
  webhook_enabled: boolean;
  webhook_url: string;
  has_secret: boolean;
}

interface AuditRow {
  id: string;
  ts: string;
  action: string;
  actor: string;
  object_type: string;
  object_id: string;
}

type SettingsTab = "organization" | "people" | "integrations" | "notifications" | "security" | "audit";

const ROLE_OPTIONS = ["viewer", "analyst", "security_manager", "admin", "owner"];
function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "The request could not be completed.";
}

async function loadPanel<T>(request: Promise<Envelope<T>>): Promise<Panel<T>> {
  try {
    const response = await request;
    return { data: response.data, error: "" };
  } catch (error) {
    return { data: null, error: errorMessage(error) };
  }
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

function permissionText(hasPermission: (permission: string) => boolean, permission: string): string {
  return hasPermission(permission) ? "Permission granted by the authenticated role." : `Your current role does not include ${permission}.`;
}

export function SettingsPage(): ReactElement {
  const { tenant, project } = useWorkspace();
  const auth = useAuth();
  const [tab, setTab] = useState<SettingsTab>("organization");
  const [tenantPanel, setTenantPanel] = useState<Panel<Tenant>>({ data: tenant, error: "" });
  const [usersPanel, setUsersPanel] = useState<Panel<UserRow[]>>({ data: null, error: "" });
  const [sessionsPanel, setSessionsPanel] = useState<Panel<SessionRow[]>>({ data: null, error: "" });
  const [catalogPanel, setCatalogPanel] = useState<Panel<Catalog>>({ data: null, error: "" });
  const [integrationsPanel, setIntegrationsPanel] = useState<Panel<IntegrationRow[]>>({ data: null, error: "" });
  const [notificationPanel, setNotificationPanel] = useState<Panel<NotificationSettings>>({ data: null, error: "" });
  const [auditPanel, setAuditPanel] = useState<Panel<AuditRow[]>>({ data: null, error: "" });
  const [loading, setLoading] = useState(true);
  const [refreshError, setRefreshError] = useState("");
  const [notice, setNotice] = useState("");
  const [operationError, setOperationError] = useState("");
  const [busyKey, setBusyKey] = useState("");

  const [newUsername, setNewUsername] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newDisplayName, setNewDisplayName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("viewer");

  const [connectionName, setConnectionName] = useState("");
  const [connectorKind, setConnectorKind] = useState("generic_webhook");
  const [authMode, setAuthMode] = useState("hmac");
  const [provider, setProvider] = useState("generic_webhook");
  const [endpointUrl, setEndpointUrl] = useState("");
  const [credentialReference, setCredentialReference] = useState("");
  const [configText, setConfigText] = useState("{}");

  const [notificationDraft, setNotificationDraft] = useState({
    emailEnabled: false,
    emailTo: "",
    webhookEnabled: false,
    webhookUrl: "",
    webhookSecret: "",
    clearSecret: false,
  });
  const [notificationDirty, setNotificationDirty] = useState<Set<string>>(() => new Set());

  const refresh = useCallback(async (signal?: AbortSignal): Promise<void> => {
    setLoading(true);
    setRefreshError("");
    const requestOptions = signal ? { signal } : {};
    const tenantPath = `/api/v1/tenants/${encodeURIComponent(tenant.id)}`;
    const projectQuery = new URLSearchParams({ project_id: project.id, limit: "100", offset: "0" });
    const tasks = await Promise.all([
      loadPanel(apiClient.get<Envelope<Tenant>>("/api/v1/tenants", requestOptions)),
      loadPanel(apiClient.get<Envelope<UserRow[]>>(`${tenantPath}/users?limit=100`, requestOptions)),
      loadPanel(apiClient.get<Envelope<SessionRow[]>>(`${tenantPath}/sessions?limit=100&status=active`, requestOptions)),
      loadPanel(apiClient.get<Envelope<Catalog>>(`${tenantPath}/integration-catalog`, requestOptions)),
      loadPanel(apiClient.get<Envelope<IntegrationRow[]>>(`${tenantPath}/integrations?${projectQuery.toString()}`, requestOptions)),
      loadPanel(apiClient.get<Envelope<NotificationSettings>>(`/api/v1/projects/${encodeURIComponent(project.id)}/notifications/settings`, requestOptions)),
      loadPanel(apiClient.get<Envelope<AuditRow[]>>(`${tenantPath}/audit-events?limit=50&offset=0`, requestOptions)),
    ]);
    if (signal?.aborted) return;
    const [tenantResult, usersResult, sessionsResult, catalogResult, integrationsResult, notificationResult, auditResult] = tasks;
    setTenantPanel(tenantResult);
    setUsersPanel(usersResult);
    setSessionsPanel(sessionsResult);
    setCatalogPanel(catalogResult);
    setIntegrationsPanel(integrationsResult);
    setNotificationPanel(notificationResult);
    setAuditPanel(auditResult);
    setLoading(false);
    const failures = tasks.filter((item) => item.error).length;
    setRefreshError(failures ? `${failures} settings panel${failures === 1 ? " is" : "s are"} unavailable for this role or service.` : "");
  }, [project.id, tenant.id]);

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    return () => controller.abort();
  }, [refresh]);

  useEffect(() => {
    const data = notificationPanel.data;
    if (!data) return;
    setNotificationDraft({
      emailEnabled: data.email_enabled,
      emailTo: data.email_to,
      webhookEnabled: data.webhook_enabled,
      webhookUrl: data.webhook_url,
      webhookSecret: "",
      clearSecret: false,
    });
    setNotificationDirty(new Set());
  }, [notificationPanel.data]);

  const integrations = integrationsPanel.data ?? [];
  const connectorKinds = useMemo(() => catalogPanel.data?.connector_kinds ?? [], [catalogPanel.data]);
  const authModes = useMemo(() => catalogPanel.data?.auth_modes ?? [], [catalogPanel.data]);
  const selectedProjectConnections = integrations.filter((connection) => connection.project_id === project.id);

  function setNotificationField<T extends keyof typeof notificationDraft>(key: T, value: (typeof notificationDraft)[T]): void {
    setNotificationDraft((current) => ({ ...current, [key]: value }));
    setNotificationDirty((current) => new Set(current).add(key));
  }

  async function createUser(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusyKey("create-user");
    setOperationError("");
    setNotice("");
    try {
      await apiClient.post(`/api/v1/tenants/${encodeURIComponent(tenant.id)}/users`, {
        username: newUsername.trim(),
        email: newEmail.trim(),
        display_name: newDisplayName.trim(),
        password: newPassword,
        roles: [newRole],
      });
      setNewUsername("");
      setNewEmail("");
      setNewDisplayName("");
      setNewPassword("");
      setNotice("User created through IdentityService.");
      await refresh();
    } catch (error) {
      setOperationError(errorMessage(error));
    } finally {
      setBusyKey("");
    }
  }

  async function updateUser(userId: string, body: { roles: string[] } | { status: string }): Promise<void> {
    setBusyKey(userId);
    setOperationError("");
    setNotice("");
    try {
      await apiClient.patch(`/api/v1/tenants/${encodeURIComponent(tenant.id)}/users/${encodeURIComponent(userId)}`, body);
      setNotice("User updated and audited by the server.");
      await refresh();
    } catch (error) {
      setOperationError(errorMessage(error));
    } finally {
      setBusyKey("");
    }
  }

  async function revokeSession(sessionId: string): Promise<void> {
    setBusyKey(sessionId);
    setOperationError("");
    setNotice("");
    try {
      await apiClient.post(`/api/v1/tenants/${encodeURIComponent(tenant.id)}/sessions/${encodeURIComponent(sessionId)}/revoke`, {});
      setNotice("Session revoked.");
      await refresh();
    } catch (error) {
      setOperationError(errorMessage(error));
    } finally {
      setBusyKey("");
    }
  }

  async function createIntegration(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusyKey("create-integration");
    setOperationError("");
    setNotice("");
    let config: unknown;
    try {
      config = JSON.parse(configText) as unknown;
    } catch {
      setOperationError("Configuration must be valid JSON.");
      setBusyKey("");
      return;
    }
    if (typeof config !== "object" || config === null || Array.isArray(config)) {
      setOperationError("Configuration must be a JSON object.");
      setBusyKey("");
      return;
    }
    try {
      await apiClient.post(`/api/v1/tenants/${encodeURIComponent(tenant.id)}/integrations`, {
        project_id: project.id,
        name: connectionName.trim(),
        connector_kind: connectorKind,
        auth_mode: authMode,
        endpoint_url: endpointUrl.trim(),
        provider: provider.trim(),
        credential_ref: credentialReference.trim(),
        config,
      });
      setConnectionName("");
      setEndpointUrl("");
      setCredentialReference("");
      setConfigText("{}");
      setNotice("Integration created disabled. Activation remains subject to server-side validation and independent approval.");
      await refresh();
    } catch (error) {
      setOperationError(errorMessage(error));
    } finally {
      setBusyKey("");
    }
  }

  async function integrationAction(integration: IntegrationRow, action: "enable" | "disable" | "test"): Promise<void> {
    setBusyKey(integration.id + action);
    setOperationError("");
    setNotice("");
    try {
      const response = await apiClient.post<Envelope<Record<string, unknown>>>(
        `/api/v1/integrations/${encodeURIComponent(integration.id)}/${action}`,
        {},
      );
      const outcome = typeof response.data["outcome"] === "string" ? response.data["outcome"] : "completed";
      setNotice(`${action === "test" ? "Integration check" : `Integration ${action}`} result: ${outcome}.`);
      await refresh();
    } catch (error) {
      setOperationError(errorMessage(error));
    } finally {
      setBusyKey("");
    }
  }

  async function saveNotifications(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (notificationDirty.size === 0 && !notificationDraft.webhookSecret && !notificationDraft.clearSecret) {
      setOperationError("Change at least one notification setting before saving.");
      return;
    }
    setBusyKey("notifications");
    setOperationError("");
    setNotice("");
    const body: Record<string, unknown> = {};
    if (notificationDirty.has("emailEnabled")) body["email_enabled"] = notificationDraft.emailEnabled;
    if (notificationDirty.has("emailTo")) body["email_to"] = notificationDraft.emailTo;
    if (notificationDirty.has("webhookEnabled")) body["webhook_enabled"] = notificationDraft.webhookEnabled;
    if (notificationDirty.has("webhookUrl")) body["webhook_url"] = notificationDraft.webhookUrl;
    if (notificationDraft.webhookSecret) body["webhook_secret"] = notificationDraft.webhookSecret;
    if (notificationDraft.clearSecret) body["keep_secret"] = false;
    try {
      await apiClient.patch(`/api/v1/projects/${encodeURIComponent(project.id)}/notifications/settings`, body);
      setNotice("Notification settings saved. Secret values are write-only.");
      await refresh();
    } catch (error) {
      setOperationError(errorMessage(error));
    } finally {
      setBusyKey("");
    }
  }

  const tabs: Array<{ id: SettingsTab; label: string }> = [
    { id: "organization", label: "Organization" },
    { id: "people", label: "People & sessions" },
    { id: "integrations", label: "Integrations" },
    { id: "notifications", label: "Notifications" },
    { id: "security", label: "Security & API access" },
    { id: "audit", label: "Audit" },
  ];

  return (
    <div className="page-stack">
      <section className="page-heading page-heading-row">
        <div><p className="eyebrow">Workspace control plane</p><h1>Settings</h1><p className="muted">Tenant-aware configuration for <strong>{tenant.name}</strong>.</p></div>
        <button className="button button-secondary" disabled={loading} onClick={() => void refresh()} type="button">{loading ? "Refreshing…" : "Refresh settings"}</button>
      </section>

      <div aria-label="Settings sections" className="settings-tabs" role="tablist">
        {tabs.map((item) => <button aria-controls={`panel-${item.id}`} aria-selected={tab === item.id} className={`settings-tab${tab === item.id ? " selected" : ""}`} id={`tab-${item.id}`} key={item.id} onClick={() => setTab(item.id)} role="tab" tabIndex={tab === item.id ? 0 : -1} type="button">{item.label}</button>)}
      </div>

      {refreshError && <div className="notice" role="status">{refreshError}</div>}
      {operationError && <div className="inline-error" role="alert">{operationError}</div>}
      {notice && <div className="inline-success" role="status">{notice}</div>}

      <div aria-labelledby={`tab-${tab}`} className="settings-tabpanel" id={`panel-${tab}`} role="tabpanel" tabIndex={0}>
        {tab === "organization" && <OrganizationPanel tenant={tenantPanel} projectName={project.name} projectId={project.id} />}
      {tab === "people" && <PeoplePanel
        users={usersPanel}
        sessions={sessionsPanel}
        currentUserId={auth.principal?.principal_id ?? ""}
        busyKey={busyKey}
        newUsername={newUsername}
        newEmail={newEmail}
        newDisplayName={newDisplayName}
        newPassword={newPassword}
        newRole={newRole}
        onUsername={setNewUsername}
        onEmail={setNewEmail}
        onDisplayName={setNewDisplayName}
        onPassword={setNewPassword}
        onRole={setNewRole}
        onCreate={(event) => void createUser(event)}
        onUpdate={(id, body) => void updateUser(id, body)}
        onRevoke={(id) => void revokeSession(id)}
        hasPermission={auth.hasPermission}
      />}
      {tab === "integrations" && <IntegrationsPanel
        catalog={catalogPanel}
        integrations={integrationsPanel}
        connectorKinds={connectorKinds}
        authModes={authModes}
        connectionName={connectionName}
        connectorKind={connectorKind}
        authMode={authMode}
        provider={provider}
        endpointUrl={endpointUrl}
        credentialReference={credentialReference}
        configText={configText}
        busyKey={busyKey}
        selectedProjectConnections={selectedProjectConnections}
        onName={setConnectionName}
        onKind={setConnectorKind}
        onAuthMode={setAuthMode}
        onProvider={setProvider}
        onEndpoint={setEndpointUrl}
        onCredentialReference={setCredentialReference}
        onConfig={setConfigText}
        onCreate={(event) => void createIntegration(event)}
        onAction={integrationAction}
        hasPermission={auth.hasPermission}
      />}
      {tab === "notifications" && <NotificationsPanel
        panel={notificationPanel}
        draft={notificationDraft}
        dirty={notificationDirty.size > 0 || Boolean(notificationDraft.webhookSecret) || notificationDraft.clearSecret}
        busy={busyKey === "notifications"}
        onField={setNotificationField}
        onSave={(event) => void saveNotifications(event)}
        hasPermission={auth.hasPermission}
      />}
      {tab === "security" && <SecurityPanel tenantName={tenant.name} hasPermission={auth.hasPermission} />}
      {tab === "audit" && <AuditPanel audit={auditPanel} />}
      </div>
    </div>
  );
}

function OrganizationPanel({ tenant, projectName, projectId }: { tenant: Panel<Tenant>; projectName: string; projectId: string }): ReactElement {
  const organization = tenant.data;
  return (
    <section className="settings-panel surface-card">
      <div className="section-title-row"><div><p className="eyebrow">Organization profile</p><h2>Tenant information</h2></div><span className={statusClass(organization?.status ?? "unknown")}>{organization?.status ?? "unavailable"}</span></div>
      {tenant.error ? <div className="panel-error" role="alert">{tenant.error}</div> : <dl className="settings-facts"><div><dt>Name</dt><dd>{organization?.name ?? "—"}</dd></div><div><dt>Tenant identifier</dt><dd>{organization?.id ?? "—"}</dd></div><div><dt>Created</dt><dd>{organization?.created_at ? dateTime(organization.created_at) : "—"}</dd></div><div><dt>Current project</dt><dd>{projectName}</dd></div><div><dt>Project identifier</dt><dd>{projectId}</dd></div></dl>}
      <div className="notice notice-muted"><strong>Read-only in API v1.</strong> Organization profile and tenant-level preference write endpoints are not exposed by the current API, so this page does not simulate edits.</div>
    </section>
  );
}

interface PeoplePanelProps {
  users: Panel<UserRow[]>;
  sessions: Panel<SessionRow[]>;
  currentUserId: string;
  busyKey: string;
  newUsername: string;
  newEmail: string;
  newDisplayName: string;
  newPassword: string;
  newRole: string;
  onUsername: (value: string) => void;
  onEmail: (value: string) => void;
  onDisplayName: (value: string) => void;
  onPassword: (value: string) => void;
  onRole: (value: string) => void;
  onCreate: (event: FormEvent<HTMLFormElement>) => void;
  onUpdate: (id: string, body: { roles: string[] } | { status: string }) => void;
  onRevoke: (id: string) => void;
  hasPermission: (permission: string) => boolean;
}

function PeoplePanel(props: PeoplePanelProps): ReactElement {
  const canCreate = props.hasPermission("user.create");
  const canAssign = props.hasPermission("role.assign");
  const canUpdate = props.hasPermission("user.update");
  const canDisable = props.hasPermission("user.disable");
  return (
    <div className="page-stack settings-stack">
      <section className="surface-card settings-panel">
        <div className="section-title-row"><div><p className="eyebrow">Tenant directory</p><h2>Users & roles</h2></div><span className="count-badge">{props.users.data?.length ?? "—"}</span></div>
        {props.users.error ? <div className="panel-error" role="alert">{props.users.error}</div> : !props.users.data?.length ? <p className="muted">No user records are available.</p> : <div className="table-wrap"><table className="data-table settings-table"><thead><tr><th>User</th><th>Roles</th><th>Status</th><th>Last authentication</th><th>Actions</th></tr></thead><tbody>{props.users.data.map((user) => {
          const isSelf = user.id === props.currentUserId;
          const selectedRole = user.roles[0] ?? "viewer";
          const canDisableUser = canDisable && !isSelf && user.status === "active";
          const canReactivateUser = canUpdate && !isSelf && user.status !== "active";
          return (
            <tr key={user.id}>
              <td><span className="table-primary">{user.display_name || user.username}</span><span className="table-sub">{user.email} · {user.username}{isSelf ? " · You" : ""}</span></td>
              <td><select aria-label={`Role for ${user.username}`} disabled={!canAssign || isSelf || props.busyKey === user.id} onChange={(event) => props.onUpdate(user.id, { roles: [event.target.value] })} value={selectedRole}>{ROLE_OPTIONS.map((role) => <option key={role} value={role}>{role.replaceAll("_", " ")}</option>)}</select></td>
              <td><span className={statusClass(user.status)}>{user.status}</span></td>
              <td>{dateTime(user.last_auth_at)}</td>
              <td>
                {canDisableUser
                  ? <button className="mini-action mini-danger" disabled={props.busyKey === user.id} onClick={() => props.onUpdate(user.id, { status: "disabled" })} type="button">Disable</button>
                  : canReactivateUser
                    ? <button className="mini-action" disabled={props.busyKey === user.id} onClick={() => props.onUpdate(user.id, { status: "active" })} type="button">Activate</button>
                    : <span className="muted">—</span>}
              </td>
            </tr>
          );
        })}</tbody></table></div>}
        {!canAssign && <p className="permission-note">{permissionText(props.hasPermission, "role.assign")}</p>}
      </section>

      <section className="surface-card settings-panel">
        <div className="section-title-row"><div><p className="eyebrow">Access administration</p><h2>Create a tenant user</h2></div></div>
        {!canCreate ? <div className="notice">{permissionText(props.hasPermission, "user.create")}</div> : <form className="user-create-grid" onSubmit={props.onCreate}>
          <label>Username<input autoComplete="off" maxLength={32} minLength={3} onChange={(event) => props.onUsername(event.target.value)} required value={props.newUsername} /></label>
          <label>Email<input autoComplete="email" maxLength={254} onChange={(event) => props.onEmail(event.target.value)} required type="email" value={props.newEmail} /></label>
          <label>Display name <span className="optional">Optional</span><input autoComplete="off" maxLength={128} onChange={(event) => props.onDisplayName(event.target.value)} value={props.newDisplayName} /></label>
          <label>Initial password<input autoComplete="new-password" minLength={12} onChange={(event) => props.onPassword(event.target.value)} required type="password" value={props.newPassword} /></label>
          <label>Initial role<select onChange={(event) => props.onRole(event.target.value)} value={props.newRole}>{ROLE_OPTIONS.map((role) => <option key={role} value={role}>{role.replaceAll("_", " ")}</option>)}</select></label>
          <div className="form-actions"><span className="muted">Password is sent once and is never displayed in the response.</span><button className="button button-primary" disabled={props.busyKey === "create-user"} type="submit">{props.busyKey === "create-user" ? "Creating…" : "Create user"}</button></div>
        </form>}
      </section>

      <section className="surface-card settings-panel">
        <div className="section-title-row"><div><p className="eyebrow">Session control</p><h2>Active sessions</h2></div><span className="count-badge">{props.sessions.data?.length ?? "—"}</span></div>
        {props.sessions.error ? <div className="panel-error" role="alert">{props.sessions.error}</div> : !props.sessions.data?.length ? <p className="muted">No active session records are available.</p> : <div className="table-wrap"><table className="data-table settings-table"><thead><tr><th>User</th><th>Authentication</th><th>MFA</th><th>Last seen</th><th>Expires</th><th /></tr></thead><tbody>{props.sessions.data.map((session) => <tr key={session.id}><td><span className="table-primary">{session.username}</span><span className="table-sub">{session.id.slice(0, 12)}</span></td><td>{session.auth_method || "—"}</td><td><span className={statusClass(session.mfa_status)}>{session.mfa_status}</span></td><td>{dateTime(session.last_seen_at || session.created_at)}</td><td>{dateTime(session.expires_at)}</td><td>{props.hasPermission("identity.sessions.revoke") ? <button className="mini-action mini-danger" disabled={props.busyKey === session.id} onClick={() => props.onRevoke(session.id)} type="button">Revoke</button> : <span className="muted">—</span>}</td></tr>)}</tbody></table></div>}
        <p className="privacy-note">Token hashes, IP addresses and browser fingerprints are not displayed.</p>
      </section>
    </div>
  );
}

interface IntegrationsPanelProps {
  catalog: Panel<Catalog>;
  integrations: Panel<IntegrationRow[]>;
  connectorKinds: string[];
  authModes: string[];
  connectionName: string;
  connectorKind: string;
  authMode: string;
  provider: string;
  endpointUrl: string;
  credentialReference: string;
  configText: string;
  busyKey: string;
  selectedProjectConnections: IntegrationRow[];
  onName: (value: string) => void;
  onKind: (value: string) => void;
  onAuthMode: (value: string) => void;
  onProvider: (value: string) => void;
  onEndpoint: (value: string) => void;
  onCredentialReference: (value: string) => void;
  onConfig: (value: string) => void;
  onCreate: (event: FormEvent<HTMLFormElement>) => void;
  onAction: (integration: IntegrationRow, action: "enable" | "disable" | "test") => void;
  hasPermission: (permission: string) => boolean;
}

function IntegrationsPanel(props: IntegrationsPanelProps): ReactElement {
  return (
    <div className="page-stack settings-stack">
      <section className="surface-card settings-panel">
        <div className="section-title-row"><div><p className="eyebrow">External providers</p><h2>Integrations</h2></div><span className="count-badge">{props.integrations.data?.length ?? "—"}</span></div>
        {props.catalog.error && <div className="panel-error" role="alert">{props.catalog.error}</div>}
        {props.integrations.error ? <div className="panel-error" role="alert">{props.integrations.error}</div> : props.selectedProjectConnections.length === 0 ? <div className="empty-state compact-empty"><div className="empty-icon">⌁</div><strong>No project integrations</strong><p>Connections are created disabled and activated only after server-side validation.</p></div> : <div className="integration-list settings-integration-list">{props.selectedProjectConnections.map((item) => <div className="integration-row integration-row-expanded" key={item.id}>
          <span className="integration-mark">{item.connector_kind.slice(0, 1).toUpperCase()}</span><div className="integration-copy"><strong>{item.name}</strong><span>{item.connector_kind.replaceAll("_", " ")} · {item.provider || "provider not specified"}</span><small>{item.endpoint_url || "No endpoint exposed"}</small></div><span className={statusClass(item.health_state || item.status)}>{item.health_state || item.status}</span><div className="row-actions">{props.hasPermission("integration.test") && <button className="mini-action" disabled={props.busyKey === item.id + "test"} onClick={() => props.onAction(item, "test")} type="button">Test</button>}{item.status === "enabled" && props.hasPermission("integration.disable") && <button className="mini-action mini-danger" disabled={props.busyKey === item.id + "disable"} onClick={() => props.onAction(item, "disable")} type="button">Disable</button>}{item.status !== "enabled" && props.hasPermission("integration.enable") && <button className="mini-action" disabled={props.busyKey === item.id + "enable"} onClick={() => props.onAction(item, "enable")} type="button">Enable</button>}</div>
        </div>)}</div>}
        <div className="notice notice-muted"><strong>Activation is a separate approval.</strong> The server enforces creator/approver separation for outbound data flow. A creator cannot enable their own connection.</div>
      </section>

      <section className="surface-card settings-panel">
        <div className="section-title-row"><div><p className="eyebrow">Connection lifecycle</p><h2>Register an integration</h2></div></div>
        {!props.hasPermission("integration.create") ? <div className="notice">{permissionText(props.hasPermission, "integration.create")}</div> : <form className="integration-create-grid" onSubmit={props.onCreate}>
          <label>Display name<input autoComplete="off" maxLength={128} onChange={(event) => props.onName(event.target.value)} required value={props.connectionName} /></label>
          <label>Connector kind<select onChange={(event) => props.onKind(event.target.value)} value={props.connectorKind}>{props.connectorKinds.map((kind) => <option key={kind} value={kind}>{kind.replaceAll("_", " ")}</option>)}</select></label>
          <label>Authentication mode<select onChange={(event) => props.onAuthMode(event.target.value)} value={props.authMode}>{props.authModes.map((mode) => <option key={mode} value={mode}>{mode.replaceAll("_", " ")}</option>)}</select></label>
          <label>Provider identifier<input autoComplete="off" maxLength={64} onChange={(event) => props.onProvider(event.target.value)} value={props.provider} /></label>
          <label className="wide-field">HTTPS endpoint<input autoComplete="url" maxLength={512} onChange={(event) => props.onEndpoint(event.target.value)} placeholder="https://provider.example/path" value={props.endpointUrl} /></label>
          <label className="wide-field">Credential reference <span className="optional">Reference only · never a raw credential</span><input autoComplete="off" maxLength={256} onChange={(event) => props.onCredentialReference(event.target.value)} placeholder="vault://team/provider/credential" value={props.credentialReference} /></label>
          <label className="wide-field">Provider configuration <span className="optional">JSON object · no secret material</span><textarea className="code-input" maxLength={16000} onChange={(event) => props.onConfig(event.target.value)} rows={3} spellCheck={false} value={props.configText} /></label>
          <div className="form-actions"><span className="muted">New connections remain disabled until approved.</span><button className="button button-primary" disabled={props.busyKey === "create-integration"} type="submit">{props.busyKey === "create-integration" ? "Registering…" : "Register disabled integration"}</button></div>
        </form>}
      </section>
    </div>
  );
}

interface NotificationDraft {
  emailEnabled: boolean;
  emailTo: string;
  webhookEnabled: boolean;
  webhookUrl: string;
  webhookSecret: string;
  clearSecret: boolean;
}

interface NotificationPanelProps {
  panel: Panel<NotificationSettings>;
  draft: NotificationDraft;
  dirty: boolean;
  busy: boolean;
  onField: <T extends keyof NotificationDraft>(key: T, value: NotificationDraft[T]) => void;
  onSave: (event: FormEvent<HTMLFormElement>) => void;
  hasPermission: (permission: string) => boolean;
}

function NotificationsPanel(props: NotificationPanelProps): ReactElement {
  const settings = props.panel.data;
  return (
    <section className="surface-card settings-panel">
      <div className="section-title-row"><div><p className="eyebrow">Alert delivery</p><h2>Notification destinations</h2></div><span className={settings?.has_secret ? "status-pill status-configured" : "status-pill status-unchecked"}>{settings?.has_secret ? "Secret configured" : "No secret configured"}</span></div>
      {props.panel.error ? <div className="panel-error" role="alert">{props.panel.error}</div> : !settings ? <p className="muted">Notification configuration is unavailable.</p> : !props.hasPermission("notification.configure") ? <div className="notice">{permissionText(props.hasPermission, "notification.configure")}</div> : <form className="notification-form" onSubmit={props.onSave}>
        <div className="channel-card">
          <div className="channel-heading"><span className="channel-symbol">✉</span><div><strong>Email destination</strong><small>Email transport is provided by a deployment adapter; no SMTP delivery is bundled.</small></div><label className="switch"><span className="sr-only">Enable email notifications</span><input checked={props.draft.emailEnabled} onChange={(event) => props.onField("emailEnabled", event.target.checked)} type="checkbox" /><i /></label></div>
          <label>Email address<input autoComplete="email" disabled={!props.draft.emailEnabled} maxLength={200} onChange={(event) => props.onField("emailTo", event.target.value)} placeholder="security@example.com" type="email" value={props.draft.emailTo} /></label>
        </div>
        <div className="channel-card">
          <div className="channel-heading"><span className="channel-symbol">⌁</span><div><strong>Signed HTTPS webhook</strong><small>Public HTTPS endpoints only. Redirects and private-address destinations are rejected.</small></div><label className="switch"><span className="sr-only">Enable webhook notifications</span><input checked={props.draft.webhookEnabled} onChange={(event) => props.onField("webhookEnabled", event.target.checked)} type="checkbox" /><i /></label></div>
          <label>Webhook URL<input autoComplete="url" disabled={!props.draft.webhookEnabled} maxLength={512} onChange={(event) => props.onField("webhookUrl", event.target.value)} placeholder="https://hooks.example.com/security" value={props.draft.webhookUrl} /></label>
          <label>Webhook secret <span className="optional">Write-only · leave blank to keep the current value</span><input autoComplete="new-password" disabled={!props.draft.webhookEnabled} maxLength={4096} onChange={(event) => { props.onField("webhookSecret", event.target.value); if (event.target.value) props.onField("clearSecret", false); }} placeholder={settings.has_secret ? "Configured — not shown" : "Enter a new signing secret"} type="password" value={props.draft.webhookSecret} /></label>
          {settings.has_secret && <label className="checkbox-row"><input checked={props.draft.clearSecret} onChange={(event) => { props.onField("clearSecret", event.target.checked); if (event.target.checked) props.onField("webhookSecret", ""); }} type="checkbox" /><span>Clear the stored webhook secret</span></label>}
        </div>
        <div className="notice notice-muted"><strong>Redaction is intentional.</strong> Existing URL query secrets are masked in read views. Only changed fields are sent, so leave the URL untouched when you are not rotating the destination.</div>
        <div className="form-actions"><span className="muted">The API never returns webhook secret material.</span><button className="button button-primary" disabled={props.busy || !props.dirty} type="submit">{props.busy ? "Saving…" : "Save notification settings"}</button></div>
      </form>}
    </section>
  );
}

function SecurityPanel({ tenantName, hasPermission }: { tenantName: string; hasPermission: (permission: string) => boolean }): ReactElement {
  return (
    <div className="page-stack settings-stack">
      <section className="surface-card settings-panel">
        <div className="section-title-row"><div><p className="eyebrow">Security posture</p><h2>Tenant security preferences</h2></div><span className="status-pill status-unchecked">API not exposed</span></div>
        <p className="muted">Organization-wide password policy, SSO preferences, retention choices and security preferences are not exposed as customer write endpoints in API v1. The UI does not store browser-only policy values.</p>
        <div className="permission-grid"><div><span>Authenticated role</span><strong>{hasPermission("configuration.read") ? "Configuration read" : "Restricted"}</strong></div><div><span>Session token strategy</span><strong>In-memory bearer token</strong></div><div><span>Tenant context</span><strong>{tenantName}</strong></div></div>
      </section>
      <section className="surface-card settings-panel">
        <div className="section-title-row"><div><p className="eyebrow">API access</p><h2>Credentials & developer access</h2></div><span className="status-pill status-unchecked">No credential-management route</span></div>
        <p className="muted">This v1 API does not expose API credential creation, listing or revocation. No token is generated or displayed here. Existing credentials remain governed by the server-side identity service.</p>
        <div className="notice notice-muted">The current browser session is not persisted to local storage, session storage, IndexedDB or cookies. Sign out or close the tab to clear its in-memory bearer token.</div>
      </section>
    </div>
  );
}

function AuditPanel({ audit }: { audit: Panel<AuditRow[]> }): ReactElement {
  return (
    <section className="surface-card settings-panel">
      <div className="section-title-row"><div><p className="eyebrow">Immutable activity</p><h2>Tenant audit events</h2></div><span className="count-badge">{audit.data?.length ?? "—"}</span></div>
      {audit.error ? <div className="panel-error" role="alert">{audit.error}</div> : !audit.data?.length ? <p className="muted">No audit events are available in this window.</p> : <div className="table-wrap"><table className="data-table settings-table"><thead><tr><th>Action</th><th>Actor</th><th>Object</th><th>Reference</th><th>Time</th></tr></thead><tbody>{audit.data.map((event) => <tr key={event.id}><td><span className="action-badge">{event.action}</span></td><td>{event.actor}</td><td>{event.object_type}</td><td><span className="table-sub">{event.object_id.slice(0, 16)}</span></td><td>{dateTime(event.ts)}</td></tr>)}</tbody></table></div>}
      <p className="privacy-note">Events are filtered to the authenticated tenant. Secret-shaped metadata is redacted by the API.</p>
    </section>
  );
}
