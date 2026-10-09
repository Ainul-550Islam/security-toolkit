import { createContext, useCallback, useContext, useEffect, useMemo, useState, type FormEvent, type ReactElement, type ReactNode } from "react";
import {
  Link,
  Navigate,
  NavLink,
  Outlet,
  Route,
  Routes,
} from "react-router-dom";
import { ApiError, apiClient } from "../lib/api";
import { useAuth } from "../lib/auth";
import { OverviewPage } from "../pages/OverviewPage";
import { ScansPage } from "../pages/ScansPage";
import { FindingsPage } from "../pages/FindingsPage";
import { SettingsPage } from "../pages/SettingsPage";

export interface Tenant {
  id: string;
  name: string;
  status?: string;
  created_at?: string;
}

export interface Project {
  id: string;
  org_id: string;
  name: string;
  description?: string;
  status?: string;
  created_at?: string;
}

interface ApiEnvelope<T> {
  data: T;
  count?: number;
}

export interface WorkspaceValue {
  tenant: Tenant;
  projects: Project[];
  projectId: string;
  project: Project;
  selectProject: (projectId: string) => void;
  reloadWorkspace: () => Promise<void>;
}

interface WorkspaceState {
  tenant: Tenant | null;
  projects: Project[];
  projectId: string;
  loading: boolean;
  error: string;
}

const WorkspaceContext = createContext<WorkspaceValue | null>(null);

function messageFrom(error: unknown): string {
  return error instanceof ApiError ? error.message : "The workspace could not be loaded.";
}

function WorkspaceProvider({ children }: { children: ReactNode }): ReactElement {
  const { principal } = useAuth();
  const [state, setState] = useState<WorkspaceState>({
    tenant: null,
    projects: [],
    projectId: "",
    loading: true,
    error: "",
  });

  const reloadWorkspace = useCallback(async (signal?: AbortSignal): Promise<void> => {
    if (!principal?.tenant_id) {
      setState({ tenant: null, projects: [], projectId: "", loading: false, error: "The signed-in principal has no tenant." });
      return;
    }
    setState((current) => ({ ...current, loading: true, error: "" }));
    try {
      const requestOptions = signal ? { signal } : {};
      const [tenantResponse, projectResponse] = await Promise.all([
        apiClient.get<ApiEnvelope<Tenant>>("/api/v1/tenants", requestOptions),
        apiClient.get<ApiEnvelope<Project[]>>(
          `/api/v1/tenants/${encodeURIComponent(principal.tenant_id)}/projects`,
          requestOptions,
        ),
      ]);
      const projects = Array.isArray(projectResponse.data) ? projectResponse.data : [];
      setState((current) => ({
        tenant: tenantResponse.data,
        projects,
        projectId: projects.some((project) => project.id === current.projectId)
          ? current.projectId
          : (projects[0]?.id ?? ""),
        loading: false,
        error: "",
      }));
    } catch (caught) {
      if (signal?.aborted) return;
      setState((current) => ({ ...current, loading: false, error: messageFrom(caught) }));
    }
  }, [principal?.tenant_id]);

  useEffect(() => {
    const controller = new AbortController();
    void reloadWorkspace(controller.signal);
    return () => controller.abort();
  }, [reloadWorkspace]);

  const selectProject = useCallback((projectId: string): void => {
    setState((current) => current.projects.some((project) => project.id === projectId)
      ? { ...current, projectId }
      : current);
  }, []);

  const value = useMemo((): WorkspaceValue | null => {
    const tenant = state.tenant;
    const project = state.projects.find((candidate) => candidate.id === state.projectId);
    if (!tenant || !project) return null;
    return {
      tenant,
      projects: state.projects,
      projectId: project.id,
      project,
      selectProject,
      reloadWorkspace: () => reloadWorkspace(),
    };
  }, [state, selectProject, reloadWorkspace]);

  if (state.loading) {
    return <div className="full-screen-state"><span className="spinner" aria-hidden="true" /><p>Loading your tenant workspace…</p></div>;
  }
  if (state.error) {
    return (
      <div className="full-screen-state">
        <div className="state-card">
          <p className="eyebrow">Workspace unavailable</p>
          <h1>We couldn’t load your workspace</h1>
          <p className="muted">{state.error}</p>
          <button className="button button-primary" onClick={() => void reloadWorkspace()} type="button">Try again</button>
        </div>
      </div>
    );
  }
  if (!state.tenant) {
    return <div className="full-screen-state"><p className="muted">No tenant is available for this account.</p></div>;
  }
  if (state.projects.length === 0) {
    return <ProjectSetup tenant={state.tenant} onCreated={() => reloadWorkspace()} />;
  }
  if (!value) {
    return <div className="full-screen-state"><span className="spinner" aria-hidden="true" /><p>Loading project context…</p></div>;
  }
  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

function ProjectSetup({ tenant, onCreated }: { tenant: Tenant; onCreated: () => Promise<void> }): ReactElement {
  const { hasPermission } = useAuth();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await apiClient.post(`/api/v1/tenants/${encodeURIComponent(tenant.id)}/projects`, {
        name: name.trim(),
        description: description.trim(),
      });
      await onCreated();
    } catch (caught) {
      setError(messageFrom(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="full-screen-state">
      <div className="state-card setup-card">
        <div className="brand-mark brand-mark-large">S</div>
        <p className="eyebrow">{tenant.name}</p>
        <h1>Start with a project</h1>
        <p className="muted">Projects define the authorized scope for assets, scans, findings and reports. Nothing is scanned until you create and authorize a scope.</p>
        {hasPermission("project.create") ? (
          <form className="stack-form" onSubmit={(event) => void submit(event)}>
            <label>Project name<input autoComplete="off" maxLength={128} onChange={(event) => setName(event.target.value)} required value={name} /></label>
            <label>Description <span className="optional">Optional</span><textarea maxLength={2000} onChange={(event) => setDescription(event.target.value)} rows={3} value={description} /></label>
            {error && <p className="inline-error" role="alert">{error}</p>}
            <button className="button button-primary" disabled={busy || !name.trim()} type="submit">{busy ? "Creating…" : "Create project"}</button>
          </form>
        ) : (
          <p className="notice">A tenant administrator with <code>project.create</code> permission must create the first project.</p>
        )}
      </div>
    </div>
  );
}

export function useWorkspace(): WorkspaceValue {
  const value = useContext(WorkspaceContext);
  if (!value) throw new Error("useWorkspace must be used inside the authenticated workspace");
  return value;
}

function LoginPage(): ReactElement {
  const auth = useAuth();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setLocalError("");
    try {
      await auth.login(identifier.trim(), password);
      setPassword("");
    } catch (caught) {
      setLocalError(messageFrom(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-layout">
      <section className="login-brand-panel">
        <div className="brand-lockup"><div className="brand-mark brand-mark-large">S</div><span>SecuToolkit</span></div>
        <div className="login-hero-copy">
          <p className="eyebrow">Security operations</p>
          <h1>Know what matters.<br />Act with confidence.</h1>
          <p>One tenant-scoped workspace for authorized assets, security findings and scan operations.</p>
        </div>
        <div className="login-footer">Built for evidence-led security work.</div>
      </section>
      <section className="login-form-panel">
        <form className="login-form" onSubmit={(event) => void submit(event)}>
          <p className="eyebrow">Welcome back</p>
          <h2>Sign in to your workspace</h2>
          <p className="muted">Use your SecuToolkit account. Your session token stays in memory and is cleared when you sign out or close this page.</p>
          <label>Email or username<input autoComplete="username" autoFocus maxLength={256} onChange={(event) => setIdentifier(event.target.value)} required value={identifier} /></label>
          <label>Password<input autoComplete="current-password" maxLength={1024} onChange={(event) => setPassword(event.target.value)} required type="password" value={password} /></label>
          {(localError || auth.error) && <div className="inline-error" role="alert">{localError || auth.error}</div>}
          <button className="button button-primary button-wide" disabled={busy || !identifier.trim() || !password} type="submit">{busy ? "Signing in…" : "Sign in"}</button>
          <p className="form-footnote">Authentication and permissions are enforced by the API. This browser does not persist passwords or bearer tokens.</p>
        </form>
      </section>
    </main>
  );
}

function AppLayout(): ReactElement {
  const auth = useAuth();
  const workspace = useWorkspace();
  const displayName = auth.principal?.principal_id ?? "Authenticated user";
  const initials = displayName.slice(0, 1).toUpperCase();

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link aria-label="SecuToolkit overview" className="brand-lockup" to="/">
          <div className="brand-mark">S</div><span>SecuToolkit</span>
        </Link>
        <div className="workspace-label">WORKSPACE</div>
        <nav aria-label="Primary navigation" className="side-nav">
          <NavLink end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`} to="/">
            <span className="nav-icon">⌂</span><span>Overview</span>
          </NavLink>
          <NavLink className={({ isActive }) => `nav-link${isActive ? " active" : ""}`} to="/scans">
            <span className="nav-icon">◷</span><span>Scans</span>
          </NavLink>
          <NavLink className={({ isActive }) => `nav-link${isActive ? " active" : ""}`} to="/findings">
            <span className="nav-icon">◇</span><span>Findings</span>
          </NavLink>
          <NavLink className={({ isActive }) => `nav-link${isActive ? " active" : ""}`} to="/settings">
            <span className="nav-icon">⚙</span><span>Settings</span>
          </NavLink>
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-security"><span className="status-dot status-dot-green" /> API authenticated</div>
          <div className="profile-row">
            <div className="avatar">{initials}</div>
            <div className="profile-copy"><strong>{displayName}</strong><span>{auth.principal?.roles.join(" · ") || "Workspace member"}</span></div>
            <button aria-label="Sign out" className="icon-button logout-button" onClick={() => void auth.logout()} title="Sign out" type="button">↗</button>
          </div>
        </div>
      </aside>
      <div className="main-area">
        <header className="topbar">
          <div className="breadcrumb"><span>{workspace.tenant.name}</span><span className="breadcrumb-divider">/</span><strong>{workspace.project.name}</strong></div>
          <div className="topbar-actions">
            <label className="project-picker-label" htmlFor="project-picker">Project</label>
            <select
              aria-label="Select project"
              className="project-picker"
              id="project-picker"
              onChange={(event) => workspace.selectProject(event.target.value)}
              value={workspace.projectId}
            >
              {workspace.projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}
            </select>
            <button aria-label="Refresh workspace" className="icon-button refresh-button" onClick={() => void workspace.reloadWorkspace()} title="Refresh workspace" type="button">↻</button>
          </div>
        </header>
        <main className="page-content"><Outlet /></main>
      </div>
    </div>
  );
}

function Startup(): ReactElement {
  return <div className="full-screen-state"><span className="spinner" aria-hidden="true" /><p>Checking your secure session…</p></div>;
}

function ProtectedRoutes(): ReactElement {
  const auth = useAuth();
  if (auth.status === "checking") return <Startup />;
  if (auth.status !== "authenticated" || !auth.principal) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate replace to="/login" />} />
      </Routes>
    );
  }
  return (
    <WorkspaceProvider>
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<OverviewPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
        <Route path="/login" element={<Navigate replace to="/" />} />
      </Routes>
    </WorkspaceProvider>
  );
}

function NotFoundPage(): ReactElement {
  return (
    <section className="state-card page-state-card">
      <p className="eyebrow">404 · Not found</p>
      <h1>This page isn’t in your workspace</h1>
      <p className="muted">The route is not part of the current customer UI.</p>
      <Link className="button button-primary" to="/">Return to overview</Link>
    </section>
  );
}

export default function App(): ReactElement {
  return <ProtectedRoutes />;
}
