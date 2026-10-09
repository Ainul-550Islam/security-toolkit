// @vitest-environment jsdom
import { act, type ReactElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "../lib/api";
import { FindingsPage } from "./FindingsPage";
import { OverviewPage } from "./OverviewPage";
import { ScansPage } from "./ScansPage";
import { SettingsPage } from "./SettingsPage";

(Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true }));

const SECRET_SENTINEL = "write-only-notification-secret-must-not-render";
const mocks = vi.hoisted(() => ({
  workspace: {
    tenant: { id: "tenant-1", name: "Northwind Security", status: "active" },
    project: { id: "project-1", org_id: "tenant-1", name: "Northwind Cloud", status: "active" },
  },
  auth: {
    principal: { principal_id: "user-1" },
    hasPermission: (_permission: string): boolean => true,
  },
}));

vi.mock("../app/App", () => ({
  useWorkspace: () => mocks.workspace,
}));

vi.mock("../lib/auth", () => ({
  useAuth: () => mocks.auth,
}));

function apiResponse(path: string): unknown {
  if (path.endsWith("/dashboard")) {
    return {
      data: {
        posture: { score: 72, level: "good" },
        kpis: { open_total: 0, open_critical: 0, open_high: 0 },
        risk: { count: 0, by_severity: {} },
        assets: { total: 0, internet_facing: 0, recently_discovered_30d: 0 },
        monitoring: { health: { health: "unknown", score: 0 } },
      },
    };
  }
  if (path === "/api/v1/scan-profiles") return { data: [] };
  if (path.includes("/scans")) return { data: [] };
  if (path.includes("/assets")) return { data: [] };
  if (path.includes("/findings")) return { data: [] };
  if (path.includes("/integration-health")) return { data: { total: 0, items: [], states: {} } };
  if (path.includes("/integration-catalog")) {
    return { data: { connector_kinds: [], auth_modes: [], capabilities: {} } };
  }
  if (path.includes("/notifications/settings")) {
    return {
      data: {
        project_id: "project-1",
        email_enabled: false,
        email_to: "",
        webhook_enabled: false,
        webhook_url: "",
        has_secret: true,
        webhook_secret: SECRET_SENTINEL,
      },
    };
  }
  if (path === "/api/v1/tenants") {
    return { data: { id: "tenant-1", name: "Northwind Security", status: "active" } };
  }
  if (path.includes("/users") || path.includes("/sessions") || path.includes("/integrations") || path.includes("/audit-events")) {
    return { data: [] };
  }
  throw new Error(`Unexpected page API path: ${path}`);
}

describe("customer page states", () => {
  let container: HTMLDivElement;
  let root: Root | null;

  beforeEach(() => {
    root = null;
    container = document.createElement("div");
    document.body.appendChild(container);
    vi.spyOn(apiClient, "get").mockImplementation(async (path: string) => apiResponse(path) as never);
  });

  afterEach(async () => {
    if (root) {
      const mountedRoot = root;
      await act(async () => {
        mountedRoot.unmount();
      });
    }
    root = null;
    container.remove();
    vi.restoreAllMocks();
  });

  async function mount(page: ReactElement): Promise<void> {
    const mountedRoot = createRoot(container);
    root = mountedRoot;
    await act(async () => {
      mountedRoot.render(<MemoryRouter>{page}</MemoryRouter>);
      await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
    });
  }

  it("renders an overview from the API and shows real empty states", async () => {
    await mount(<OverviewPage />);

    expect(container.querySelector("h1")?.textContent).toBe("Northwind Cloud");
    expect(container.textContent).toContain("No scans have been queued for this project.");
    expect(container.textContent).toContain("No findings are recorded for this project yet.");
    expect(container.textContent).toContain("No integrations registered");
    expect(container.textContent).not.toContain("sample scan");
  });

  it("renders scan-profile and history empty states without inventing scan results", async () => {
    await mount(<ScansPage />);

    expect(container.querySelector("h1")?.textContent).toBe("Scans");
    expect(container.textContent).toContain("No API-supported profiles");
    expect(container.textContent).toContain("No scans found");
    expect(container.textContent).not.toContain("completed scan");
  });

  it("renders an empty findings queue from the API response", async () => {
    await mount(<FindingsPage />);

    expect(container.querySelector("h1")?.textContent).toBe("Findings");
    expect(container.textContent).toContain("No findings recorded");
    expect(container.textContent).not.toContain("Critical finding");
  });

  it("renders tenant settings and marks unsupported API actions as unavailable", async () => {
    await mount(<SettingsPage />);

    expect(container.querySelector("h1")?.textContent).toBe("Settings");
    expect(container.textContent).toContain("Northwind Security");
    expect(container.textContent).toContain("Read-only in API v1.");
    const securityTab = Array.from(container.querySelectorAll<HTMLButtonElement>("[role=tab]"))
      .find((button) => button.textContent?.trim() === "Security & API access");
    if (!securityTab) throw new Error("Security & API access tab was not rendered");
    await act(async () => {
      securityTab.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });
    expect(container.textContent).toContain("No credential-management route");
  });

  it("never renders a notification secret returned in an unexpected response field", async () => {
    await mount(<SettingsPage />);
    const notificationTab = Array.from(container.querySelectorAll<HTMLButtonElement>("[role=tab]"))
      .find((button) => button.textContent?.trim() === "Notifications");
    if (!notificationTab) throw new Error("Notifications tab was not rendered");
    await act(async () => {
      notificationTab.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    });

    const secretInput = container.querySelector<HTMLInputElement>('input[type="password"]');
    expect(container.textContent).toContain("Secret configured");
    expect(secretInput?.value).toBe("");
    expect(secretInput?.placeholder).toBe("Configured — not shown");
    expect(container.textContent).not.toContain(SECRET_SENTINEL);
  });
});
