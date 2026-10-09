// @vitest-environment jsdom
import { act, type ReactElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiClient, hasInMemoryAccessToken, setInMemoryAccessToken } from "./api";
import { AuthProvider, useAuth } from "./auth";

(Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true }));

const VALID_PRINCIPAL = {
  principal_id: "user-1",
  tenant_id: "tenant-1",
  subject_type: "user" as const,
  roles: ["analyst"],
  permissions: ["scan.create", "finding.read"],
  authentication_method: "password",
  session_id: "session-1",
  credential_id: "",
};

function grant(overrides: Partial<{
  access_token: string;
  token_type: string;
  expires_at: string;
  mfa_required: boolean;
  mfa_status: string;
  principal: unknown;
}> = {}): Record<string, unknown> {
  return {
    access_token: "temporary-in-memory-access-token",
    token_type: "Bearer",
    expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    mfa_required: false,
    mfa_status: "verified",
    principal: VALID_PRINCIPAL,
    ...overrides,
  };
}

function AuthProbe(): ReactElement {
  const auth = useAuth();
  return (
    <main>
      <output data-testid="status">{auth.status}</output>
      <output data-testid="principal">{auth.principal?.principal_id ?? ""}</output>
      <output data-testid="scan-permission">{auth.hasPermission("scan.create") ? "granted" : "denied"}</output>
      <output data-testid="admin-permission">{auth.hasPermission("platform.admin") ? "granted" : "denied"}</output>
      <output data-testid="error">{auth.error}</output>
      <button data-action="login" onClick={() => void auth.login("analyst@example.test", "not-stored-password").catch(() => undefined)} type="button">Sign in</button>
      <button data-action="logout" onClick={() => void auth.logout()} type="button">Sign out</button>
    </main>
  );
}

describe("AuthProvider session state", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    setInMemoryAccessToken(null);
    window.localStorage.clear();
    window.sessionStorage.clear();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => {
      root.unmount();
    });
    container.remove();
    setInMemoryAccessToken(null);
    vi.restoreAllMocks();
  });

  async function mount(): Promise<void> {
    await act(async () => {
      root.render(<AuthProvider><AuthProbe /></AuthProvider>);
      await Promise.resolve();
      await Promise.resolve();
    });
  }

  async function click(action: "login" | "logout"): Promise<void> {
    const button = container.querySelector<HTMLButtonElement>(`[data-action="${action}"]`);
    if (!button) throw new Error(`Missing ${action} action in auth probe`);
    await act(async () => {
      button.dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await Promise.resolve();
      await Promise.resolve();
    });
  }

  it("starts anonymous and denies permissions when no in-memory session exists", async () => {
    await mount();

    expect(container.querySelector('[data-testid="status"]')?.textContent).toBe("anonymous");
    expect(container.querySelector('[data-testid="scan-permission"]')?.textContent).toBe("denied");
    expect(container.querySelector('[data-testid="admin-permission"]')?.textContent).toBe("denied");
    expect(hasInMemoryAccessToken()).toBe(false);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it("authenticates a validated login response using memory-only session state", async () => {
    vi.spyOn(apiClient, "post").mockResolvedValue(grant() as never);
    await mount();
    await click("login");

    expect(container.querySelector('[data-testid="status"]')?.textContent).toBe("authenticated");
    expect(container.querySelector('[data-testid="principal"]')?.textContent).toBe("user-1");
    expect(container.querySelector('[data-testid="scan-permission"]')?.textContent).toBe("granted");
    expect(container.querySelector('[data-testid="admin-permission"]')?.textContent).toBe("denied");
    expect(hasInMemoryAccessToken()).toBe(true);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it("clears credentials and fails closed for an invalid principal response", async () => {
    vi.spyOn(apiClient, "post").mockResolvedValue(grant({
      principal: {
        principal_id: "",
        tenant_id: "tenant-1",
        subject_type: "user",
        roles: ["admin"],
        permissions: ["platform.admin"],
      },
    }) as never);
    await mount();
    await click("login");

    expect(container.querySelector('[data-testid="status"]')?.textContent).toBe("anonymous");
    expect(container.querySelector('[data-testid="principal"]')?.textContent).toBe("");
    expect(container.querySelector('[data-testid="error"]')?.textContent).toBe("The sign-in response is invalid.");
    expect(hasInMemoryAccessToken()).toBe(false);
  });

  it("does not retain a bearer token when MFA is required but unavailable", async () => {
    vi.spyOn(apiClient, "post").mockResolvedValue(grant({ mfa_required: true }) as never);
    await mount();
    await click("login");

    expect(container.querySelector('[data-testid="status"]')?.textContent).toBe("anonymous");
    expect(container.querySelector('[data-testid="error"]')?.textContent).toContain("requires multi-factor verification");
    expect(hasInMemoryAccessToken()).toBe(false);
  });

  it("restores only a valid server-issued session principal", async () => {
    setInMemoryAccessToken("existing-memory-token");
    vi.spyOn(apiClient, "get").mockResolvedValue({
      data: {
        principal: VALID_PRINCIPAL,
        expires_at: new Date(Date.now() + 3_600_000).toISOString(),
      },
    } as never);

    await mount();

    expect(container.querySelector('[data-testid="status"]')?.textContent).toBe("authenticated");
    expect(container.querySelector('[data-testid="principal"]')?.textContent).toBe("user-1");
    expect(container.querySelector('[data-testid="scan-permission"]')?.textContent).toBe("granted");
  });

  it("clears memory state after logout even when server revocation is unavailable", async () => {
    setInMemoryAccessToken("existing-memory-token");
    vi.spyOn(apiClient, "get").mockResolvedValue({
      data: {
        principal: VALID_PRINCIPAL,
        expires_at: new Date(Date.now() + 3_600_000).toISOString(),
      },
    } as never);
    vi.spyOn(apiClient, "post").mockRejectedValue(new Error("provider-secret /private/traceback"));
    await mount();
    await click("logout");

    expect(container.querySelector('[data-testid="status"]')?.textContent).toBe("anonymous");
    expect(container.querySelector('[data-testid="principal"]')?.textContent).toBe("");
    expect(container.querySelector('[data-testid="error"]')?.textContent).toBe("Your local session was cleared, but server-side revocation could not be confirmed.");
    expect(container.textContent).not.toContain("provider-secret");
    expect(container.textContent).not.toContain("/private/traceback");
    expect(hasInMemoryAccessToken()).toBe(false);
  });
});
