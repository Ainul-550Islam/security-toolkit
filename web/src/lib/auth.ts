import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactElement,
  type ReactNode,
} from "react";
import { ApiError, apiClient, hasInMemoryAccessToken, setInMemoryAccessToken } from "./api";

export interface Principal {
  principal_id: string;
  tenant_id: string;
  subject_type: "user" | "api_credential" | "service";
  roles: string[];
  permissions: string[];
  authentication_method: string;
  session_id: string;
  credential_id: string;
}

export type AuthStatus = "checking" | "authenticated" | "anonymous";

interface TokenGrant {
  access_token: string;
  token_type: string;
  expires_at: string;
  mfa_required: boolean;
  mfa_status: string;
  principal: unknown;
}

interface SessionResponse {
  data: {
    principal: unknown;
    mfa_status?: string;
    step_up_until?: string;
    expires_at?: string;
  };
}

interface AuthContextValue {
  status: AuthStatus;
  principal: Principal | null;
  error: string;
  hasPermission: (permission: string) => boolean;
  login: (identifier: string, password: string) => Promise<void>;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedString(value: unknown, maximum: number): string {
  return typeof value === "string" && value.length <= maximum ? value : "";
}

function normalizePrincipal(value: unknown): Principal | null {
  if (!isRecord(value)) return null;
  const principalId = boundedString(value["principal_id"], 160);
  const tenantId = boundedString(value["tenant_id"], 160);
  const subjectType = value["subject_type"];
  const roles = value["roles"];
  const permissions = value["permissions"];
  if (
    !principalId ||
    !tenantId ||
    (subjectType !== "user" && subjectType !== "api_credential" && subjectType !== "service") ||
    !Array.isArray(roles) ||
    !Array.isArray(permissions)
  ) {
    return null;
  }
  const safeRoles = roles.filter((item): item is string => typeof item === "string" && item.length > 0 && item.length <= 64).slice(0, 32);
  const safePermissions = permissions.filter((item): item is string => typeof item === "string" && item.length > 0 && item.length <= 128).slice(0, 512);
  return {
    principal_id: principalId,
    tenant_id: tenantId,
    subject_type: subjectType,
    roles: safeRoles,
    permissions: safePermissions,
    authentication_method: boundedString(value["authentication_method"], 64),
    session_id: boundedString(value["session_id"], 160),
    credential_id: boundedString(value["credential_id"], 160),
  };
}

function validGrant(value: unknown): TokenGrant | null {
  if (!isRecord(value)) return null;
  const accessToken = boundedString(value["access_token"], 4096);
  const tokenType = boundedString(value["token_type"], 16);
  const expiresAt = boundedString(value["expires_at"], 64);
  const expiryTime = Date.parse(expiresAt);
  if (
    !accessToken ||
    tokenType.toLowerCase() !== "bearer" ||
    !expiresAt ||
    !Number.isFinite(expiryTime) ||
    expiryTime <= Date.now() ||
    typeof value["mfa_required"] !== "boolean"
  ) {
    return null;
  }
  return {
    access_token: accessToken,
    token_type: tokenType,
    expires_at: expiresAt,
    mfa_required: value["mfa_required"],
    mfa_status: boundedString(value["mfa_status"], 32),
    principal: value["principal"],
  };
}

export function AuthProvider({ children }: { children: ReactNode }): ReactElement {
  const [status, setStatus] = useState<AuthStatus>("checking");
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [sessionExpiresAt, setSessionExpiresAt] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    if (!hasInMemoryAccessToken()) {
      setPrincipal(null);
      setSessionExpiresAt("");
      setStatus("anonymous");
      return () => controller.abort();
    }
    setStatus("checking");
    apiClient.get<SessionResponse>("/api/v1/auth/session", { signal: controller.signal })
      .then((response) => {
        const safePrincipal = normalizePrincipal(response.data.principal);
        if (!safePrincipal) throw new ApiError(502, "invalid_session", "The session response is invalid.");
        setPrincipal(safePrincipal);
        setSessionExpiresAt(boundedString(response.data.expires_at, 64));
        setError("");
        setStatus("authenticated");
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return;
        setInMemoryAccessToken(null);
        setPrincipal(null);
        setSessionExpiresAt("");
        setStatus("anonymous");
        setError(caught instanceof ApiError ? caught.message : "The session could not be restored.");
      });
    return () => controller.abort();
  }, []);

  const login = useCallback(async (identifier: string, password: string): Promise<void> => {
    setError("");
    setStatus("checking");
    try {
      const response = await apiClient.post<TokenGrant>("/api/v1/auth/login", { identifier, password });
      const grant = validGrant(response);
      if (!grant) {
        throw new ApiError(502, "invalid_login_response", "The sign-in response is invalid.");
      }
      if (grant.mfa_required) {
        setInMemoryAccessToken(null);
        setSessionExpiresAt("");
        throw new ApiError(
          403,
          "mfa_verification_required",
          "This account requires multi-factor verification. The current API does not expose an MFA verification route.",
        );
      }
      const safePrincipal = normalizePrincipal(grant.principal);
      if (!safePrincipal) {
        throw new ApiError(502, "invalid_login_response", "The sign-in response is invalid.");
      }
      setInMemoryAccessToken(grant.access_token);
      setPrincipal(safePrincipal);
      setSessionExpiresAt(grant.expires_at);
      setStatus("authenticated");
    } catch (caught) {
      setInMemoryAccessToken(null);
      setPrincipal(null);
      setSessionExpiresAt("");
      setStatus("anonymous");
      const safeMessage = caught instanceof ApiError ? caught.message : "Sign-in could not be completed.";
      setError(safeMessage);
      throw caught instanceof ApiError ? caught : new ApiError(0, "sign_in_failed", safeMessage);
    }
  }, []);

  const refresh = useCallback(async (): Promise<void> => {
    if (!hasInMemoryAccessToken()) {
      throw new ApiError(401, "authentication_failed", "Sign in again to continue.");
    }
    try {
      const response = await apiClient.post<TokenGrant>("/api/v1/auth/refresh", {});
      const grant = validGrant(response);
      const safePrincipal = normalizePrincipal(grant?.principal);
      if (!grant || !safePrincipal || grant.mfa_required) {
        throw new ApiError(401, "authentication_failed", "The session could not be refreshed.");
      }
      setInMemoryAccessToken(grant.access_token);
      setPrincipal(safePrincipal);
      setSessionExpiresAt(grant.expires_at);
      setStatus("authenticated");
      setError("");
    } catch (caught) {
      if (caught instanceof ApiError && [401, 403].includes(caught.status)) {
        setInMemoryAccessToken(null);
        setPrincipal(null);
        setSessionExpiresAt("");
        setStatus("anonymous");
        setError("Your session is no longer valid. Sign in again.");
      }
      throw caught instanceof ApiError ? caught : new ApiError(0, "session_refresh_failed", "The session could not be refreshed.");
    }
  }, []);

  useEffect(() => {
    if (status !== "authenticated" || !sessionExpiresAt) return;
    const expiryTime = Date.parse(sessionExpiresAt);
    const clearLocalSession = (message: string): void => {
      setInMemoryAccessToken(null);
      setPrincipal(null);
      setSessionExpiresAt("");
      setStatus("anonymous");
      setError(message);
    };
    if (!Number.isFinite(expiryTime) || expiryTime <= Date.now()) {
      clearLocalSession("Your session has expired. Sign in again.");
      return;
    }

    let active = true;
    let timer: number | undefined;
    const attemptRefresh = async (): Promise<void> => {
      try {
        await refresh();
      } catch (caught) {
        if (!active || (caught instanceof ApiError && [401, 403].includes(caught.status))) return;
        const remaining = expiryTime - Date.now();
        if (remaining <= 0) {
          clearLocalSession("Your session has expired. Sign in again.");
          return;
        }
        setError("Session renewal is temporarily unavailable. Retrying before expiry.");
        timer = window.setTimeout(() => void attemptRefresh(), Math.min(30_000, remaining));
      }
    };

    const refreshDelay = Math.max(0, expiryTime - Date.now() - 60_000);
    timer = window.setTimeout(() => void attemptRefresh(), refreshDelay);
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [status, sessionExpiresAt, refresh]);

  const logout = useCallback(async (): Promise<void> => {
    let revocationWarning = "";
    try {
      if (hasInMemoryAccessToken()) {
        await apiClient.post<undefined>("/api/v1/auth/logout", {});
      }
    } catch {
      revocationWarning = "Your local session was cleared, but server-side revocation could not be confirmed.";
    } finally {
      setInMemoryAccessToken(null);
      setPrincipal(null);
      setSessionExpiresAt("");
      setStatus("anonymous");
      setError(revocationWarning);
    }
  }, []);

  const hasPermission = useCallback(
    (permission: string): boolean => principal?.permissions.includes(permission) ?? false,
    [principal],
  );

  const value = useMemo<AuthContextValue>(() => ({
    status,
    principal,
    error,
    hasPermission,
    login,
    refresh,
    logout,
  }), [status, principal, error, hasPermission, login, refresh, logout]);

  return createElement(AuthContext.Provider, { value }, children);
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}
