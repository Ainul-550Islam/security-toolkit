export interface ApiFieldViolation {
  field: string;
  code: string;
  message: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string;
  readonly fields: readonly ApiFieldViolation[];

  constructor(
    status: number,
    code: string,
    message: string,
    requestId = "",
    fields: readonly ApiFieldViolation[] = [],
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.fields = fields;
  }
}

export interface ApiRequestOptions {
  method?: "GET" | "POST" | "PATCH";
  body?: unknown;
  headers?: Readonly<Record<string, string>>;
  signal?: AbortSignal;
  timeoutMs?: number;
  idempotencyKey?: string;
}

export interface ApiClientOptions {
  fetcher?: typeof fetch;
  tokenProvider?: () => string;
  basePath?: string;
  defaultTimeoutMs?: number;
}

interface UnknownRecord {
  [key: string]: unknown;
}

const MAX_RESPONSE_BYTES = 4_000_000;
const MAX_REQUEST_BYTES = 4_000_000;
const REQUEST_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$/;
const ERROR_CODE_RE = /^[a-z][a-z0-9_]{0,79}$/;
const FIELD_NAME_RE = /^[A-Za-z][A-Za-z0-9_.-]{0,95}$/;
const PUBLIC_ERROR_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  authentication_failed: "Authentication is required or invalid. Sign in again.",
  forbidden: "You do not have permission to perform this action.",
  scope_denied: "This operation is outside the authorized project or tenant scope.",
  not_found: "The requested resource was not found.",
  conflict: "The requested change conflicts with existing data.",
  invalid_state_transition: "The requested state change is not allowed.",
  rate_limited: "Too many requests. Wait briefly and try again.",
  validation_failed: "The request is invalid. Check the supplied fields and try again.",
  internal_error: "The service could not complete this request.",
  storage_unavailable: "The service could not complete this request.",
  service_not_configured: "A required service is not configured.",
  engine_unavailable: "A required engine is not available.",
  capability_unavailable: "This capability is not available.",
  request_too_large: "The request is too large.",
  response_too_large: "The server response exceeded the supported size.",
  invalid_response: "The server returned an invalid response.",
  invalid_request: "The request could not be processed.",
  mfa_verification_required: "Multi-factor verification is required, but is not available in this API session flow.",
  integration_disabled: "The integration is disabled.",
  integration_misconfigured: "The integration configuration must be corrected before activation.",
  ticketing_not_configured: "Ticketing is not configured for this tenant.",
  ticketing_configuration_invalid: "The ticketing configuration is invalid.",
  ticketing_credentials_invalid: "Ticketing credentials are unavailable or invalid.",
  ticketing_provider_error: "The ticketing provider could not complete the request.",
  ticketing_provider_unavailable: "The ticketing provider is unavailable.",
  ticketing_rate_limited: "The ticketing provider is rate limiting requests.",
  ticketing_reference_conflict: "The external issue reference is ambiguous.",
  ticketing_transition_unavailable: "The external issue cannot be closed.",
});
const SAFE_FIELD_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  required: "This field is required.",
  invalid_type: "Use the expected value type.",
  invalid: "This field is invalid.",
  out_of_range: "This value is outside the allowed range.",
  too_large: "This value is too large.",
  duplicate: "This value is duplicated.",
  empty: "Provide at least one value.",
  unknown_field: "This field is not supported.",
  unknown_parameter: "This parameter is not supported.",
  duplicate_parameter: "Specify this parameter only once.",
});
let inMemoryAccessToken = "";

function asRecord(value: unknown): UnknownRecord | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as UnknownRecord)
    : null;
}

function safeString(value: unknown, maximum: number): string {
  return typeof value === "string" && value.length <= maximum ? value : "";
}

function containsControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x20 || code === 0x7f) return true;
  }
  return false;
}

function createRequestId(): string {
  try {
    if (globalThis.crypto && "randomUUID" in globalThis.crypto) {
      return globalThis.crypto.randomUUID();
    }
  } catch {
    // Correlation IDs are not credentials; the bounded fallback remains local.
  }
  const random = Math.random().toString(36).slice(2, 14);
  return `web-${Date.now().toString(36)}-${random}`.slice(0, 96);
}

function parseFieldViolations(value: unknown): ApiFieldViolation[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 20).flatMap((item) => {
    const record = asRecord(item);
    if (!record) return [];
    const field = safeString(record["field"], 96);
    const code = safeString(record["code"], 64);
    if (!FIELD_NAME_RE.test(field) || !ERROR_CODE_RE.test(code)) return [];
    return [{
      field,
      code,
      message: SAFE_FIELD_MESSAGES[code] ?? "Check this field and try again.",
    }];
  });
}

function publicErrorMessage(code: string, status: number): string {
  const knownMessage = PUBLIC_ERROR_MESSAGES[code];
  if (knownMessage) return knownMessage;
  if (status === 401) return "Authentication is required or invalid. Sign in again.";
  if (status === 403) return "You do not have permission to perform this action.";
  if (status === 404) return "The requested resource was not found.";
  if (status === 409) return "The requested change conflicts with existing data.";
  if (status === 429) return "Too many requests. Wait briefly and try again.";
  if (status >= 500) return "The service could not complete this request.";
  return "The request could not be completed.";
}

function safeRequestId(value: unknown): string {
  const candidate = safeString(value, 96);
  return REQUEST_ID_RE.test(candidate) ? candidate : "";
}

function apiErrorFromResponse(
  payload: unknown,
  status: number,
  headerRequestId: string,
): ApiError {
  const root = asRecord(payload);
  const error = asRecord(root?.["error"]);
  const rawCode = safeString(error?.["code"], 80);
  const code = ERROR_CODE_RE.test(rawCode) ? rawCode : "request_failed";
  const message = publicErrorMessage(code, status);
  const requestId = safeRequestId(error?.["request_id"]) || safeRequestId(headerRequestId);
  return new ApiError(
    status,
    code,
    message,
    requestId,
    parseFieldViolations(error?.["fields"]),
  );
}

async function readBoundedResponse(response: Response, requestId: string): Promise<string> {
  const declaredLength = response.headers.get("Content-Length") ?? "";
  if (/^\d+$/.test(declaredLength) && Number(declaredLength) > MAX_RESPONSE_BYTES) {
    try {
      await response.body?.cancel();
    } catch {
      // A rejected response stream does not change the public size-limit error.
    }
    throw new ApiError(502, "response_too_large", "The server response exceeded the supported size.", safeRequestId(requestId));
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let receivedBytes = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      receivedBytes += result.value.byteLength;
      if (receivedBytes > MAX_RESPONSE_BYTES) {
        throw new ApiError(502, "response_too_large", "The server response exceeded the supported size.", safeRequestId(requestId));
      }
      chunks.push(decoder.decode(result.value, { stream: true }));
    }
    chunks.push(decoder.decode());
    return chunks.join("");
  } catch (error) {
    try {
      await reader.cancel();
    } catch {
      // Preserve the bounded public error or caller cancellation.
    }
    throw error;
  } finally {
    reader.releaseLock();
  }
}

export function setInMemoryAccessToken(value: string | null): void {
  inMemoryAccessToken = typeof value === "string" && value.length > 0 && value.length <= 4096
    ? value
    : "";
}

export function hasInMemoryAccessToken(): boolean {
  return inMemoryAccessToken.length > 0;
}

export function newIdempotencyKey(): string {
  return createRequestId();
}

export class ApiClient {
  private readonly fetcher: typeof fetch;
  private readonly tokenProvider: () => string;
  private readonly basePath: string;
  private readonly defaultTimeoutMs: number;

  constructor(options: ApiClientOptions = {}) {
    this.fetcher = options.fetcher ?? globalThis.fetch.bind(globalThis);
    this.tokenProvider = options.tokenProvider ?? (() => inMemoryAccessToken);
    this.basePath = options.basePath ?? "/api/v1";
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 15_000;
    if (!/^\/[A-Za-z0-9/_-]{1,80}$/.test(this.basePath) || this.basePath.endsWith("/")) {
      throw new TypeError("API base path is invalid");
    }
    if (!Number.isSafeInteger(this.defaultTimeoutMs) || this.defaultTimeoutMs < 1 || this.defaultTimeoutMs > 120_000) {
      throw new TypeError("API timeout must be between 1 and 120000 milliseconds");
    }
  }

  get<T>(path: string, options: Omit<ApiRequestOptions, "method" | "body"> = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: "GET" });
  }

  post<T>(path: string, body: unknown = {}, options: Omit<ApiRequestOptions, "method" | "body"> = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: "POST", body });
  }

  patch<T>(path: string, body: unknown, options: Omit<ApiRequestOptions, "method" | "body"> = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: "PATCH", body });
  }

  async request<T>(path: string, options: ApiRequestOptions = {}): Promise<T> {
    const url = this.validatePath(path);
    const method = options.method ?? "GET";
    const token = this.tokenProvider();
    const requestId = createRequestId();
    const headers: Record<string, string> = {
      Accept: "application/json",
      "X-Request-ID": requestId,
    };
    for (const [name, value] of Object.entries(options.headers ?? {})) {
      if (!name || /[\r\n:]/.test(name) || /[\r\n]/.test(value)) {
        throw new TypeError("API request header is invalid");
      }
      const normalizedName = name.toLowerCase();
      if (["authorization", "cookie", "x-request-id"].includes(normalizedName)) {
        throw new TypeError("Authentication, cookies, and request IDs are managed by the API client");
      }
      headers[name] = value;
    }
    if (token && !headers["Authorization"]) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    if (options.idempotencyKey) {
      if (options.idempotencyKey.length > 128 || /[\r\n]/.test(options.idempotencyKey)) {
        throw new TypeError("Idempotency key is invalid");
      }
      headers["Idempotency-Key"] = options.idempotencyKey;
    }
    let encodedBody: string | undefined;
    if (options.body !== undefined) {
      try {
        encodedBody = JSON.stringify(options.body);
      } catch {
        throw new ApiError(400, "invalid_request", "The request body is invalid.", requestId);
      }
      if (typeof encodedBody !== "string" || new TextEncoder().encode(encodedBody).byteLength > MAX_REQUEST_BYTES) {
        throw new ApiError(413, "request_too_large", "The request body is too large.", requestId);
      }
      headers["Content-Type"] = "application/json";
    }
    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
      throw new TypeError("Request timeout must be between 1 and 120000 milliseconds");
    }
    const controller = new AbortController();
    const abortFromCaller = (): void => controller.abort();
    if (options.signal?.aborted) {
      controller.abort();
    } else {
      options.signal?.addEventListener("abort", abortFromCaller, { once: true });
    }
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const init: RequestInit = {
      method,
      headers,
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
      ...(encodedBody === undefined ? {} : { body: encodedBody }),
    };
    try {
      const response = await this.fetcher(url, init);
      const headerRequestId = safeRequestId(response.headers.get("X-Request-ID"));
      if (response.status === 204) {
        if (!response.ok) {
          throw apiErrorFromResponse(null, response.status, headerRequestId);
        }
        return undefined as T;
      }
      const text = await readBoundedResponse(response, headerRequestId);
      let payload: unknown = null;
      if (text) {
        try {
          payload = JSON.parse(text) as unknown;
        } catch {
          throw new ApiError(502, "invalid_response", "The server returned an invalid response.", headerRequestId);
        }
      }
      if (!response.ok) {
        throw apiErrorFromResponse(payload, response.status, headerRequestId);
      }
      return payload as T;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      if (controller.signal.aborted) {
        const callerCancelled = options.signal?.aborted === true;
        throw new ApiError(
          callerCancelled ? 499 : 408,
          callerCancelled ? "request_cancelled" : "request_timeout",
          callerCancelled ? "The request was cancelled." : "The request timed out.",
          requestId,
        );
      }
      throw new ApiError(0, "network_error", "The service could not be reached.", requestId);
    } finally {
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", abortFromCaller);
    }
  }

  private validatePath(path: string): string {
    if (
      typeof path !== "string" ||
      !path.startsWith(`${this.basePath}/`) ||
      path.startsWith("//") ||
      path.includes("\\") ||
      path.includes("#") ||
      containsControlCharacter(path) ||
      /^[A-Za-z][A-Za-z0-9+.-]*:/.test(path)
    ) {
      throw new TypeError("API paths must remain under the same-origin versioned API base path");
    }
    const queryStart = path.indexOf("?");
    const rawPath = queryStart < 0 ? path : path.slice(0, queryStart);
    let normalized: URL;
    try {
      normalized = new URL(path, "https://security-toolkit.invalid");
    } catch {
      throw new TypeError("API paths must remain under the same-origin versioned API base path");
    }
    if (
      normalized.origin !== "https://security-toolkit.invalid" ||
      !normalized.pathname.startsWith(`${this.basePath}/`)
    ) {
      throw new TypeError("API paths must remain under the same-origin versioned API base path");
    }
    const segments = rawPath.slice(this.basePath.length + 1).split("/");
    if (segments.some((segment) => !segment)) {
      throw new TypeError("API paths must not contain empty route segments");
    }
    for (const segment of segments) {
      let decoded: string;
      try {
        decoded = decodeURIComponent(segment);
      } catch {
        throw new TypeError("API paths must contain valid encoded segments");
      }
      if (
        decoded === "." ||
        decoded === ".." ||
        decoded.includes("/") ||
        decoded.includes("\\") ||
        containsControlCharacter(decoded)
      ) {
        throw new TypeError("API paths must not contain path traversal segments");
      }
    }
    return path;
  }
}

export const apiClient = new ApiClient();
