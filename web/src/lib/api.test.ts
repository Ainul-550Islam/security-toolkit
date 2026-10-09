import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiClient,
  ApiError,
  hasInMemoryAccessToken,
  setInMemoryAccessToken,
} from "./api";

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Request-ID": "request-12345678",
    },
  });
}

afterEach(() => {
  setInMemoryAccessToken(null);
  vi.restoreAllMocks();
});

describe("ApiClient", () => {
  it("uses a same-origin versioned path and restrictive request options with a memory token", async () => {
    let requestedUrl: RequestInfo | URL | undefined;
    let requestInit: RequestInit | undefined;
    const fetcher: typeof fetch = async (input, init) => {
      requestedUrl = input;
      requestInit = init;
      return jsonResponse({ data: { id: "tenant-1" } });
    };
    setInMemoryAccessToken("memory-only-access-token");
    const client = new ApiClient({ fetcher });

    const result = await client.get<{ data: { id: string } }>("/api/v1/tenants");

    expect(result.data.id).toBe("tenant-1");
    expect(String(requestedUrl)).toBe("/api/v1/tenants");
    expect(requestInit?.credentials).toBe("omit");
    expect(requestInit?.cache).toBe("no-store");
    expect(requestInit?.redirect).toBe("error");
    expect(requestInit?.referrerPolicy).toBe("no-referrer");
    expect(new Headers(requestInit?.headers).get("Authorization")).toBe("Bearer memory-only-access-token");
    expect(new Headers(requestInit?.headers).get("X-Request-ID")).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$/);
    expect(hasInMemoryAccessToken()).toBe(true);
  });

  it("never displays server-provided exception text or field messages", async () => {
    const secretText = "api_token=exception-secret /srv/private/provider.py traceback";
    const client = new ApiClient({
      fetcher: async () => jsonResponse({
        error: {
          code: "internal_error",
          message: secretText,
          request_id: "request-12345678",
          fields: [{ field: "email", code: "invalid", message: secretText }],
        },
      }, 500),
    });

    let caught: unknown;
    try {
      await client.get("/api/v1/tenants");
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(ApiError);
    const apiError = caught as ApiError;
    expect(apiError.message).toBe("The service could not complete this request.");
    expect(apiError.message).not.toContain(secretText);
    expect(apiError.fields).toEqual([{ field: "email", code: "invalid", message: "This field is invalid." }]);
    expect(JSON.stringify(apiError.fields)).not.toContain(secretText);
    expect(apiError.requestId).toBe("request-12345678");
  });

  it("rejects external, traversal, encoded traversal, and empty-segment paths before fetch", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse({ data: true }));
    const client = new ApiClient({ fetcher });
    const unsafePaths = [
      "https://attacker.example/api/v1/tenants",
      "/api/v1/../admin",
      "/api/v1/%2e%2e/admin",
      "/api/v1/tenants//tenant-1",
    ];

    for (const path of unsafePaths) {
      await expect(client.get(path)).rejects.toBeInstanceOf(TypeError);
    }
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("maps caller cancellation without exposing the transport exception", async () => {
    const fetcher: typeof fetch = async (_input, init) => new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal;
      if (signal?.aborted) {
        reject(new DOMException("provider internals", "AbortError"));
        return;
      }
      signal?.addEventListener("abort", () => reject(new DOMException("provider internals", "AbortError")), { once: true });
    });
    const client = new ApiClient({ fetcher });
    const controller = new AbortController();
    const pending = client.get("/api/v1/tenants", { signal: controller.signal });
    controller.abort();

    await expect(pending).rejects.toMatchObject({
      status: 499,
      code: "request_cancelled",
      message: "The request was cancelled.",
    });
  });

  it("rejects oversized responses and caller-supplied authentication headers", async () => {
    const client = new ApiClient({
      fetcher: async () => new Response("{\"data\":true}", {
        status: 200,
        headers: { "Content-Length": "4000001" },
      }),
    });

    await expect(client.get("/api/v1/tenants")).rejects.toMatchObject({
      code: "response_too_large",
      status: 502,
    });
    await expect(client.get("/api/v1/tenants", {
      headers: { authorization: "Bearer caller-controlled-token" },
    })).rejects.toBeInstanceOf(TypeError);
  });

  it("accepts a successful empty response", async () => {
    const client = new ApiClient({
      fetcher: async () => new Response(null, { status: 204 }),
    });

    await expect(client.post<undefined>("/api/v1/auth/logout", {})).resolves.toBeUndefined();
  });
});
