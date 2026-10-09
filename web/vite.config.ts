import react from "@vitejs/plugin-react";
import { env } from "node:process";
import { defineConfig } from "vitest/config";

function apiProxyOrigin(): string {
  const configured = env["SECURITY_TOOLKIT_API_PROXY"]?.trim() || "http://127.0.0.1:8080";
  let target: URL;
  try {
    target = new URL(configured);
  } catch {
    throw new Error("SECURITY_TOOLKIT_API_PROXY must be an HTTP or HTTPS origin");
  }
  if (
    !["http:", "https:"].includes(target.protocol) ||
    target.username ||
    target.password ||
    target.pathname !== "/" ||
    target.search ||
    target.hash
  ) {
    throw new Error("SECURITY_TOOLKIT_API_PROXY must be an HTTP or HTTPS origin without credentials or a path");
  }
  return target.origin;
}

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    allowedHosts: ["localhost", "127.0.0.1", ".e2b.app"],
    cors: {
      origin: [
        /^https?:\/\/localhost(?::\d+)?$/,
        /^https?:\/\/127\.0\.0\.1(?::\d+)?$/,
        /^https:\/\/.+\.e2b\.app$/,
      ],
    },
    proxy: {
      "/api/v1": {
        target: apiProxyOrigin(),
        changeOrigin: true,
        secure: true,
        ws: false,
      },
    },
  },
  preview: {
    host: "0.0.0.0",
    allowedHosts: ["localhost", "127.0.0.1", ".e2b.app"],
  },
  build: {
    target: "es2022",
    sourcemap: false,
    assetsInlineLimit: 4096,
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    clearMocks: true,
    restoreMocks: true,
  },
});
