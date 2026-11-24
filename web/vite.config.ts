import path from "node:path"

import tailwindcss from "@tailwindcss/vite"
import { tanstackRouter } from "@tanstack/router-plugin/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vitest/config"

// SEALIFT_API lets `vite dev`/`vite preview` point at a sealift instance
// other than the default local one, such as a second container on another
// port while the default 8080 stays running for other work.
const apiTarget = process.env.SEALIFT_API ?? "http://127.0.0.1:8080"

// The proxy leaves the browser's Host as it came: the signing key's
// regenerate refuses a request whose Origin does not name the Host it receives.
export const apiProxy = {
  "/api": {
    target: apiTarget,
  },
}

export default defineConfig({
  plugins: [tanstackRouter({ target: "react" }), react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  server: {
    proxy: apiProxy,
  },
  preview: {
    proxy: apiProxy,
  },
  // dist/index.html is a tracked placeholder (see web/embed.go), so the
  // build writes to a subdirectory instead of overwriting it on every
  // local build.
  build: {
    outDir: "dist/app",
  },
  test: {
    environment: "jsdom",
    // tests/ holds the browser gate, which runs under Playwright.
    include: ["src/**/*.test.{ts,tsx}", "vite.config.test.ts"],
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
    passWithNoTests: true,
  },
})
