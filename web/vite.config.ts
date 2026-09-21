import path from "node:path"

import tailwindcss from "@tailwindcss/vite"
import { tanstackRouter } from "@tanstack/router-plugin/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vitest/config"

const apiProxy = {
  "/api": {
    target: "http://127.0.0.1:8080",
    changeOrigin: true,
  },
}

export default defineConfig({
  plugins: [tanstackRouter({ target: "react", autoCodeSplitting: true }), react(), tailwindcss()],
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
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
    passWithNoTests: true,
  },
})
