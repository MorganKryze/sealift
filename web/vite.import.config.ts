import path from "node:path"

import tailwindcss from "@tailwindcss/vite"
import { tanstackRouter } from "@tanstack/router-plugin/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// The import role's screens: a second entry beside the collection's, built to
// dist/import, which is the only build `sealift import-server` serves.
const apiTarget = process.env.SEALIFT_IMPORT_API ?? "http://127.0.0.1:8080"

const apiProxy = {
  "/api": {
    target: apiTarget,
    changeOrigin: true,
  },
}

export default defineConfig({
  root: "import",
  // The icons the shell links to; the collection's build copies the same files.
  publicDir: "../public",
  plugins: [
    tanstackRouter({
      target: "react",
      routesDirectory: path.resolve(import.meta.dirname, "src/import/routes"),
      generatedRouteTree: path.resolve(import.meta.dirname, "src/import/routeTree.gen.ts"),
    }),
    react(),
    tailwindcss(),
  ],
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
  build: {
    outDir: "../dist/import",
    emptyOutDir: true,
    // The policy allows no data: URI, so nothing is inlined.
    assetsInlineLimit: 0,
  },
})
