import "@fontsource/inter/400.css"
import "@fontsource/inter/500.css"
import "@fontsource/inter/600.css"
import "@fontsource/inter/800.css"
import "@fontsource/jetbrains-mono/500.css"
import "./index.css"

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createRouter, RouterProvider } from "@tanstack/react-router"
import { StrictMode } from "react"
import { createRoot } from "react-dom/client"

import { applyTheme, readStoredTheme } from "@/components/theme-toggle"

import { retryOnlyTransient } from "./api/queries"
import { routeTree } from "./routeTree.gen"

const router = createRouter({ routeTree })

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router
  }
}

// The theme control lives in the settings sheet, which is not open at load.
applyTheme(readStoredTheme())

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: retryOnlyTransient } } })

const rootElement = document.getElementById("root")
if (!rootElement) {
  throw new Error("missing #root element")
}

createRoot(rootElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
)
