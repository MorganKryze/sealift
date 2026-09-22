import "@fontsource/inter/400.css"
import "@fontsource/inter/500.css"
import "@fontsource/inter/600.css"
import "@fontsource/inter/800.css"
import "@fontsource/jetbrains-mono/500.css"
import "./styles/index.css"

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createRouter, RouterProvider } from "@tanstack/react-router"
import { StrictMode } from "react"
import { createRoot } from "react-dom/client"

import { RouteError, RouteNotFound } from "./components/route-error"
import { applyTheme, readStoredTheme } from "./components/theme-toggle"
import { routeTree } from "./routeTree.gen"

const router = createRouter({
  routeTree,
  defaultErrorComponent: RouteError,
  defaultNotFoundComponent: RouteNotFound,
})

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router
  }
}

// The theme control lives in the settings panel, which is not mounted until opened.
applyTheme(readStoredTheme())

// A 4xx will answer the same on a retry (a deleted session stays deleted),
// so only a network failure or a 5xx is worth trying again.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        const status = typeof error === "object" && error && "status" in error ? (error as { status: number }).status : 0
        return status >= 400 && status < 500 ? false : failureCount < 3
      },
    },
  },
})

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
