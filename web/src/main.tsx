import "@fontsource/inter/400.css"
import "@fontsource/inter/500.css"
import "@fontsource/inter/600.css"
import "@fontsource/inter/800.css"
import "@fontsource/jetbrains-mono/500.css"
import "./styles/index.css"

import { StrictMode } from "react"
import { createRoot } from "react-dom/client"

import { Button } from "@/components/ui/button"

const rootElement = document.getElementById("root")
if (!rootElement) {
  throw new Error("missing #root element")
}

createRoot(rootElement).render(
  <StrictMode>
    <div className="flex min-h-screen items-center justify-center bg-background text-ink">
      <Button>sealift</Button>
    </div>
  </StrictMode>,
)
