import { Monitor, Moon, Sun } from "lucide-react"
import { useEffect, useState, type ComponentType } from "react"

import { cn } from "@/lib/utils"

type ThemeChoice = "system" | "light" | "dark"

const STORAGE_KEY = "sealift-theme"

// localStorage throws in a private tab with storage blocked; fall back to system.
export function readStoredTheme(): ThemeChoice {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === "system" || stored === "light" || stored === "dark") {
      return stored
    }
  } catch {
    // Ignored: system is the safe default when storage is unavailable.
  }
  return "system"
}

export function applyTheme(theme: ThemeChoice) {
  const root = document.documentElement
  root.classList.remove("light", "dark")
  if (theme !== "system") {
    root.classList.add(theme)
  }
}

const options: { value: ThemeChoice; label: string; icon: ComponentType<{ className?: string }> }[] = [
  { value: "system", label: "System", icon: Monitor },
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
]

export function ThemeToggle() {
  const [theme, setTheme] = useState<ThemeChoice>(readStoredTheme)

  useEffect(() => {
    applyTheme(theme)
    try {
      localStorage.setItem(STORAGE_KEY, theme)
    } catch {
      // Ignored: the theme still applies for this page load.
    }
  }, [theme])

  return (
    <div role="radiogroup" aria-label="Theme" className="grid grid-cols-3 gap-1 rounded-lg border border-line p-1">
      {options.map(({ value, label, icon: Icon }) => (
        <button
          key={value}
          type="button"
          role="radio"
          aria-checked={theme === value}
          onClick={() => setTheme(value)}
          className={cn(
            "flex h-9 items-center justify-center gap-2 rounded-md text-sm font-medium outline-none",
            "focus-visible:ring-2 focus-visible:ring-accent",
            theme === value ? "bg-accent text-background" : "text-muted hover:bg-card hover:text-ink",
          )}
        >
          <Icon className="size-4" />
          {label}
        </button>
      ))}
    </div>
  )
}
