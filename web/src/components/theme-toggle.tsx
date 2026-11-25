import { Monitor, Moon, Sun } from "lucide-react"
import { useRef, useState, type ComponentType, type KeyboardEvent } from "react"

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

const options: { value: ThemeChoice; label: string; icon: ComponentType<{ className?: string; "aria-hidden"?: "true" }> }[] = [
  { value: "system", label: "System", icon: Monitor },
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
]

// The radio group pattern: Tab reaches the pick, the arrow keys move it.
export function ThemeToggle() {
  const [theme, setTheme] = useState<ThemeChoice>(readStoredTheme)
  const picked = options.findIndex((o) => o.value === theme)
  const radios = useRef<(HTMLButtonElement | null)[]>([])

  const pick = (index: number) => {
    const { value } = options[index]
    setTheme(value)
    applyTheme(value)
    try {
      localStorage.setItem(STORAGE_KEY, value)
    } catch {
      // Ignored: the theme still applies for this page load.
    }
  }

  const onKeyDown = (event: KeyboardEvent) => {
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[event.key]
    if (!step) return
    event.preventDefault()
    const next = (picked + step + options.length) % options.length
    pick(next)
    radios.current[next]?.focus()
  }

  return (
    <div
      role="radiogroup"
      aria-label="Theme"
      onKeyDown={onKeyDown}
      className="relative inline-grid grid-cols-3 rounded-lg border border-rule-2 bg-hover p-[3px]"
    >
      <span
        data-thumb
        aria-hidden="true"
        className="absolute top-[3px] bottom-[3px] left-[3px] w-[calc((100%-6px)/3)] rounded-md bg-seg-on shadow-[0_1px_2px_rgba(var(--shadow),.14),0_0_0_1px_rgba(var(--shadow),.06)] transition-transform duration-200 ease-move"
        style={{ transform: `translateX(${picked * 100}%)` }}
      />
      {options.map(({ value, label, icon: Icon }, index) => (
        <button
          key={value}
          ref={(node) => {
            radios.current[index] = node
          }}
          type="button"
          role="radio"
          aria-checked={theme === value}
          tabIndex={theme === value ? 0 : -1}
          onClick={() => pick(index)}
          className={cn(
            "relative flex h-8 items-center justify-center gap-1.5 rounded-md px-3 text-sm transition-colors duration-160",
            theme === value ? "font-semibold text-ink" : "font-medium text-ink-2 hover:text-ink",
          )}
        >
          <Icon aria-hidden="true" className="size-3.5" />
          {label}
        </button>
      ))}
    </div>
  )
}
