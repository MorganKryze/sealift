import { Link } from "@tanstack/react-router"
import { Container, FileCode2, LayoutGrid, Package, Settings } from "lucide-react"
import type { ComponentType } from "react"

import lockup from "@/assets/brand/lockup.svg"

interface NavItem {
  label: string
  icon: ComponentType<{ className?: string }>
  to?: "/projects"
  soon?: boolean
}

const items: NavItem[] = [
  { label: "Projects", icon: LayoutGrid, to: "/projects" },
  { label: "npm", icon: Package, soon: true },
  { label: "Python", icon: FileCode2, soon: true },
  { label: "Docker", icon: Container, soon: true },
  { label: "Settings", icon: Settings },
]

export function Nav() {
  return (
    <nav className="flex w-56 shrink-0 flex-col border-r border-line bg-card p-4">
      <img src={lockup} alt="sealift" className="mb-6 h-6 w-auto" />
      <ul className="flex flex-1 flex-col gap-1">
        {items.map(({ label, icon: Icon, to, soon }) => (
          <li key={label}>
            {to ? (
              <Link
                to={to}
                className="flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-ink hover:bg-background [&.active]:bg-background"
                activeProps={{ className: "active" }}
              >
                <Icon className="size-4" />
                {label}
              </Link>
            ) : (
              <span className="flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-muted">
                <Icon className="size-4" />
                {label}
                {soon ? (
                  <span className="ml-auto rounded-full bg-background px-2 py-0.5 text-xs text-muted">
                    soon
                  </span>
                ) : null}
              </span>
            )}
          </li>
        ))}
      </ul>
    </nav>
  )
}
