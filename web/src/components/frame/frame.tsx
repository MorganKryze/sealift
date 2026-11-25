import { Link, useRouterState } from "@tanstack/react-router"
import { ChevronRight, type LucideIcon, TriangleAlert } from "lucide-react"
import { type ReactNode, useId, useState } from "react"

import { BrandMark, SideLabel } from "@/components/frame/brand"
import { cn } from "@/lib/utils"

export interface Place {
  to: string
  label: string
  icon: LucideIcon
}

export interface Crumb {
  label: string
  to?: string
}

interface FrameProps {
  side: "online" | "offline"
  places: Place[]
  instance: Place
  instanceWarning?: string
  user?: string
  crumbs: Crumb[]
  children: ReactNode
}

// The place a path belongs to: the one whose address is the longest start of it, so a session page sits under Home.
function currentPlace(pathname: string, places: Place[]): string | undefined {
  const holds = (to: string) => to === "/" || pathname === to || pathname.startsWith(`${to}/`)
  return places
    .filter((p) => holds(p.to))
    .sort((a, b) => b.to.length - a.to.length)[0]?.to
}

/** Up to two letters for the signed-in user: the first of each of two parts split on a dot, an underscore, a hyphen or a space, else the first two. */
export function initials(user: string): string {
  const parts = user.split(/[._\-\s]+/).filter(Boolean)
  const letters = parts.length >= 2 ? parts[0][0] + parts[1][0] : user.slice(0, 2)
  return letters.toUpperCase()
}

/** Every screen but the preparing page: a sidebar of places, a top bar with the breadcrumb and the side label, the page. */
export function Frame({ side, places, instance, instanceWarning, user, crumbs, children }: FrameProps) {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const current = currentPlace(pathname, [...places, instance])

  return (
    <div className="grid min-h-screen grid-cols-[76px_minmax(0,1fr)] bg-bg text-ink">
      <a
        href="#content"
        className="fixed top-2 left-2 z-50 inline-flex h-9 -translate-y-16 items-center rounded-lg bg-ink px-3 text-sm font-semibold text-bg transition-transform duration-200 ease-out focus-visible:translate-y-0 motion-reduce:transition-none"
      >
        Skip to content
      </a>
      <nav aria-label="Places" className="sticky top-0 z-30 flex h-screen flex-col items-center gap-1 border-r border-rule bg-canvas px-1.5 py-3.5">
        <span className="mb-3 grid size-10 place-items-center">
          <BrandMark size={28} />
        </span>
        <ul className="flex flex-col items-center gap-1">
          {places.map((place) => (
            <li key={place.to}>
              <PlaceLink place={place} current={place.to === current} />
            </li>
          ))}
        </ul>
        <div className="mt-auto flex flex-col items-center gap-2.5">
          <PlaceLink place={instance} current={instance.to === current} warning={instanceWarning} />
          {user ? (
            <span title={user} className="grid size-8 place-items-center rounded-full bg-sel text-[11.5px] font-semibold text-ink">
              <span aria-hidden="true">{initials(user)}</span>
              <span className="sr-only">Signed in as {user}</span>
            </span>
          ) : null}
        </div>
      </nav>
      <div className="grid min-w-0 grid-rows-[52px_minmax(0,1fr)]">
        <header className="sticky top-0 z-20 flex min-w-0 items-center justify-between gap-3 border-b border-rule bg-bg px-5">
          <nav aria-label="Breadcrumb" className="min-w-0">
            <ol className="flex min-w-0 flex-wrap items-center gap-1.5 text-sm text-muted">
              {crumbs.map((crumb, index) => {
                const last = index === crumbs.length - 1
                return (
                  <li key={`${index}-${crumb.label}`} className="inline-flex min-w-0 items-center gap-1.5">
                    {index > 0 ? <ChevronRight aria-hidden="true" className="size-3.5 flex-none text-faint" /> : null}
                    {last || !crumb.to ? (
                      <span aria-current={last ? "page" : undefined} className={cn("[overflow-wrap:anywhere]", last && "font-semibold text-ink")}>
                        {crumb.label}
                      </span>
                    ) : (
                      <Link to={crumb.to} className="inline-flex h-8 items-center rounded-md px-1 hover:text-ink">
                        {crumb.label}
                      </Link>
                    )}
                  </li>
                )
              })}
            </ol>
          </nav>
          <SideLabel side={side} />
        </header>
        <main id="content" tabIndex={-1} className="flex min-w-0 flex-col outline-none">
          {children}
        </main>
      </div>
    </div>
  )
}

function PlaceLink({ place, current, warning }: { place: Place; current: boolean; warning?: string }) {
  const [tip, setTip] = useState(false)
  const tipId = useId()
  const Icon = place.icon
  return (
    <span className="relative block">
      <Link
        to={place.to}
        activeOptions={{ exact: true }}
        aria-current={current ? "page" : undefined}
        aria-describedby={warning ? tipId : undefined}
        onMouseEnter={warning ? () => setTip(true) : undefined}
        onMouseLeave={warning ? () => setTip(false) : undefined}
        onFocus={warning ? () => setTip(true) : undefined}
        onBlur={warning ? () => setTip(false) : undefined}
        onKeyDown={warning ? (e) => e.key === "Escape" && setTip(false) : undefined}
        className={cn(
          "relative flex min-h-14 w-[62px] flex-col items-center justify-center gap-1 rounded-lg text-xs text-muted transition-colors duration-150 [@media(hover:hover)_and_(pointer:fine)]:hover:bg-hover [@media(hover:hover)_and_(pointer:fine)]:hover:text-ink",
          current && "bg-sel font-semibold text-ink",
        )}
      >
        <Icon aria-hidden="true" strokeWidth={1.75} className={cn("size-5", current && "text-brand")} />
        {place.label}
        {warning ? (
          <span className="tinted-warn absolute top-1 left-[35px] grid size-5 place-items-center !rounded-full text-warn">
            <TriangleAlert aria-hidden="true" className="size-3" />
          </span>
        ) : null}
      </Link>
      {warning ? (
        <span
          id={tipId}
          role="tooltip"
          hidden={!tip}
          className="tinted-warn absolute bottom-0 left-full z-30 ml-2.5 w-65 px-3 py-2.5 text-left text-[13px] text-ink-2 shadow-lg"
        >
          {warning}
        </span>
      ) : null}
    </span>
  )
}
