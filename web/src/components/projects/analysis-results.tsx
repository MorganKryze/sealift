import { useEffect, useState, type KeyboardEvent } from "react"

import type { AnalysisResult, Candidate, DependencyResult } from "@/api/projects"
import { SeverityCounts } from "@/components/severity-counts"
import { useSelection } from "@/hooks/use-selection"
import { cn } from "@/lib/utils"

interface AnalysisResultsProps {
  analysisId: string
  result: AnalysisResult
}

function bestCandidateOf(dependency: DependencyResult): Candidate | undefined {
  return dependency.best ? dependency.candidates.find((candidate) => candidate.version === dependency.best) : undefined
}

function isBlocked(candidate: Candidate): boolean {
  return candidate.signals.some((signal) => signal.blocking)
}

export function AnalysisResults({ analysisId, result }: AnalysisResultsProps) {
  const { dependencies, before, after, target } = result
  const [selectedIndex, setSelectedIndex] = useState(0)
  const selection = useSelection(analysisId)

  useEffect(() => {
    const defaults: Record<string, string[]> = {}
    for (const dependency of dependencies) {
      const best = bestCandidateOf(dependency)
      if (best && !isBlocked(best)) {
        defaults[dependency.name] = [best.version]
      }
    }
    selection.seedDefaults(defaults)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [analysisId, dependencies])

  const selected = dependencies[Math.min(selectedIndex, dependencies.length - 1)] as DependencyResult | undefined

  function handleListKeyDown(event: KeyboardEvent<HTMLUListElement>) {
    if (event.key === "ArrowDown") {
      event.preventDefault()
      setSelectedIndex((index) => Math.min(index + 1, dependencies.length - 1))
    } else if (event.key === "ArrowUp") {
      event.preventDefault()
      setSelectedIndex((index) => Math.max(index - 1, 0))
    }
  }

  return (
    <div className="flex flex-1 flex-col gap-6 p-8">
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-6">
          <div>
            <p className="text-xs uppercase tracking-wide text-muted">Before</p>
            <SeverityCounts vector={before} />
          </div>
          <div>
            <p className="text-xs uppercase tracking-wide text-muted">After</p>
            {after === null || after === undefined ? (
              <p className="text-sm text-muted">Combined check not measured.</p>
            ) : (
              <SeverityCounts vector={after} />
            )}
          </div>
        </div>
        <p className="text-xs text-muted">
          Target: {target.os}/{target.cpu} · {target.libc} · Node {target.node} · pnpm {target.pnpmVer}
        </p>
      </div>

      <div className="grid flex-1 grid-cols-2 gap-6">
        <ul
          role="listbox"
          aria-label="Dependencies"
          tabIndex={0}
          onKeyDown={handleListKeyDown}
          className="flex flex-col gap-1 overflow-auto rounded-md border border-line p-2 outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {dependencies.map((dependency, index) => {
            const best = bestCandidateOf(dependency)
            return (
              <li key={dependency.name} role="option" aria-selected={index === selectedIndex}>
                <button
                  type="button"
                  onClick={() => setSelectedIndex(index)}
                  className={cn(
                    "w-full rounded-md px-3 py-2 text-left text-sm",
                    index === selectedIndex ? "bg-card" : "hover:bg-card",
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-ink">{dependency.name}</span>
                    <span className="text-xs text-muted">{dependency.current}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-3 text-xs">
                    <SeverityCounts vector={dependency.vector} />
                    <span aria-hidden className="text-muted">
                      →
                    </span>
                    {best ? (
                      <SeverityCounts vector={best.vector} />
                    ) : (
                      <span className="text-muted">no candidate</span>
                    )}
                  </div>
                </button>
              </li>
            )
          })}
        </ul>

        {selected ? <DependencyDetail dependency={selected} selection={selection} /> : null}
      </div>
    </div>
  )
}

interface DependencyDetailProps {
  dependency: DependencyResult
  selection: ReturnType<typeof useSelection>
}

function DependencyDetail({ dependency, selection }: DependencyDetailProps) {
  return (
    <div className="flex flex-col gap-4 overflow-auto rounded-md border border-line p-4">
      <div>
        <h3 className="text-base font-semibold text-ink">{dependency.name}</h3>
        <p className="text-sm text-muted">Current {dependency.current}</p>
        <SeverityCounts vector={dependency.vector} className="mt-1" />
      </div>

      <ul className="flex flex-col gap-3">
        {dependency.candidates.map((candidate) => {
          const blockingSignals = candidate.signals.filter((signal) => signal.blocking)
          const blocked = blockingSignals.length > 0
          const checked = selection.isSelected(dependency.name, candidate.version)
          const inputId = `${dependency.name}-${candidate.version}`

          return (
            <li key={candidate.version} className="rounded-md border border-line p-3">
              <div className="flex items-center gap-2">
                <input
                  id={inputId}
                  type="checkbox"
                  checked={checked}
                  disabled={blocked}
                  onChange={() => selection.toggle(dependency.name, candidate.version)}
                />
                <label htmlFor={inputId} className="text-sm font-medium text-ink">
                  {candidate.version}
                </label>
                <SeverityCounts vector={candidate.vector} className="ml-auto" />
              </div>
              {blocked ? (
                <p className="mt-2 text-sm text-severity-critical">{blockingSignals[0]?.evidence}</p>
              ) : null}
              {candidate.signals.length > 0 ? (
                <ul className="mt-2 flex flex-col gap-1 text-xs text-muted">
                  {candidate.signals.map((signal) => (
                    <li key={signal.name}>
                      {signal.name}: {signal.evidence}
                    </li>
                  ))}
                </ul>
              ) : null}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
