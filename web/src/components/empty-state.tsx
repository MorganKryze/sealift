import type { ReactNode } from "react"

import { Mark } from "@/components/brand/Mark"
import { DropZone } from "@/components/projects/drop-zone"

interface EmptyStateProps {
  onFile?: (file: File) => void
  onInvalidFile?: (message: string) => void
  children?: ReactNode
}

export function EmptyState({ onFile, onInvalidFile, children }: EmptyStateProps) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-4 p-8 text-center">
      <Mark size={96} />
      <h1 className="text-xl font-semibold text-ink">Nothing in the hold yet</h1>
      <p className="max-w-sm text-muted">Drop a package.json to prepare its first shipment.</p>
      {children}
      <DropZone onFile={onFile ?? (() => {})} onInvalidFile={onInvalidFile ?? (() => {})} />
    </div>
  )
}
