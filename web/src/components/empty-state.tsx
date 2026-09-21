import mark from "@/assets/brand/mark.svg"

export function EmptyState() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-4 p-8 text-center">
      <img src={mark} alt="" className="size-10" />
      <h1 className="text-xl font-semibold text-ink">Nothing in the hold yet</h1>
      <p className="max-w-sm text-muted">Drop a package.json to prepare its first shipment.</p>
      <div className="h-40 w-full max-w-md rounded-lg border-2 border-dashed border-line" />
    </div>
  )
}
