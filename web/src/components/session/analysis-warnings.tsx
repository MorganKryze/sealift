/** What the analysis could not check. A dependency it skipped would otherwise read as clean. */
export function AnalysisWarnings({ warnings }: { warnings: string[] }) {
  if (warnings.length === 0) return null

  return (
    <section
      aria-label="Analysis warnings"
      className="mb-6 rounded-lg border border-severity-medium/60 bg-severity-medium/5 p-4 text-sm text-ink"
    >
      <p className="font-medium">sealift could not check everything</p>
      <p className="mt-1 max-w-[62ch]">
        A dependency named here can look clean without having been checked. Read each line before you confirm, and
        analyse again once its cause is fixed.
      </p>
      <ul className="mt-2 list-disc space-y-1 pl-5">
        {warnings.map((warning) => (
          <li key={warning} className="break-words">
            {warning}
          </li>
        ))}
      </ul>
    </section>
  )
}
