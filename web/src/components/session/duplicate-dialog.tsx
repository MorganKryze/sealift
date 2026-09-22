import type { ProjectSummary } from "@/api/projects"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog"
import { formatWhen } from "@/lib/utils"

interface DuplicateDialogProps {
  match: ProjectSummary
  onResume: () => void
  onStartNew: () => void
  onOpenChange: (open: boolean) => void
}

function describeOutcome(match: ProjectSummary): string {
  const { lastAnalysis, lastExport } = match
  if (lastExport?.state === "done") {
    return "That session ended with a sealed archive."
  }
  if (lastExport && (lastExport.state === "failed" || lastExport.state === "cancelled" || lastExport.state === "interrupted")) {
    return "That session's export did not finish."
  }
  if (lastAnalysis?.state === "done") {
    return "That session's analysis finished; no archive was built yet."
  }
  if (lastAnalysis && (lastAnalysis.state === "failed" || lastAnalysis.state === "cancelled" || lastAnalysis.state === "interrupted")) {
    return "That session's analysis did not finish."
  }
  return "That session is still running."
}

/**
 * Offered when a dropped file's sha256 matches an existing session's
 * manifest, byte for byte: resume that session, or start fresh with new
 * data from the registry and the vulnerability database.
 */
export function DuplicateDialog({ match, onResume, onStartNew, onOpenChange }: DuplicateDialogProps) {
  const when = match.lastAnalysis?.createdAt ?? match.lastExport?.createdAt
  const title = when ? `You analysed this file ${formatWhen(when)}` : "You already analysed this file"

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent aria-describedby="duplicate-description">
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription id="duplicate-description">
          Same content, byte for byte. {describeOutcome(match)} Resume it, or start over with fresh data from the
          registry and the vulnerability database.
        </DialogDescription>
        <DialogFooter>
          <Button variant="outline" onClick={onStartNew}>
            Start a new session
          </Button>
          <Button onClick={onResume} autoFocus>
            Resume that session
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
