import { Check, Copy } from "lucide-react"
import { useEffect, useRef, useState } from "react"

interface CopyControlProps {
  text: string
  /** What the text is, as the button's name says it: "Copy <label>". */
  label: string
}

type State = "idle" | "copied" | "select"

/**
 * Copies a text with the clipboard. A page served over plain http has no clipboard, so the control
 * then shows the text selected in a read-only box and says how to copy it with the keyboard.
 */
export function CopyControl({ text, label }: CopyControlProps) {
  const [state, setState] = useState<State>("idle")
  const box = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    if (state === "select" && box.current) {
      box.current.focus()
      box.current.setSelectionRange(0, text.length)
    }
  }, [state, text])

  async function copy() {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("no clipboard")
      }
      await navigator.clipboard.writeText(text)
      setState("copied")
    } catch {
      setState("select")
    }
  }

  return (
    <span className="inline-flex min-w-0 flex-col gap-1.5">
      <span className="inline-flex items-center gap-2">
        <button
          type="button"
          onClick={copy}
          className="inline-flex h-8 items-center gap-1.5 rounded-md border border-line bg-card px-2.5 text-sm text-ink outline-none hover:bg-background focus-visible:ring-2 focus-visible:ring-accent"
        >
          {state === "copied" ? <Check aria-hidden className="size-3.5" /> : <Copy aria-hidden className="size-3.5" />}
          <span aria-hidden>Copy</span>
          <span className="sr-only">Copy {label}</span>
        </button>
        <span aria-live="polite" className="text-sm text-muted">
          {state === "copied" ? "Copied" : null}
          {state === "select" ? "The clipboard is not available on this page. The text is selected: press Ctrl+C, or Command+C on a Mac, to copy it." : null}
        </span>
      </span>
      {state === "select" ? (
        <textarea
          ref={box}
          readOnly
          rows={Math.min(6, Math.max(2, Math.ceil(text.length / 64)))}
          value={text}
          aria-label={`Text of ${label}`}
          className="w-full rounded-md border border-line bg-background p-2 font-mono text-xs [overflow-wrap:anywhere] outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
      ) : null}
    </span>
  )
}
