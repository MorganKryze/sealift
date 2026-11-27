import { FileDown, Files, FolderOpen } from "lucide-react"
import { useId, useRef, useState, type DragEvent } from "react"

import { Button } from "@/components/ui/button"
import { MAX_REQUIREMENTS_BYTES, MAX_REQUIREMENTS_FILES } from "@/lib/requirementsPreview"
import { cn } from "@/lib/utils"

/** What a choice or a drop holds: one package.json, requirements files, or a refusal with what to drop instead. */
export type DroppedFiles = { kind: "npm"; file: File } | { kind: "pip"; files: File[] } | { kind: "refused"; message: string; instead: string; file?: string }

const AT_ROOT = "Drop the package.json at your project's root; nothing was sent."
const ONE_SIDE = "Drop the package.json alone, or the requirements files alone; nothing was sent."

const isJson = (file: File) => file.name.toLowerCase().endsWith(".json")
const plural = (n: number, one: string, many: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`

/**
 * Reads the ecosystem from the files' names: one .json file is npm, files of which none ends in .json are
 * requirements files, whatever their names; both together are refused, and so are requirements files past the
 * server's bounds. Nothing is read or sent here.
 */
export function takeDroppedFiles(files: FileList | File[] | null): DroppedFiles {
  const all = Array.from(files ?? [])
  const json = all.filter(isJson)
  const others = all.filter((file) => !isJson(file))
  if (json.length > 0 && others.length > 0) {
    const what = json.length === 1 ? json[0].name : plural(json.length, ".json file", ".json files")
    return { kind: "refused", message: `${what} and ${plural(others.length, "requirements file", "requirements files")} dropped together`, instead: ONE_SIDE }
  }
  if (json.length > 1) return { kind: "refused", message: "Several files were dropped", instead: AT_ROOT }
  if (json.length === 1) return { kind: "npm", file: json[0] }
  if (others.length > MAX_REQUIREMENTS_FILES) {
    return {
      kind: "refused",
      message: `${plural(others.length, "file", "files")} dropped; a crossing takes at most ${MAX_REQUIREMENTS_FILES} requirements files`,
      instead: `Drop at most ${MAX_REQUIREMENTS_FILES} files; nothing was sent.`,
    }
  }
  const big = others.find((file) => file.size > MAX_REQUIREMENTS_BYTES)
  if (big) return { kind: "refused", file: big.name, message: "is over 1 MiB, the most a requirements file may hold", instead: "Drop requirements files of 1 MiB or less; nothing was sent." }
  return { kind: "pip", files: others }
}

/**
 * Update's zone before a file: one line and one button. Files over it turn the dashed line solid, and say how
 * many there are when there are several, the one fact a browser gives before the drop.
 */
export function DropZone({ onFiles }: { onFiles: (dropped: DroppedFiles) => void }) {
  const inputId = useId()
  const inputRef = useRef<HTMLInputElement>(null)
  const [over, setOver] = useState(0)

  function take(files: FileList | null) {
    if (files && files.length > 0) onFiles(takeDroppedFiles(files))
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setOver(0)
    take(event.dataTransfer.files)
  }

  const Icon = over > 0 ? FileDown : Files
  return (
    <div
      data-drop-zone
      onClick={() => inputRef.current?.click()}
      onDragOver={(event) => {
        event.preventDefault()
        setOver(Math.max(1, event.dataTransfer.items.length))
      }}
      onDragLeave={() => setOver(0)}
      onDrop={handleDrop}
      className={cn(
        "flex min-h-65 w-full cursor-pointer flex-col items-center justify-center gap-3.5 rounded-xl border border-dashed border-field bg-canvas px-6 py-10 text-center transition-colors duration-150",
        over > 0 && "border-solid border-ink",
      )}
    >
      <span className="grid size-12 place-items-center rounded-xl border border-rule-2 bg-bg text-ink-2">
        <Icon aria-hidden="true" className="size-5" />
      </span>
      <h2 className="text-[15px] font-semibold text-ink">
        {over > 1 ? (
          `Drop to read ${over} files`
        ) : (
          <>
            Drop a <span className="font-mono font-normal">package.json</span> or requirements files
          </>
        )}
      </h2>
      <Button
        type="button"
        variant="outline"
        size="sm"
        data-choose-file
        onClick={(event) => {
          event.stopPropagation()
          inputRef.current?.click()
        }}
      >
        <FolderOpen aria-hidden="true" />
        Choose files
      </Button>
      <label htmlFor={inputId} className="sr-only">
        Choose a package.json or requirements files
      </label>
      <input
        ref={inputRef}
        id={inputId}
        type="file"
        multiple
        tabIndex={-1}
        className="sr-only"
        onChange={(event) => {
          take(event.target.files)
          event.target.value = ""
        }}
      />
    </div>
  )
}
