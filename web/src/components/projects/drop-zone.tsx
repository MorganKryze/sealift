import { FileDown, FileJson, FolderOpen } from "lucide-react"
import { useId, useRef, useState, type DragEvent } from "react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

interface DropZoneProps {
  onFile: (file: File) => void
  /** A choice that is no package.json: the file's name, or null when several files came at once. */
  onInvalidFile: (name: string | null) => void
}

/** The one .json file of a choice or a drop, sent to `onFile`; anything else goes to `onInvalidFile`. */
export function takeJsonFile(files: FileList | null, { onFile, onInvalidFile }: DropZoneProps) {
  if (!files || files.length === 0) {
    return
  }
  if (files.length > 1) {
    onInvalidFile(null)
    return
  }
  const file = files[0]
  if (!file.name.toLowerCase().endsWith(".json")) {
    onInvalidFile(file.name)
    return
  }
  onFile(file)
}

/** Update's zone before a file: one line and one button. A file over it turns the dashed line solid. */
export function DropZone({ onFile, onInvalidFile }: DropZoneProps) {
  const inputId = useId()
  const inputRef = useRef<HTMLInputElement>(null)
  const [isDragging, setIsDragging] = useState(false)

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setIsDragging(false)
    takeJsonFile(event.dataTransfer.files, { onFile, onInvalidFile })
  }

  const Icon = isDragging ? FileDown : FileJson
  return (
    <div
      onClick={() => inputRef.current?.click()}
      onDragOver={(event) => {
        event.preventDefault()
        setIsDragging(true)
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      className={cn(
        "flex min-h-65 w-full cursor-pointer flex-col items-center justify-center gap-3.5 rounded-xl border border-dashed border-field bg-canvas px-6 py-10 text-center transition-colors duration-150",
        isDragging && "border-solid border-ink",
      )}
    >
      <span className="grid size-12 place-items-center rounded-xl border border-rule-2 bg-bg text-ink-2">
        <Icon aria-hidden="true" className="size-5" />
      </span>
      <h2 className="text-[15px] font-semibold text-ink">
        Drop a <span className="font-mono font-normal">package.json</span>
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
        Choose file
      </Button>
      <label htmlFor={inputId} className="sr-only">
        Choose a package.json
      </label>
      <input
        ref={inputRef}
        id={inputId}
        type="file"
        tabIndex={-1}
        accept="application/json,.json"
        className="sr-only"
        onChange={(event) => {
          takeJsonFile(event.target.files, { onFile, onInvalidFile })
          event.target.value = ""
        }}
      />
    </div>
  )
}
