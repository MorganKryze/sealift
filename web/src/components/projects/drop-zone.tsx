import { useId, useRef, useState, type DragEvent, type KeyboardEvent } from "react"

import { cn } from "@/lib/utils"

interface DropZoneProps {
  onFile: (file: File) => void
  onInvalidFile: (message: string) => void
  compact?: boolean
}

const LABEL = "Drop package.json here, or browse"

export function DropZone({ onFile, onInvalidFile, compact = false }: DropZoneProps) {
  const inputId = useId()
  const inputRef = useRef<HTMLInputElement>(null)
  const [isDragging, setIsDragging] = useState(false)

  function handleFiles(fileList: FileList | null) {
    if (!fileList || fileList.length === 0) {
      return
    }
    if (fileList.length > 1) {
      onInvalidFile("Drop a single package.json file.")
      return
    }
    const file = fileList[0]
    if (!file.name.toLowerCase().endsWith(".json")) {
      onInvalidFile(`${file.name} is not a .json file.`)
      return
    }
    onFile(file)
  }

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault()
      inputRef.current?.click()
    }
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setIsDragging(false)
    handleFiles(event.dataTransfer.files)
  }

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={LABEL}
      onClick={() => inputRef.current?.click()}
      onKeyDown={handleKeyDown}
      onDragOver={(event) => {
        event.preventDefault()
        setIsDragging(true)
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      className={cn(
        "flex w-full max-w-md cursor-pointer flex-col items-center justify-center gap-1 rounded-lg border-2 border-dashed border-line text-center text-sm text-muted outline-none transition-colors",
        "hover:border-accent focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent",
        compact ? "h-20" : "h-40",
        isDragging && "border-accent bg-card",
      )}
    >
      <label htmlFor={inputId} className="sr-only">
        {LABEL}
      </label>
      <span>{LABEL}</span>
      <input
        ref={inputRef}
        id={inputId}
        type="file"
        accept="application/json,.json"
        className="sr-only"
        onChange={(event) => {
          handleFiles(event.target.files)
          event.target.value = ""
        }}
      />
    </div>
  )
}
