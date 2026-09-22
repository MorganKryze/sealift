import { useId, useRef, useState, type DragEvent, type ReactNode } from "react"

import { Mark } from "@/components/brand/Mark"
import { Button } from "@/components/ui/button"

import { cn } from "@/lib/utils"

interface DropZoneProps {
  onFile: (file: File) => void
  onInvalidFile: (message: string) => void
  /** Rules shown inside the zone, under the button. */
  children?: ReactNode
}

const LABEL = "Drop package.json here, or browse"

export function DropZone({ onFile, onInvalidFile, children }: DropZoneProps) {
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

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setIsDragging(false)
    handleFiles(event.dataTransfer.files)
  }

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
        "flex w-full cursor-pointer flex-col items-center gap-3.5 rounded-2xl border-[1.5px] border-dashed border-accent/45 bg-card px-6 py-11 text-center transition-colors",
        "hover:border-accent",
        isDragging && "border-accent bg-accent/10",
      )}
    >
      <Mark size={56} />
      <h2 className="text-lg font-semibold tracking-tight text-ink">Drop package.json here</h2>
      <Button
        type="button"
        data-choose-file
        onClick={(event) => {
          event.stopPropagation()
          inputRef.current?.click()
        }}
      >
        Choose a file
      </Button>
      {children ? <div className="max-w-[52ch] text-sm text-muted">{children}</div> : null}
      <label htmlFor={inputId} className="sr-only">
        {LABEL}
      </label>
      <input
        ref={inputRef}
        id={inputId}
        type="file"
        tabIndex={-1}
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
