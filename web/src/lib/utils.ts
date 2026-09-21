import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function latestByDate<T extends { createdAt: string }>(items: T[] | undefined): T | undefined {
  if (!items || items.length === 0) {
    return undefined
  }
  return [...items].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]
}

export function formatDuration(ms: number) {
  const seconds = Math.round(ms / 1000)
  if (seconds < 60) {
    return `${seconds}s`
  }
  const minutes = Math.floor(seconds / 60)
  const remainingSeconds = seconds % 60
  return `${minutes}m ${remainingSeconds}s`
}

export function formatBytes(bytes: number) {
  if (bytes < 1024) {
    return `${bytes} B`
  }
  const units = ["KB", "MB", "GB", "TB"]
  let value = bytes / 1024
  let unitIndex = 0
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024
    unitIndex += 1
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`
}

// Signal.name has no fixed enum in the schema, so identifiers are turned
// into labels generically (too-recent -> Too recent) instead of a lookup
// table that would drift from whatever the analyzer actually emits.
export function humanizeSignal(name: string) {
  const spaced = name.replace(/-/g, " ")
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}
