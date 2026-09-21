// The server sends a release age as a Go duration ("911h6m30.7s"), and a
// database date of year 1 when no database was ever downloaded. Both read
// badly as they come, so the settings screen formats them here.

export function formatGoDuration(value: string): string {
  const match = /^(?:(\d+)h)?(?:(\d+)m)?(?:[\d.]+s)?$/.exec(value)
  if (!match) return value
  const hours = Number(match[1] ?? 0)
  const minutes = Number(match[2] ?? 0)
  if (hours >= 48) return `${Math.floor(hours / 24)} days`
  if (hours >= 1) return `${hours} h`
  return `${minutes} min`
}

export function formatDbDate(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime()) || date.getUTCFullYear() < 2000) return "never downloaded"
  return date.toLocaleString()
}
