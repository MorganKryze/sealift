// The server sends a release age as a Go duration ("911h6m30.7s"), and a
// database date of year 1 when no database was ever downloaded. Both read
// badly as they come, so the instance screens format them here.

export function formatGoDuration(value: string): string {
  const match = /^(?:(\d+)h)?(?:(\d+)m)?(?:[\d.]+s)?$/.exec(value)
  if (!match) return value
  const hours = Number(match[1] ?? 0)
  const minutes = Number(match[2] ?? 0)
  if (hours >= 48) return `${Math.floor(hours / 24)} days`
  if (hours >= 1) return `${hours} h`
  return `${minutes} min`
}

const downloaded = (value: string) => {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) || date.getUTCFullYear() < 2000 ? null : date
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["day", 86_400_000],
  ["hour", 3_600_000],
  ["minute", 60_000],
]

/** The database's age as the design rules write dates: relative for a week at most, then the day. */
export function formatDbDate(value: string, now = Date.now()): string {
  const date = downloaded(value)
  if (!date) return "never downloaded"
  const age = Math.max(0, now - date.getTime())
  if (age <= 7 * 86_400_000) {
    const [unit, ms] = UNITS.find(([, ms]) => age >= ms) ?? ["minute", 60_000]
    return new Intl.RelativeTimeFormat("en", { numeric: "always" }).format(-Math.floor(age / ms), unit)
  }
  const sameYear = date.getFullYear() === new Date(now).getFullYear()
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", ...(sameYear ? {} : { year: "numeric" }) }).format(date)
}

/** The database's date and time in full, for a title on the relative one. */
export function dbDateTitle(value: string): string {
  const date = downloaded(value)
  return date ? new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" }).format(date) : ""
}
