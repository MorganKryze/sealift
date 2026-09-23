/**
 * The targets an archive can be prepared for. os, cpu and libc only filter
 * the native packages npm would install, and libc only means something on
 * Linux, so the settings offer these combinations rather than three free
 * fields that allow nonsense such as musl on Windows.
 */
export const PLATFORMS = [
  { id: "linux-x64-glibc", label: "Linux x64 · glibc", hint: "Ubuntu, Debian, RHEL", os: "linux", cpu: "x64", libc: "glibc" },
  { id: "linux-arm64-glibc", label: "Linux arm64 · glibc", hint: "Ubuntu, Debian on ARM servers", os: "linux", cpu: "arm64", libc: "glibc" },
  { id: "linux-x64-musl", label: "Linux x64 · musl", hint: "Alpine", os: "linux", cpu: "x64", libc: "musl" },
  { id: "linux-arm64-musl", label: "Linux arm64 · musl", hint: "Alpine on ARM", os: "linux", cpu: "arm64", libc: "musl" },
] as const

export type PlatformId = (typeof PLATFORMS)[number]["id"]

interface PlatformFields {
  os: string
  cpu: string
  libc: string
}

/** The listed platform matching a target, or undefined for one saved outside the list. */
export function platformIdOf(target: PlatformFields): PlatformId | undefined {
  return PLATFORMS.find((p) => p.os === target.os && p.cpu === target.cpu && p.libc === target.libc)?.id
}

export function targetOf(id: string): PlatformFields | undefined {
  const platform = PLATFORMS.find((p) => p.id === id)
  return platform ? { os: platform.os, cpu: platform.cpu, libc: platform.libc } : undefined
}
