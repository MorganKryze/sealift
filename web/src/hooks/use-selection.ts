import { useEffect, useState } from "react"

type SelectionMap = Record<string, string[]>

function readStorage<T extends object>(key: string): T {
  try {
    const raw = sessionStorage.getItem(key)
    return raw ? (JSON.parse(raw) as T) : ({} as T)
  } catch {
    return {} as T
  }
}

function writeStorage(key: string, map: object) {
  try {
    sessionStorage.setItem(key, JSON.stringify(map))
  } catch {
    // sessionStorage unavailable (private mode, quota, disabled storage):
    // the map still works for this render, just not across a reload.
  }
}

/**
 * A map kept in sessionStorage under storageKey. A changed key re-reads
 * storage without the extra render an effect-based sync would cost:
 * adjusting state during render is the documented way to reset it from a
 * changed prop.
 */
function useStoredMap<T extends object>(storageKey: string) {
  const [loadedKey, setLoadedKey] = useState(storageKey)
  const [map, setMap] = useState<T>(() => readStorage<T>(storageKey))

  if (storageKey !== loadedKey) {
    setLoadedKey(storageKey)
    setMap(readStorage<T>(storageKey))
  }

  useEffect(() => {
    writeStorage(storageKey, map)
  }, [storageKey, map])

  return [map, setMap] as const
}

/**
 * Holds the export selection (dependency name to the list of its chosen
 * versions) in sessionStorage, keyed by analysis, so it survives a
 * navigation to the export screen and back.
 */
export function useSelection(analysisId: string) {
  const [map, setMap] = useStoredMap<SelectionMap>(`sealift:selection:${analysisId}`)

  /** The review screen's radio choice: one version selected, or none (current is kept). */
  function selected(dependency: string, current: string): string {
    return map[dependency]?.[0] ?? current
  }

  /** Replaces whatever was picked for dependency with version, or clears it when version is current. */
  function pick(dependency: string, version: string, current: string) {
    setMap((prev) => ({ ...prev, [dependency]: version === current ? [] : [version] }))
  }

  function seedDefaults(defaults: SelectionMap) {
    setMap((prev) => {
      let changed = false
      const next = { ...prev }
      for (const [dependency, versions] of Object.entries(defaults)) {
        if (next[dependency] === undefined) {
          next[dependency] = versions
          changed = true
        }
      }
      return changed ? next : prev
    })
  }

  return { selected, pick, seedDefaults, selection: map }
}

/**
 * Holds the reasons written for an analysis' export, keyed by reasonKey, in
 * sessionStorage beside the selection, so a retry of a failed export sends
 * them again. Nothing reaches the server before an export is queued.
 */
export function useReasons(analysisId: string) {
  const [reasons, setReasons] = useStoredMap<Record<string, string>>(`sealift:reasons:${analysisId}`)

  function setReason(key: string, text: string) {
    setReasons((prev) => ({ ...prev, [key]: text }))
  }

  return { reasons, setReason }
}
