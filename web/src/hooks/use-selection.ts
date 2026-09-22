import { useEffect, useState } from "react"

type SelectionMap = Record<string, string[]>

function readStorage(key: string): SelectionMap {
  try {
    const raw = sessionStorage.getItem(key)
    return raw ? (JSON.parse(raw) as SelectionMap) : {}
  } catch {
    return {}
  }
}

function writeStorage(key: string, map: SelectionMap) {
  try {
    sessionStorage.setItem(key, JSON.stringify(map))
  } catch {
    // sessionStorage unavailable (private mode, quota, disabled storage):
    // the selection still works for this render, just not across a reload.
  }
}

/**
 * Holds the export selection (dependency name to the list of its chosen
 * versions) in sessionStorage, keyed by analysis, so it survives a
 * navigation to the export screen and back.
 */
export function useSelection(analysisId: string) {
  const storageKey = `sealift:selection:${analysisId}`
  const [loadedKey, setLoadedKey] = useState(storageKey)
  const [map, setMap] = useState<SelectionMap>(() => readStorage(storageKey))

  // Re-reads storage when the analysis changes, without the extra render an
  // effect-based sync would cost: adjusting state during render is the
  // documented way to reset it from a changed prop.
  if (storageKey !== loadedKey) {
    setLoadedKey(storageKey)
    setMap(readStorage(storageKey))
  }

  useEffect(() => {
    writeStorage(storageKey, map)
  }, [storageKey, map])

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
