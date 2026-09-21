import { act, renderHook } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { useJobEvents } from "@/hooks/use-job-events"

// Mimics the browser's real EventSource close enough to drive the hook
// with the exact bytes internal/api/events.go's writeSSE writes: named
// frames ("event: step\ndata: {...}\n\n"), not pre-parsed JobEvent
// objects. That is the shape the hook broke on: it used to listen with
// onmessage, which a named frame never reaches.
class FakeEventSource {
  static instances: FakeEventSource[] = []
  listeners = new Map<string, Set<(event: MessageEvent<string>) => void>>()
  closed = false

  constructor(public url: string) {
    FakeEventSource.instances.push(this)
  }

  addEventListener(type: string, listener: (event: MessageEvent<string>) => void) {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, new Set())
    }
    this.listeners.get(type)!.add(listener)
  }

  removeEventListener(type: string, listener: (event: MessageEvent<string>) => void) {
    this.listeners.get(type)?.delete(listener)
  }

  close() {
    this.closed = true
  }

  emitRaw(raw: string) {
    for (const frame of raw.split("\n\n")) {
      if (!frame.trim()) {
        continue
      }
      const lines = frame.split("\n")
      const eventLine = lines.find((line) => line.startsWith("event: "))
      const dataLine = lines.find((line) => line.startsWith("data: "))
      if (!eventLine || !dataLine) {
        continue
      }
      const type = eventLine.slice("event: ".length)
      const data = dataLine.slice("data: ".length)
      for (const listener of this.listeners.get(type) ?? []) {
        listener({ data } as MessageEvent<string>)
      }
    }
  }
}

let realEventSource: typeof EventSource

beforeEach(() => {
  FakeEventSource.instances = []
  realEventSource = globalThis.EventSource
  // @ts-expect-error test double, narrower than the real EventSource
  globalThis.EventSource = FakeEventSource
})

afterEach(() => {
  globalThis.EventSource = realEventSource
})

describe("useJobEvents", () => {
  it("folds a named step frame belonging to this store id", () => {
    const { result } = renderHook(() => useJobEvents("analysis-1", true, vi.fn()))
    const source = FakeEventSource.instances[0]!

    act(() => {
      source.emitRaw(
        'event: step\ndata: {"kind":"step","job":"analysis-3","storeId":"analysis-1","data":{"name":"resolve","state":"running"}}\n\n',
      )
    })

    expect(result.current.steps).toEqual([{ name: "resolve", state: "running", durationMs: undefined }])
  })

  it("ignores a frame whose store id belongs to a different job", () => {
    const { result } = renderHook(() => useJobEvents("analysis-1", true, vi.fn()))
    const source = FakeEventSource.instances[0]!

    act(() => {
      source.emitRaw(
        'event: step\ndata: {"kind":"step","job":"analysis-3","storeId":"analysis-2","data":{"name":"resolve","state":"running"}}\n\n',
      )
    })

    expect(result.current.steps).toEqual([])
  })

  it("calls onEnd once the matching end frame arrives", () => {
    const onEnd = vi.fn()
    renderHook(() => useJobEvents("analysis-1", true, onEnd))
    const source = FakeEventSource.instances[0]!

    act(() => {
      source.emitRaw('event: end\ndata: {"kind":"end","job":"analysis-3","storeId":"analysis-1","data":{"state":"done"}}\n\n')
    })

    expect(onEnd).toHaveBeenCalledTimes(1)
  })

  it("does not subscribe while inactive", () => {
    renderHook(() => useJobEvents("analysis-1", false, vi.fn()))
    expect(FakeEventSource.instances).toHaveLength(0)
  })
})
