import { cleanup, render } from "@testing-library/react"
import { afterEach, expect, test } from "vitest"

import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog"

import { adoptStyleNonce } from "./nonce"

afterEach(() => {
  cleanup()
  document.head.querySelectorAll("meta[name=csp-nonce]").forEach((m) => m.remove())
})

test("the dialog's scroll lock style carries the page's nonce", () => {
  const meta = document.createElement("meta")
  meta.name = "csp-nonce"
  meta.content = "c2VhbGlmdC1ub25jZS10ZXN0"
  document.head.append(meta)
  adoptStyleNonce(document)
  render(
    <Dialog open>
      <DialogContent aria-describedby={undefined}>
        <DialogTitle>Cancel</DialogTitle>
      </DialogContent>
    </Dialog>,
  )
  const styles = [...document.head.querySelectorAll("style")]
  expect(styles.length).toBeGreaterThan(0)
  for (const s of styles) expect(s.getAttribute("nonce")).toBe("c2VhbGlmdC1ub25jZS10ZXN0")
})

test("a page without the meta tag leaves the nonce unset", () => {
  expect(adoptStyleNonce(document)).toBeUndefined()
})
