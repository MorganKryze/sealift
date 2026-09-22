import { useRef } from "react"

/**
 * Radix returns focus to a Dialog.Trigger on close, but these dialogs open
 * from code (a header button, a file drop), so focus fell to the page body.
 * Call `remember` as the dialog opens; pass `onCloseAutoFocus` to its content.
 */
export function useReturnFocus() {
  const opener = useRef<HTMLElement | null>(null)
  return {
    remember: () => {
      opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    },
    onCloseAutoFocus: (event: Event) => {
      if (opener.current?.isConnected) {
        event.preventDefault()
        opener.current.focus()
      }
    },
  }
}
