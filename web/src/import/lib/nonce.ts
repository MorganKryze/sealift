import { setNonce } from "get-nonce"

// The server names a fresh style nonce per page; the dialogs' scroll lock
// injects a <style> element the policy refuses without it.
export function adoptStyleNonce(doc: Document): string | undefined {
  const nonce = doc.querySelector<HTMLMetaElement>("meta[name=csp-nonce]")?.content
  if (nonce) setNonce(nonce)
  return nonce || undefined
}
