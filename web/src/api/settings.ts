import { apiFetch, apiFetchProblem } from "./client"
import type { components } from "./schema"

export type Settings = components["schemas"]["Settings"]
export type SigningKey = components["schemas"]["SigningKey"]

export function getSettings(): Promise<Settings> {
  return apiFetch<Settings>("/settings")
}

export function getSigningKey(): Promise<SigningKey> {
  return apiFetch<SigningKey>("/signing-key")
}

/** Replaces the key pair. The body is an empty JSON object: the server refuses any other kind of body. */
export function regenerateSigningKey(): Promise<SigningKey> {
  return apiFetchProblem<SigningKey>("/signing-key/regenerate", { method: "POST", body: "{}" })
}

export type Instance = components["schemas"]["Instance"]

export function getInstance(): Promise<Instance> {
  return apiFetch<Instance>("/instance")
}
