import { apiFetch } from "./client"
import type { components } from "./schema"

export type Settings = components["schemas"]["Settings"]
export type SigningKey = components["schemas"]["SigningKey"]

export function getSettings(): Promise<Settings> {
  return apiFetch<Settings>("/settings")
}

export function getSigningKey(): Promise<SigningKey> {
  return apiFetch<SigningKey>("/signing-key")
}

export type Instance = components["schemas"]["Instance"]

export function getInstance(): Promise<Instance> {
  return apiFetch<Instance>("/instance")
}
