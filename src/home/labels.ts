import * as sources from './sources.js'

/**
 * id / email → display name, for every person the Home names (home-data J10, privacy rule 1).
 *
 * Several stores still record people by address (`appliedBy`, `draft.by`, `requestedBy`, the legacy
 * trail's `who`). The Home never forwards one: it resolves the display name from the identity
 * directory and falls back to "Unknown user" — never to the address, and never to a local part of it.
 *
 * Held per replica, refreshed in the background every 5 minutes from the light directory walk that
 * OPAL's bindings feed already keeps warm. A cold directory is loaded once (single-flight).
 */

export const UNKNOWN_USER = 'Unknown user'
const FRESH_MS = 5 * 60_000

type Entry = { id: string; name: string | null; active: boolean }

let byEmail = new Map<string, Entry>()
let byId = new Map<string, Entry>()
let loadedAt = 0
let loading: Promise<void> | null = null

function load(): Promise<void> {
  if (loading) return loading
  loading = (async () => {
    const dir = await sources.identityDirectory()
    byEmail = new Map([...dir].map(([email, e]) => [email.toLowerCase(), e]))
    byId = new Map([...dir.values()].map((e) => [e.id, e]))
    loadedAt = Date.now()
  })().finally(() => { loading = null })
  return loading
}

/** Loads on first use; later calls refresh in the background when older than 5 minutes. */
export async function ensureLabels(): Promise<void> {
  if (loadedAt === 0) {
    await load()
    return
  }
  if (Date.now() - loadedAt >= FRESH_MS) void load().catch(() => {})
}

const EMAILISH = /@/

/** A person recorded by address or id, as the Home may show them. */
export function person(ref: string | null | undefined): { id: string | null; label: string } {
  if (!ref || ref === 'unknown' || ref === 'anon') return { id: null, label: UNKNOWN_USER }
  const e = EMAILISH.test(ref) ? byEmail.get(ref.toLowerCase()) : byId.get(ref)
  if (!e) return { id: EMAILISH.test(ref) ? null : ref, label: UNKNOWN_USER }
  return { id: e.id, label: e.name?.trim() && !EMAILISH.test(e.name) ? e.name.trim() : UNKNOWN_USER }
}

/** Kratos id → active, for counting an org's active members; undefined when unknown. */
export const isActive = (id: string): boolean | undefined => byId.get(id)?.active

/** Test seam. */
export function resetLabels(): void {
  byEmail = new Map()
  byId = new Map()
  loadedAt = 0
  loading = null
}
