import { getRedisClient } from './redis-client.service.js'

/**
 * When each API key (org machine key or personal key) was last used, for the key lists: one Redis hash
 * `apikey:last_used` (field = client_id, value = epoch ms), shared by every replica.
 *
 * Written from the places that already see a key being used — the internal client-id resolution
 * (the introspection path of an org key), the personal-key exchange, and the delegated introspection
 * of a personal key's token — at most once a minute per key per replica, fire-and-forget. Read with
 * one HMGET per list, under a short deadline. Neither side ever holds up or fails a request: an
 * unreadable store answers "unknown" (null), a lost write is a slightly older date.
 */

export const LAST_USED_KEY = 'apikey:last_used'
const WRITE_EVERY_MS = 60_000
const READ_DEADLINE_MS = 250
const MAX_TRACKED = 10_000

const lastWritten = new Map<string, number>()

/** Record that `clientId` was used now. Never throws, never awaited by a caller. */
export function touchApiKeyUse(clientId: string, now: number = Date.now()): void {
  if (!clientId) return
  const prev = lastWritten.get(clientId)
  if (prev !== undefined && now - prev < WRITE_EVERY_MS) return
  if (lastWritten.size >= MAX_TRACKED) lastWritten.clear()
  lastWritten.set(clientId, now)
  try {
    getRedisClient().hset(LAST_USED_KEY, clientId, String(now)).catch(() => {})
  } catch {
    // No Redis: the date is only for display.
  }
}

/** A revoked key's date goes with it. */
export function forgetApiKeyUse(clientId: string): void {
  lastWritten.delete(clientId)
  try {
    getRedisClient().hdel(LAST_USED_KEY, clientId).catch(() => {})
  } catch {
    // Harmless: nothing lists a deleted client.
  }
}

/** RFC 3339 last use per client id; a key never seen (or an unreadable store) is absent. */
export async function lastUsedOf(clientIds: readonly string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>()
  const ids = [...new Set(clientIds.filter(Boolean))]
  if (ids.length === 0) return out
  let timer: NodeJS.Timeout | undefined
  try {
    const values = await Promise.race([
      getRedisClient().hmget(LAST_USED_KEY, ...ids),
      new Promise<null>((resolve) => { timer = setTimeout(() => resolve(null), READ_DEADLINE_MS) }),
    ])
    if (!values) return out
    ids.forEach((id, i) => {
      const ms = Number(values[i])
      if (values[i] && Number.isFinite(ms)) out.set(id, new Date(ms).toISOString())
    })
  } catch {
    // Unknown, not an error.
  } finally {
    if (timer) clearTimeout(timer)
  }
  return out
}

/** Tests only. */
export function resetApiKeyUseThrottle(): void {
  lastWritten.clear()
}
