import { getRedisClient } from '../services/redis-client.service.js'

/**
 * The two lifecycle stores beside a site's intent (wave 19): its expiry when it is ephemeral, and the
 * requests to delete it. Neither is part of the intent — saving, rendering and the etag ignore them.
 *
 *   rbac:sites:ephemeral           → Hash: { name: JSON(EphemeralState) }
 *   rbac:sites:deletion-requests   → Hash: { id: JSON(DeletionRequest) }
 *
 * Plain storage, no service imports: apply.service.ts (delete) clears both through here.
 */

export interface EphemeralState {
  ttlSec: number
  expiresAt: string
  setBy: string
  setAt: string
  /** Set once the sweep paused the site for its TTL; a renewal clears it. */
  expiredAt?: string
}

export type DeletionRequestState = 'pending' | 'approved' | 'rejected' | 'cancelled'

export interface DeletionRequest {
  id: string
  site: string
  reason?: string
  requestedBy: string
  /** The requester's identity id: four-eyes compares it (the email as a fallback). */
  requesterId: string | null
  /** The client the requester acted through (an MCP key), when not a browser session. */
  requestedVia?: string
  requestedAt: string
  state: DeletionRequestState
  decidedBy?: string
  decidedAt?: string
  decisionReason?: string
}

const EPHEMERAL = 'rbac:sites:ephemeral'
const DELETIONS = 'rbac:sites:deletion-requests'
const redis = () => getRedisClient()

export const ephemeralStore = {
  async get(name: string): Promise<EphemeralState | null> {
    const raw = await redis().hget(EPHEMERAL, name)
    return raw ? (JSON.parse(raw) as EphemeralState) : null
  },
  async all(): Promise<Map<string, EphemeralState>> {
    const all = await redis().hgetall(EPHEMERAL)
    return new Map(Object.entries(all ?? {}).map(([name, raw]) => [name, JSON.parse(raw) as EphemeralState]))
  },
  async set(name: string, state: EphemeralState): Promise<void> {
    await redis().hset(EPHEMERAL, name, JSON.stringify(state))
  },
  async clear(name: string): Promise<void> {
    await redis().hdel(EPHEMERAL, name)
  },
}

export const deletionStore = {
  async get(id: string): Promise<DeletionRequest | null> {
    const raw = await redis().hget(DELETIONS, id)
    return raw ? (JSON.parse(raw) as DeletionRequest) : null
  },
  async all(): Promise<DeletionRequest[]> {
    return Object.values((await redis().hgetall(DELETIONS)) ?? {}).map((raw) => JSON.parse(raw) as DeletionRequest)
  },
  async put(request: DeletionRequest): Promise<void> {
    await redis().hset(DELETIONS, request.id, JSON.stringify(request))
  },
  /** Close the site's pending requests (but `except`, the one being approved): it was deleted. Returns their ids. */
  async cancelPending(site: string, by: string, reason: string, except?: string): Promise<string[]> {
    const pending = (await this.all()).filter((r) => r.site === site && r.state === 'pending' && r.id !== except)
    const at = new Date().toISOString()
    for (const r of pending) await this.put({ ...r, state: 'cancelled', decidedBy: by, decidedAt: at, decisionReason: reason })
    return pending.map((r) => r.id)
  },
}

/** What a listing and a site read show about an ephemeral site. */
export function ephemeralView(state: EphemeralState | null | undefined, now = Date.now()) {
  if (!state) return null
  return {
    ttlSec: state.ttlSec,
    expiresAt: state.expiresAt,
    remainingSec: Math.max(0, Math.round((Date.parse(state.expiresAt) - now) / 1000)),
    expired: !!state.expiredAt,
    ...(state.expiredAt ? { expiredAt: state.expiredAt } : {}),
    setBy: state.setBy,
  }
}
