import { withRedisLock } from '../services/redis-lock.js'
import { sitesRepository } from './repository.js'
import { EPHEMERAL_TTL } from './schemas.js'
import { ephemeralStore, ephemeralView, type EphemeralState } from './lifecycle-store.js'
import { setPaused } from './apply.service.js'
import { getRecord } from './sites.service.js'
import { assertNotSystem, siteError } from './checks.js'
import { auditSite, type Actor } from './audit.js'

/**
 * Ephemeral sites (wave 19, owner-approved): a site saved with `ephemeral: {ttl}` is paused by jinbe
 * when its TTL passes — the existing pause, nothing deleted — audited, and marked expired. A renewal
 * (sites:write) moves the expiry; it does not resume an expired site (resuming is sites:apply).
 *
 * The sweep runs in the sites background tick (sync.ts), under its lock; each site is expired under
 * its own lock and re-read inside it, so two replicas, a restart mid-sweep or a renewal racing the
 * sweep pause a site at most once. Expiry state lives in Redis (lifecycle-store.ts).
 */

const EXPIRY_ACTOR: Actor = { id: null, email: 'jinbe (ephemeral)', ip: null, ua: null, sessionId: null, requestId: null }
const lockOf = (name: string) => `sites:expire:${name}`

/** Make the site ephemeral from now (`{ttlSec}`), or permanent (null). Called after a save. */
export async function setEphemeral(name: string, ephemeral: { ttl?: number } | null, actor: Actor) {
  return withRedisLock(lockOf(name), async () => {
    const current = await ephemeralStore.get(name)
    if (ephemeral === null) {
      if (!current) return null
      await ephemeralStore.clear(name)
      auditSite('ephemeral_off', name, actor, 'made permanent (no expiry)', { was: current })
      return null
    }
    const state = fresh(ephemeral.ttl ?? EPHEMERAL_TTL.defaultSec, actor)
    await ephemeralStore.set(name, state)
    auditSite('ephemeral', name, actor, `ephemeral: paused automatically at ${state.expiresAt}`, { ttlSec: state.ttlSec, expiresAt: state.expiresAt, ...(current ? { previousExpiresAt: current.expiresAt } : {}) })
    return ephemeralView(state)
  })
}

/** Move an ephemeral site's expiry to now + ttl (its own TTL when left out). */
export async function renewTtl(name: string, ttl: number | undefined, actor: Actor) {
  assertNotSystem(name)
  const record = await getRecord(name)
  return withRedisLock(lockOf(name), async () => {
    const current = await ephemeralStore.get(name)
    if (!current) throw siteError(409, 'not_ephemeral', `${name} is not ephemeral: it has no expiry to extend`)
    const state = fresh(ttl ?? current.ttlSec, actor)
    await ephemeralStore.set(name, state)
    auditSite('ttl_renew', name, actor, `expiry moved to ${state.expiresAt}${current.expiredAt ? ' (it had expired and stays paused)' : ''}`, {
      ttlSec: state.ttlSec, expiresAt: state.expiresAt, previousExpiresAt: current.expiresAt, ...(current.expiredAt ? { wasExpired: true } : {}),
    })
    const paused = record.site.state === 'paused'
    return {
      name,
      state: record.site.state,
      ephemeral: ephemeralView(state),
      ...(paused ? { hint: 'The site is paused: resume it (sites:apply) to serve it again.' } : {}),
    }
  })
}

function fresh(ttlSec: number, actor: Actor): EphemeralState {
  const now = Date.now()
  return { ttlSec, expiresAt: new Date(now + ttlSec * 1000).toISOString(), setBy: actor.email ?? 'unknown', setAt: new Date(now).toISOString() }
}

export interface ExpiryResult { expired: string[]; errors: string[] }

/** Pause every ephemeral site whose TTL has passed and is not marked expired yet. */
export async function expireDue(now = Date.now()): Promise<ExpiryResult> {
  const out: ExpiryResult = { expired: [], errors: [] }
  const due = (s: EphemeralState | null) => !!s && !s.expiredAt && Date.parse(s.expiresAt) <= now
  for (const [name, listed] of await ephemeralStore.all()) {
    if (!due(listed)) continue
    try {
      await withRedisLock(lockOf(name), async () => {
        const state = await ephemeralStore.get(name)
        if (!due(state)) return // renewed, or expired by another replica
        const record = await sitesRepository.get(name)
        if (!record) return ephemeralStore.clear(name)
        const wasPaused = record.site.state === 'paused'
        if (!wasPaused) await setPaused(name, true, EXPIRY_ACTOR)
        await ephemeralStore.set(name, { ...state!, expiredAt: new Date(now).toISOString() })
        auditSite('expire', name, EXPIRY_ACTOR, wasPaused ? 'TTL passed (already paused): marked expired' : 'TTL passed: paused automatically', {
          ttlSec: state!.ttlSec, expiresAt: state!.expiresAt, wasPaused,
        })
        out.expired.push(name)
      }, { waitMs: 0, ttlMs: 60_000 })
    } catch {
      // Kubernetes or the lock did not answer: the next tick tries again.
      out.errors.push(name)
    }
  }
  return out
}
