import { randomUUID } from 'crypto'
import { getRedisClient } from './redis-client.service.js'
import { withRedisLock } from './redis-lock.js'

/**
 * Per-person direct grants (owner feature, authz-v2-design §2.6): besides groups, a person may hold a
 * single ROLE or a single PERMISSION of one app, platform-wide or inside one organisation.
 *
 *   rbac:direct_grants → Hash: { subjectId: JSON(DirectGrant[]) }
 *
 * Keyed by identity id (an address can change, the subject cannot), in jinbe's own store next to the
 * org role assignments: audited by jinbe, in the RBAC bundle and the bootstrap snapshot, published in
 * the /bindings document as data.bindings.direct[email] with expired grants left out (directBindings).
 * Reason and expiry are optional; who granted it and when are always kept.
 */

export type GrantScope = 'platform' | string // 'platform' or an organisation id
export type GrantKind = 'role' | 'permission'

export interface DirectGrant {
  id: string
  scope: GrantScope
  app: string
  kind: GrantKind
  /** The role name (in `app`) or the permission. */
  name: string
  reason?: string
  /** ISO time after which the grant stops counting (and is swept). */
  expiresAt?: string
  grantedBy: string
  grantedAt: string
}

/** What a caller asks for; the rest (id, who, when) is the store's. */
export type GrantRequest = Pick<DirectGrant, 'scope' | 'app' | 'kind' | 'name'> & Partial<Pick<DirectGrant, 'reason' | 'expiresAt'>>

/** One published grant: the name, and its expiry when it has one (the policy checks it too). */
export interface PublishedGrant {
  name: string
  expires_at?: string
}

/** The published shape per person (opal-policies `package rbac` §3, data.bindings.direct[email]). */
export interface DirectSlot {
  roles: PublishedGrant[]
  permissions: PublishedGrant[]
}
export interface DirectBinding {
  platform?: Record<string, DirectSlot>
  orgs?: Record<string, Record<string, DirectSlot>>
}

const KEY = 'rbac:direct_grants'
const NAME = /^[a-z0-9][a-z0-9_.:-]*$/
export const APP_NAME = /^[a-z0-9][a-z0-9_-]*$/

/** Two grants are the same grant when they give the same thing in the same place. */
export const grantKey = (g: Pick<DirectGrant, 'scope' | 'app' | 'kind' | 'name'>) => `${g.scope}|${g.app}|${g.kind}|${g.name}`

export const isActive = (g: Pick<DirectGrant, 'expiresAt'>, now = Date.now()) => !g.expiresAt || Date.parse(g.expiresAt) > now

function parse(raw: string): DirectGrant[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return []
  }
  if (!Array.isArray(parsed)) return []
  return parsed.filter((g): g is DirectGrant =>
    !!g && typeof g === 'object' && typeof g.id === 'string' && typeof g.scope === 'string' && typeof g.app === 'string' && APP_NAME.test(g.app) &&
    (g.kind === 'role' || g.kind === 'permission') && typeof g.name === 'string' && NAME.test(g.name) &&
    typeof g.grantedBy === 'string' && typeof g.grantedAt === 'string')
}

const sorted = (gs: DirectGrant[]) => [...gs].sort((a, b) => grantKey(a).localeCompare(grantKey(b)))

class DirectGrantsRepository {
  private get redis() { return getRedisClient() }

  /** Everything, expired included. Throws when Redis cannot be read — never a partial map. */
  async getAll(): Promise<Record<string, DirectGrant[]>> {
    const out: Record<string, DirectGrant[]> = {}
    for (const [subject, raw] of Object.entries(await this.redis.hgetall(KEY))) {
      const grants = parse(raw)
      if (grants.length) out[subject] = sorted(grants)
    }
    return out
  }

  async getFor(subjectId: string): Promise<DirectGrant[]> {
    const raw = await this.redis.hget(KEY, subjectId)
    return raw === null ? [] : sorted(parse(raw))
  }

  /**
   * Replaces the grants of one person IN the scopes named by `within` (all scopes when omitted) with
   * `wanted`: a grant already held (same scope, app, kind, name) keeps its id, author and date unless
   * its reason or expiry changed. Returns what was added (new or changed) and removed.
   */
  async replace(
    subjectId: string,
    wanted: readonly GrantRequest[],
    by: string,
    within?: (scope: GrantScope) => boolean,
  ): Promise<{ before: DirectGrant[]; after: DirectGrant[]; added: DirectGrant[]; removed: DirectGrant[] }> {
    return withRedisLock(`direct_grants:${subjectId}`, async () => {
      const before = await this.getFor(subjectId)
      const inScope = within ?? (() => true)
      const kept = before.filter((g) => !inScope(g.scope))
      const current = new Map(before.filter((g) => inScope(g.scope)).map((g) => [grantKey(g), g]))
      const now = new Date().toISOString()
      const next: DirectGrant[] = []
      const added: DirectGrant[] = []
      for (const w of wanted) {
        const same = current.get(grantKey(w))
        const unchanged = same && (same.reason ?? null) === (w.reason ?? null) && (same.expiresAt ?? null) === (w.expiresAt ?? null)
        if (same && unchanged) { next.push(same); continue }
        const g: DirectGrant = {
          id: same?.id ?? randomUUID(), scope: w.scope, app: w.app, kind: w.kind, name: w.name,
          ...(w.reason ? { reason: w.reason } : {}), ...(w.expiresAt ? { expiresAt: w.expiresAt } : {}),
          grantedBy: by, grantedAt: now,
        }
        next.push(g)
        added.push(g)
      }
      const nextKeys = new Set(next.map(grantKey))
      const removed = [...current.values()].filter((g) => !nextKeys.has(grantKey(g)))
      const after = sorted([...kept, ...next])
      await this.write(subjectId, after)
      return { before, after, added, removed }
    })
  }

  /** Takes one grant away by id; null when the person holds no such grant. */
  async revoke(subjectId: string, grantId: string): Promise<DirectGrant | null> {
    return withRedisLock(`direct_grants:${subjectId}`, async () => {
      const before = await this.getFor(subjectId)
      const gone = before.find((g) => g.id === grantId) ?? null
      if (gone) await this.write(subjectId, before.filter((g) => g.id !== grantId))
      return gone
    })
  }

  /** Expired grants, taken out of the store; returns them per person (for the audit trail). */
  async sweepExpired(now = Date.now()): Promise<Array<{ subjectId: string; grant: DirectGrant }>> {
    const out: Array<{ subjectId: string; grant: DirectGrant }> = []
    for (const [subjectId, grants] of Object.entries(await this.getAll())) {
      if (grants.every((g) => isActive(g, now))) continue
      await withRedisLock(`direct_grants:${subjectId}`, async () => {
        const current = await this.getFor(subjectId)
        const expired = current.filter((g) => !isActive(g, now))
        if (expired.length === 0) return
        await this.write(subjectId, current.filter((g) => isActive(g, now)))
        out.push(...expired.map((grant) => ({ subjectId, grant })))
      })
    }
    return out
  }

  /** Exactly these grants for one person, as stored (a bundle restore: ids, authors and dates kept). */
  async restore(subjectId: string, grants: readonly DirectGrant[]): Promise<void> {
    await withRedisLock(`direct_grants:${subjectId}`, () => this.write(subjectId, parse(JSON.stringify(grants))))
  }

  /** The person left an org: their grants there go with the membership. */
  async forgetOrg(subjectId: string, organizationId: string): Promise<DirectGrant[]> {
    return withRedisLock(`direct_grants:${subjectId}`, async () => {
      const before = await this.getFor(subjectId)
      const gone = before.filter((g) => g.scope === organizationId)
      if (gone.length) await this.write(subjectId, before.filter((g) => g.scope !== organizationId))
      return gone
    })
  }

  private async write(subjectId: string, grants: DirectGrant[]): Promise<void> {
    if (grants.length) await this.redis.hset(KEY, subjectId, JSON.stringify(sorted(grants)))
    else await this.redis.hdel(KEY, subjectId)
  }
}

export const directGrantsRepository = new DirectGrantsRepository()

/**
 * One person's grants as the policy reads them (data.bindings.direct[email]): active grants only, each
 * with its expiry (the policy counts a grant until expires_at even when the feed is stale), org grants
 * only where they are a member. Null when nothing remains.
 */
export function directBinding(grants: readonly DirectGrant[], memberOf: readonly string[], now = Date.now()): DirectBinding | null {
  const platform: NonNullable<DirectBinding['platform']> = {}
  const orgs: NonNullable<DirectBinding['orgs']> = {}
  for (const g of grants) {
    if (!isActive(g, now)) continue
    let slot: DirectSlot
    if (g.scope === 'platform') slot = (platform[g.app] ??= { roles: [], permissions: [] })
    else if (memberOf.includes(g.scope)) slot = ((orgs[g.scope] ??= {})[g.app] ??= { roles: [], permissions: [] })
    else continue
    const list = g.kind === 'role' ? slot.roles : slot.permissions
    if (!list.some((x) => x.name === g.name)) list.push({ name: g.name, ...(g.expiresAt ? { expires_at: g.expiresAt } : {}) })
  }
  const byName = (a: PublishedGrant, b: PublishedGrant) => a.name.localeCompare(b.name)
  for (const s of [...Object.values(platform), ...Object.values(orgs).flatMap((o) => Object.values(o))]) {
    s.roles.sort(byName)
    s.permissions.sort(byName)
  }
  const out: DirectBinding = {}
  if (Object.keys(platform).length) out.platform = platform
  if (Object.keys(orgs).length) out.orgs = orgs
  return Object.keys(out).length ? out : null
}
