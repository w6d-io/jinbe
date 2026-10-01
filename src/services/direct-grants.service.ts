import { z } from 'zod'
import { grantVerdict, invalidateAuthz, type GrantVerdict } from '../authz/opa.js'
import { auditEventService, type AuditActorInput } from './audit-event.service.js'
import { rbacService } from './rbac.service.js'
import { kratosService } from './kratos.service.js'
import { flatten } from './grant-subset.js'
import {
  APP_NAME, directGrantsRepository, grantKey, isActive, type DirectGrant, type GrantRequest, type GrantScope,
} from './direct-grants.repository.js'

/**
 * Per-person direct grants: one role (`app` role name) or one permission of one app, platform-wide or
 * inside one organisation, with an optional reason and expiry (authz-v2-design §2.6).
 *
 * The holding rule is the policy's, as for every grant: each grant ADDED (new, or its reason/expiry
 * changed) asks `rbac.delegation.grant_direct_verdict`; taking grants away asks
 * `revoke_direct_verdict` once per scope. Nothing is written unless every verdict allows, and a
 * verdict OPA cannot give is a 503 (AuthzUnavailableError), never a write. Every grant, revocation,
 * expiry and refusal is audited with who and when.
 */

const ROLE_NAME = /^[a-z][a-z0-9_-]{0,39}$/
const PERMISSION = /^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_-]*$/

export const grantRequestSchema = z.object({
  scope: z.union([z.literal('platform'), z.string().uuid()]),
  app: z.string().regex(APP_NAME, 'an app (site or service) name'),
  kind: z.enum(['role', 'permission']),
  name: z.string().min(1).max(120),
  reason: z.string().trim().max(500).optional(),
  expiresAt: z.string().datetime().optional(),
}).strict().superRefine((g, ctx) => {
  if (g.kind === 'role' && !ROLE_NAME.test(g.name)) ctx.addIssue({ code: 'custom', path: ['name'], message: 'a role name' })
  if (g.kind === 'permission' && !PERMISSION.test(g.name)) ctx.addIssue({ code: 'custom', path: ['name'], message: 'a permission like resource:verb (no wildcard)' })
  if (g.expiresAt && Date.parse(g.expiresAt) <= Date.now()) ctx.addIssue({ code: 'custom', path: ['expiresAt'], message: 'must be in the future' })
})

export const grantsBodySchema = z.object({ grants: z.array(grantRequestSchema).max(100) }).strict()

/** JSON schemas for the routes (the zod ones above validate; these document and serialize). */
export const grantJsonSchema = {
  type: 'object',
  properties: {
    id: { type: 'string' },
    scope: { type: 'string', description: '"platform" or an organisation id' },
    app: { type: 'string' },
    kind: { type: 'string', enum: ['role', 'permission'] },
    name: { type: 'string' },
    reason: { type: 'string' },
    expiresAt: { type: 'string', format: 'date-time' },
    grantedBy: { type: 'string' },
    grantedAt: { type: 'string', format: 'date-time' },
    active: { type: 'boolean' },
  },
} as const

export const grantRequestJsonSchema = {
  type: 'object',
  required: ['scope', 'app', 'kind', 'name'],
  additionalProperties: false,
  properties: {
    scope: { type: 'string', description: '"platform" or an organisation id' },
    app: { type: 'string', pattern: APP_NAME.source },
    kind: { type: 'string', enum: ['role', 'permission'] },
    name: { type: 'string', minLength: 1, maxLength: 120 },
    reason: { type: 'string', maxLength: 500 },
    expiresAt: { type: 'string', format: 'date-time' },
  },
} as const

export interface GrantRefusal {
  grant: Pick<DirectGrant, 'scope' | 'app' | 'kind' | 'name'> & { id?: string }
  reasons: string[]
  missing: string[]
  grantedBy: string[]
}

const what = (g: Pick<DirectGrant, 'scope' | 'app' | 'kind' | 'name'>) => ({ scope: g.scope, app: g.app, kind: g.kind, name: g.name })

function refusalOf(g: Pick<DirectGrant, 'scope' | 'app' | 'kind' | 'name'> & { id?: string }, v: GrantVerdict): GrantRefusal {
  return {
    grant: { ...what(g), ...(g.id ? { id: g.id } : {}) },
    reasons: v.reasons,
    missing: [...flatten(v.missing), ...flatten(v.missingEveryOrg).map((p) => `every organisation: ${p}`)],
    grantedBy: v.grantedBy,
  }
}

/** A grant as answered by the API: stored fields and whether it still counts. */
export const view = (g: DirectGrant, now = Date.now()) => ({ ...g, active: isActive(g, now) })

export class GrantsRefusedError extends Error {
  constructor(public readonly refused: GrantRefusal[]) {
    super(`Not allowed: ${refused.map((r) => `${r.grant.kind} ${r.grant.app}:${r.grant.name} (${r.grant.scope})`).join(', ')}`)
  }
}

function audit(type: string, subjectId: string, actor: AuditActorInput, details: Record<string, unknown>, result: 'applied' | 'denied' = 'applied') {
  auditEventService.emit({
    type, actor, target: { type: 'user', id: subjectId }, result, details, source: 'jinbe-api',
  }).catch(() => {})
}

class DirectGrantsService {
  /**
   * Replaces one person's grants in the scopes `within` covers (the admin route: every scope; the org
   * route: that org only) after the policy allows every change. Returns the person's grants after.
   */
  async replace(opts: {
    subjectId: string
    granteeEmail: string
    wanted: readonly GrantRequest[]
    actor: AuditActorInput & { email: string }
    within?: (scope: GrantScope) => boolean
  }): Promise<DirectGrant[]> {
    const { subjectId, granteeEmail, actor } = opts
    const within = opts.within ?? (() => true)
    const outside = opts.wanted.filter((g) => !within(g.scope))
    if (outside.length) throw Object.assign(new Error(`Grants outside this organisation: ${outside.map((g) => g.scope).join(', ')}`), { statusCode: 400 })

    const before = (await directGrantsRepository.getFor(subjectId)).filter((g) => within(g.scope))
    const current = new Map(before.map((g) => [grantKey(g), g]))
    const added = opts.wanted.filter((w) => {
      const same = current.get(grantKey(w))
      return !same || (same.reason ?? null) !== (w.reason ?? null) || (same.expiresAt ?? null) !== (w.expiresAt ?? null)
    })
    const wantedKeys = new Set(opts.wanted.map(grantKey))
    const removed = before.filter((g) => !wantedKeys.has(grantKey(g)))

    const refused: GrantRefusal[] = []
    for (const g of added) {
      const v = await grantVerdict({ kind: 'grant_direct', actor: actor.email, grantee: granteeEmail, scope: g.scope, app: g.app, grantKind: g.kind, name: g.name })
      if (!v.allow) refused.push(refusalOf(g, v))
    }
    for (const scope of new Set(removed.map((g) => g.scope))) {
      const v = await grantVerdict({ kind: 'revoke_direct', actor: actor.email, scope })
      if (!v.allow) refused.push(...removed.filter((g) => g.scope === scope).map((g) => refusalOf(g, v)))
    }
    if (refused.length) {
      audit('user.grant_refused', subjectId, actor, { email: granteeEmail, refused }, 'denied')
      throw new GrantsRefusedError(refused)
    }

    const result = await directGrantsRepository.replace(subjectId, opts.wanted, actor.email, within)
    for (const g of result.added) audit('user.grant_granted', subjectId, actor, { email: granteeEmail, grant: g })
    for (const g of result.removed) audit('user.grant_revoked', subjectId, actor, { email: granteeEmail, grant: g })
    if (result.added.length || result.removed.length) await this.changed('direct_grants_changed', actor)
    return result.after
  }

  /** Takes one grant away (its scope must pass `within`); null when there is no such grant there. */
  async revoke(opts: {
    subjectId: string
    granteeEmail: string
    grantId: string
    actor: AuditActorInput & { email: string }
    within?: (scope: GrantScope) => boolean
  }): Promise<DirectGrant | null> {
    const within = opts.within ?? (() => true)
    const grant = (await directGrantsRepository.getFor(opts.subjectId)).find((g) => g.id === opts.grantId && within(g.scope))
    if (!grant) return null
    const v = await grantVerdict({ kind: 'revoke_direct', actor: opts.actor.email, scope: grant.scope })
    if (!v.allow) {
      const refused = [refusalOf(grant, v)]
      audit('user.grant_refused', opts.subjectId, opts.actor, { email: opts.granteeEmail, refused }, 'denied')
      throw new GrantsRefusedError(refused)
    }
    const gone = await directGrantsRepository.revoke(opts.subjectId, opts.grantId)
    if (gone) {
      audit('user.grant_revoked', opts.subjectId, opts.actor, { email: opts.granteeEmail, grant: gone })
      await this.changed('direct_grants_changed', opts.actor)
    }
    return gone
  }

  /** Everyone holding direct grants (review, recertification): id, address, grants. */
  async everyone(filter?: (g: DirectGrant) => boolean): Promise<Array<{ id: string; email: string | null; grants: ReturnType<typeof view>[] }>> {
    const all = await directGrantsRepository.getAll()
    const ids = Object.keys(all)
    const identities = ids.length ? await kratosService.getIdentitiesByIds(ids) : new Map()
    const now = Date.now()
    return ids.map((id) => ({
      id,
      email: ((identities.get(id)?.traits as { email?: string } | undefined)?.email) ?? null,
      grants: all[id].filter((g) => !filter || filter(g)).map((g) => view(g, now)),
    })).filter((p) => p.grants.length > 0).sort((a, b) => (a.email ?? a.id).localeCompare(b.email ?? b.id))
  }

  /** Expired grants out of the store, each audited; the policy data refreshed when any went. */
  async sweep(now = Date.now()): Promise<number> {
    const expired = await directGrantsRepository.sweepExpired(now)
    for (const { subjectId, grant } of expired) {
      audit('user.grant_expired', subjectId, { email: 'system' }, { grant })
    }
    if (expired.length) await this.changed('direct_grants_expired', { email: 'system' })
    return expired.length
  }

  private async changed(reason: string, actor: AuditActorInput): Promise<void> {
    invalidateAuthz()
    await rbacService.notifyBindingsChanged(reason, actor).catch(() => {})
  }
}

export const directGrantsService = new DirectGrantsService()

let sweeper: ReturnType<typeof setInterval> | null = null

/** Every minute in the server: an expiry holds even if nobody looks. */
export function startDirectGrantSweeper(logger: { warn(obj: object, msg?: string): void }): void {
  if (sweeper) return
  sweeper = setInterval(() => {
    void directGrantsService.sweep().catch((err) => logger.warn({ err: (err as Error).message }, 'direct grant sweep failed'))
  }, 60_000)
  sweeper.unref?.()
}
