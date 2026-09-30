import type { FastifyRequest } from 'fastify'
import type { ZodType, ZodTypeDef } from 'zod'
import { scopeGrants, specOf, type Permission } from '../policy/catalog.js'
import { KratosApiError, kratosService } from '../services/kratos.service.js'
import { allows } from '../services/user-permissions.js'
import type { GroupUpdateActor } from '../services/user-groups.service.js'
import type { AuditActor } from '../services/audit-event.service.js'
import type { KratosIdentity } from '../schemas/admin.schema.js'
import { auditActor } from '../utils/audit-actor.js'
import { actorOf } from '../sites/http.js'
import { keyStepUpVerdict } from '../middleware/delegated-step-up.js'
import type { Actor as SiteActor } from '../sites/audit.js'

/**
 * One bulk operation (mcp-write-wave.md §3, owner revision: direct, never a delete): many items of
 * the same change, planned first (a dry run judged against the caller's rights), then executed with
 * each item re-checked by the same guards as its single route.
 */

export const BULK_MAX_ITEMS = 200

/** What planning an item says would happen. */
export type Outcome =
  | { status: 'ok'; action: string }
  | { status: 'skip'; reason: string }
  | { status: 'refused'; reason: string }
  | { status: 'not_found' }

/** What executing an item did. */
export type ItemResult = { status: 'done'; action: string } | { status: 'skipped' | 'refused' | 'failed'; reason: string }

/**
 * Who asked, captured while the request is in hand: execution goes on after the answer is sent. The
 * rights are the caller's NOW (the route guard just asked OPA); the scopes narrow them for a key.
 */
export interface Caller {
  id: string
  delegated: boolean
  clientId: string | null
  scopes: readonly string[]
  permissions: readonly string[]
  audit: AuditActor & { requestId: string | null }
  groupActor: GroupUpdateActor
  siteActor: SiteActor
}

export function callerOf(request: FastifyRequest): Caller {
  const uc = request.userContext
  const audit = auditActor(request)
  return {
    id: uc?.id ?? 'unknown',
    delegated: uc?.authVia === 'delegated',
    clientId: uc?.delegation?.clientId ?? null,
    scopes: uc?.delegation?.scopes ?? [],
    permissions: request.rbacInfo?.permissions ?? [],
    audit,
    groupActor: { ...audit, aal: uc?.aal, authenticatedAt: uc?.authenticatedAt, secondFactorAt: uc?.secondFactorAt, authVia: uc?.authVia, stepUpViaKey: keyStepUpVerdict(request, 'groups.members:write').ok },
    siteActor: actorOf(request),
  }
}

/**
 * Whether the caller may use a permission on an item: the user holds it, and for a key the token
 * covers it and the catalogue lets a token use it at all (the delegation gate's rules 1 and 4).
 */
export function may(caller: Caller, permission: Permission): boolean {
  if (!allows(caller.permissions, permission)) return false
  if (!caller.delegated) return true
  return specOf(permission)?.delegable !== 'never' && scopeGrants(caller.scopes, permission)
}

export interface RunContext {
  jobId: string
}

export interface BulkOp<I = unknown, P = unknown, S = unknown> {
  /** The catalogue permission the op's routes declare (the gate checks a key's scope against it). */
  permission: Permission
  item: ZodType<I, ZodTypeDef, unknown>
  params: ZodType<P, ZodTypeDef, unknown>
  /** What makes two items the same (refused as a duplicate). */
  key(item: I): string
  /** What every item is judged against, read once per plan and once per run. */
  load(caller: Caller, params: P): Promise<S>
  plan(caller: Caller, params: P, state: S, item: I): Promise<Outcome>
  run(caller: Caller, params: P, state: S, item: I, ctx: RunContext): Promise<ItemResult>
  /** For ops whose items build ONE write (the site draft): made after every item ran. */
  commit?(caller: Caller, params: P, state: S, ctx: RunContext): Promise<void>
  /** Said once for the whole plan (a limit the items will meet). */
  warnings?(caller: Caller, params: P, outcomes: Outcome[]): string[]
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** A user named by identity id or address, or null when there is none. */
export async function resolveUser(ref: string): Promise<KratosIdentity | null> {
  if (UUID.test(ref)) {
    try {
      return await kratosService.getIdentity(ref)
    } catch (err) {
      if (err instanceof KratosApiError && err.statusCode === 404) return null
      throw err
    }
  }
  return kratosService.findByEmail(ref.trim().toLowerCase())
}

/** "No such user" only for somebody who may look users up; anybody else learns nothing. */
export const notFound = (caller: Caller): Outcome =>
  may(caller, 'users:read') ? { status: 'not_found' } : { status: 'refused', reason: 'unavailable' }

export const isSelf = (caller: Caller, identity: KratosIdentity) => identity.id === caller.id
