import { createHash } from 'node:crypto'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { env } from '../config/env.js'
import { holds, isSuperAdmin, manageableOrgs, rights } from '../authz/opa.js'
import { secondFactorIsFresh } from '../services/step-up.js'
import type { HomeModuleName } from './types.js'

/**
 * Who sees which part of the Home (home-data §3.2–3.3), resolved ONCE per request and entirely from
 * OPA — `rbac.user_info` for what the caller holds in jinbe, `rbac.delegation.manageable_orgs` for
 * the orgs they administer, `rbac.super_admin` — like every other gate in jinbe. Nothing here reads
 * a roster, a ConfigMap or the client's own claim.
 *
 * "Could not tell" is not "holds nothing": OPA unreachable fails the WHOLE request with 503, never a
 * quietly narrowed Home.
 */

export interface HomeScope {
  subject: string
  email: string
  name: string | null
  aal: 'aal1' | 'aal2'
  /** A second factor proven in the last 15 minutes (what requireRecentMfa asks of approvals). */
  stepUpFresh: boolean
  roles: string[]
  permissions: string[]
  /** Holds `admin:read` (super_admin, admin): the platform-wide modules. */
  platform: boolean
  superAdmin: boolean
  /** Holds `sites:apply`: may decide apply requests. */
  canApply: boolean
  /** Holds `users:read` (support, admin). */
  people: boolean
  sessions: boolean
  /** The orgs the caller administers, sorted. */
  orgs: string[]
}

/** Which slice of the data one answer is about. */
export type HomeView =
  | { kind: 'platform' }
  | { kind: 'orgs'; orgs: string[] }
  | { kind: 'self' }

declare module 'fastify' {
  interface FastifyRequest {
    homeScope?: HomeScope
  }
}

const PLATFORM_READ = 'admin:read'
const DEV_PERMISSIONS = ['admin:read', 'admin:write', 'sites:apply']

export class HomeScopeUnknown extends Error {}

async function tell<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (err) {
    throw new HomeScopeUnknown((err as Error).message)
  }
}

export async function resolveHomeScope(request: FastifyRequest): Promise<HomeScope | null> {
  const ctx = request.userContext
  if (!ctx?.id || ctx.id === 'unknown' || !ctx.email || ctx.email === 'unknown') return null
  const base = {
    subject: ctx.id,
    email: ctx.email,
    name: ctx.name && !ctx.name.includes('@') ? ctx.name : null,
    aal: ctx.aal === 'aal2' ? 'aal2' as const : 'aal1' as const,
    stepUpFresh: secondFactorIsFresh({ aal: ctx.aal, secondFactorAt: ctx.secondFactorAt, authVia: ctx.authVia }),
  }

  // Local development only, as every other gate does (require-admin.ts): a platform super admin.
  if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
    request.log.warn({ email: ctx.email }, '⚠️  DEV MODE: home scope bypassed')
    return { ...base, roles: ['platform-admin'], permissions: DEV_PERMISSIONS, platform: true, superAdmin: true, canApply: true, people: true, sessions: true, orgs: [] }
  }

  const [held, administered, superAdmin] = await Promise.all([
    tell(() => rights(ctx.email)),
    tell(() => manageableOrgs(ctx.email)),
    tell(() => isSuperAdmin(ctx.email)),
  ])
  const permissions = held.permissions
  return {
    ...base,
    roles: held.roles,
    permissions,
    platform: holds(permissions, PLATFORM_READ),
    superAdmin,
    canApply: holds(permissions, 'sites:apply'),
    people: holds(permissions, 'users:read'),
    sessions: holds(permissions, 'sessions:read'),
    orgs: [...new Set(administered)].sort(),
  }
}

/**
 * The gate on /api/home: any authenticated caller passes (everyone has `me` and their own recert
 * inbox); what they see is narrowed per module from the scope attached here. It carries no
 * permission marker on purpose — the published route table then reads it as `authenticated`, which
 * is exactly what it enforces.
 */
export function requireHomeScope() {
  return async function requireHomeScope(request: FastifyRequest, reply: FastifyReply) {
    let scope: HomeScope | null
    try {
      scope = await resolveHomeScope(request)
    } catch {
      request.log.warn({ subject: request.userContext?.id }, '[home] could not resolve what the caller may see — 503')
      return reply.status(503).send({ error: 'Service Unavailable', message: 'Unable to verify authorization. Please try again later.' })
    }
    if (!scope) return reply.status(401).send({ error: 'Unauthorized', message: 'Authentication required' })
    request.homeScope = scope
  }
}

/**
 * The view one answer covers. A requested org must be inside the caller's scope (else null → 403),
 * exactly as the audit API's `orgsFor`: a platform reader may narrow to any org; an org admin only to
 * one of theirs. No org means the whole scope.
 */
export function viewFor(scope: HomeScope, org?: string): HomeView | null {
  if (scope.platform) return org ? { kind: 'orgs', orgs: [org] } : { kind: 'platform' }
  if (org) return scope.orgs.includes(org) ? { kind: 'orgs', orgs: [org] } : null
  return scope.orgs.length > 0 ? { kind: 'orgs', orgs: scope.orgs } : { kind: 'self' }
}

const sha1 = (s: string) => createHash('sha1').update(s).digest('hex').slice(0, 16)

/**
 * The cache partition of a view. Platform modules are computed once for every platform reader, org
 * modules once per org set (hashed, so org ids never appear in a Redis key listing), self per subject.
 */
export function scopeKeyOf(view: HomeView, subject: string): string {
  if (view.kind === 'platform') return 'platform'
  if (view.kind === 'orgs') return `orgs:${sha1(view.orgs.join(','))}`
  return `self:${sha1(subject)}`
}

/** Module visibility (home-data §3.3). A module that answers false is omitted from the response. */
export function canSee(module: HomeModuleName, scope: HomeScope, view: HomeView): boolean {
  switch (module) {
    case 'health':
      return scope.platform
    case 'people':
      return view.kind !== 'self' || scope.people
    case 'activity':
    case 'access':
    case 'sites':
    case 'changes':
      return view.kind !== 'self'
    case 'attention':
    case 'actions':
    case 'me':
      return true
  }
}
