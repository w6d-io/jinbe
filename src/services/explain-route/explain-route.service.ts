import type { FastifyInstance } from 'fastify'
import { decisionInput, memberOrgs, orgPermissionsByOrg, rights } from '../../authz/opa.js'
import { queryOpa } from '../opa-client.js'
import { grants, isCatalogPermission, specOf } from '../../policy/catalog.js'
import { declaredRoute, type DeclaredRoute } from '../../policy/declared-routes.js'
import { patternFor, routeChain } from '../../policy/route-guards.js'
import { delegationOf, isClient } from '../../middleware/require-service-admin.js'
import { delegationRefusal } from '../../middleware/delegation-gate.js'
import type { UserContext } from '../../middleware/identity-extractor.js'
import { redisRbacRepository, type RouteRule } from '../redis-rbac.repository.js'
import { orgRolesRepository } from '../org-roles.repository.js'
import { dryRequest, dryRunChain, type ChainVerdict } from './guard-dry-run.js'
import { findDisagreements, type Disagreement } from './disagreements.js'

/**
 * "Why did jinbe accept or refuse THIS call?" — the chain the request runs, each step with what it
 * read and what it answered (POST /api/admin/rbac/explain-route):
 *
 *   route       → the pattern, its declaration, the guards Fastify runs for it
 *   catalogue   → the permission's spec (scope, delegable, step-up)
 *   delegation  → the delegation gate's verdict for a user through a client
 *   platform    → what the subject holds in jinbe on platform routes (OPA user_info)
 *   opa         → rbac.decision with EXACTLY the guard's input, rbac.explain (which clause fired;
 *                 optional — absent on a policy that predates it) and the matching route rows
 *   org         → for an org route: membership, the org roles assigned there, the org permissions
 *                 OPA says they hold there (assigned ∪ every-org) and the org's entitled sites
 *   guard       → the route's real guards run in a dry run: the status and body the caller gets
 *
 * Nothing is replayed in JS: every verdict is the policy's or the guard's own. A step that could not
 * be asked says `unavailable` and the others still run.
 */

export type StepVerdict = 'pass' | 'refuse' | 'info' | 'skipped' | 'unavailable'

export interface ExplainStep {
  step: 'route' | 'catalogue' | 'delegation' | 'platform' | 'opa' | 'org' | 'guard'
  verdict: StepVerdict
  input?: Record<string, unknown>
  detail: Record<string, unknown>
}

export interface ExplainQuestion {
  method: string
  path: string
  body?: unknown
}

export interface ExplainResult {
  subject: { id: string; email: string; via: string; aal?: string; client: boolean; scopes?: readonly string[] }
  route: { method: string; path: string; pattern: string | null; params: Record<string, string> }
  verdict: { status: number; allowed: boolean; code?: string; reason?: string; message?: string }
  decidedBy: string
  steps: ExplainStep[]
  disagreements: Disagreement[]
}

/** What rbac.explain answers (opal-policies rbac-explain.patch). */
export interface PolicyExplain {
  allow: boolean
  reason: string
  granted: boolean
  granted_by: string[]
  step_up_required: boolean
  step_up_by: string[]
  effective_app: string | null
  matching_rules: RouteRule[]
  is_client: boolean
  session_aal: number
  second_factor_required: boolean
}

async function attempt<T>(fn: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: string }> {
  try {
    return { ok: true, value: await fn() }
  } catch (err) {
    return { ok: false, error: (err as Error).message }
  }
}

const orgOf = (row: DeclaredRoute | null, pattern: string, params: Record<string, string>): string | null => {
  const name = row?.org ?? (pattern.startsWith('/api/organizations/:organizationId') ? 'organizationId' : null)
  return name ? params[name] ?? null : null
}

function bodyField(body: unknown, key: string): string | undefined {
  const v = body && typeof body === 'object' ? (body as Record<string, unknown>)[key] : undefined
  return typeof v === 'string' ? v : undefined
}

export async function explainRoute(fastify: FastifyInstance, subject: UserContext, q: ExplainQuestion, meta: { id?: string; ip?: string } = {}): Promise<ExplainResult> {
  const method = q.method.toUpperCase()
  const path = q.path
  const email = subject.email
  const steps: ExplainStep[] = []
  const subjectOut = {
    id: subject.id,
    email,
    via: subject.authVia ?? 'session',
    ...(subject.aal ? { aal: subject.aal } : {}),
    client: false,
    ...(subject.delegation ? { scopes: subject.delegation.scopes } : {}),
  }

  // ── route ──
  const found = fastify.findRoute({ method: method as 'GET', url: path })
  const params = Object.fromEntries(Object.entries(found?.params ?? {}).filter((e): e is [string, string] => typeof e[1] === 'string'))
  const pattern = found ? patternFor(method, path, params) : null
  const chain = pattern ? routeChain(method, pattern) : null
  const row = pattern ? declaredRoute(method, pattern) : null
  if (!found || !pattern || !chain) {
    steps.push({ step: 'route', verdict: 'refuse', input: { method, path }, detail: { found: Boolean(found), message: 'jinbe has no route for this method and path' } })
    return {
      subject: subjectOut,
      route: { method, path, pattern: null, params },
      verdict: { status: 404, allowed: false, message: 'Route not found' },
      decidedBy: 'route',
      steps,
      disagreements: [],
    }
  }
  const request = dryRequest({ method, path, pattern, params, config: chain.config, userContext: subject, body: q.body, ...meta })
  const asRequest = request as never
  const client = isClient(asRequest)
  subjectOut.client = client
  const permission = row?.permission
  steps.push({
    step: 'route',
    verdict: 'info',
    input: { method, path },
    detail: {
      pattern,
      params,
      class: row?.class ?? null,
      permission: permission ?? null,
      access: row?.access ?? null,
      stepUp: row?.stepUp === true,
      org: row?.org ?? null,
      guards: [
        ...chain.onRequest.map((h) => h.name || 'anonymous').filter((n) => ['requireSecondFactor', 'requireOpalClient', 'scimAuth'].includes(n)),
        ...chain.preHandler.map((h) => h.name || 'anonymous').filter((n) => n !== 'idempotencyPreHandler'),
      ],
      chainComplete: chain.complete,
    },
  })

  // ── catalogue ──
  const spec = permission && isCatalogPermission(permission) ? specOf(permission) : undefined
  steps.push({
    step: 'catalogue',
    verdict: permission ? 'info' : 'skipped',
    detail: permission
      ? {
          permission,
          inCatalogue: Boolean(spec),
          ...(spec ? { scope: spec.scope, delegable: spec.delegable, stepUp: spec.stepUp, sensitivity: spec.sensitivity } : {}),
        }
      : { message: 'The route requires no permission' },
  })

  // ── delegation ──
  if (subject.authVia === 'delegated') {
    const refusal = delegationRefusal(asRequest)
    steps.push({
      step: 'delegation',
      verdict: refusal ? 'refuse' : 'pass',
      input: { scopes: subject.delegation?.scopes ?? [], clientId: subject.delegation?.clientId ?? null },
      detail: { reason: refusal },
    })
  } else {
    steps.push({ step: 'delegation', verdict: 'skipped', detail: { message: `Not a delegated caller (${subject.authVia ?? 'session'})` } })
  }

  // ── platform ──
  const held = await attempt(() => rights(email))
  const holder = held.ok && permission && isCatalogPermission(permission) ? grants(held.value.permissions, permission) : false
  steps.push({
    step: 'platform',
    verdict: !held.ok ? 'unavailable' : holder ? 'pass' : 'info',
    input: { email, app: 'jinbe' },
    detail: held.ok ? { ...held.value, holdsRoutePermission: holder } : { error: held.error },
  })

  // ── opa ──
  const opaInput = decisionInput({ email, method, path, aal: subject.aal, client, delegation: delegationOf(asRequest) })
  const [decision, explained, simulated] = await Promise.all([
    attempt(() => queryOpa<{ allow?: boolean; reason?: string }>('rbac/decision', opaInput)),
    attempt(() => queryOpa<PolicyExplain>('rbac/explain', opaInput)),
    attempt(() => queryOpa<{ matching_rules?: RouteRule[] }>('rbac/simulate', { email, action: method, object: path, app: 'jinbe' })),
  ])
  const policy = explained.ok && explained.value && typeof explained.value === 'object' ? explained.value : null
  const opaAllow = decision.ok && decision.value ? decision.value.allow === true : null
  const opaReason = decision.ok && decision.value ? decision.value.reason ?? (decision.value.allow ? 'ok' : 'forbidden') : null
  const matching = policy?.matching_rules ?? (simulated.ok ? simulated.value?.matching_rules ?? [] : [])
  let stepUpBy = policy?.step_up_by
  if (!policy && opaReason === 'needs_2fa' && !client) {
    // No rbac.explain: say what can be said without it — whether platform 2FA applies to them.
    const platform = await attempt(() => queryOpa<boolean>('rbac/second_factor_required', { email }))
    if (platform.ok && platform.value === true) stepUpBy = ['platform_8c']
  }
  const storedRows = await attempt(async () => ((await redisRbacRepository.getRouteMap('jinbe'))?.rules ?? []).filter((r) => r.method === method && r.path === pattern))
  steps.push({
    step: 'opa',
    verdict: opaAllow === null ? 'unavailable' : opaAllow ? 'pass' : 'refuse',
    input: opaInput,
    detail: {
      allow: opaAllow,
      reason: opaReason,
      ...(decision.ok ? {} : { error: decision.error }),
      explain: policy
        ? { available: true, grantedBy: policy.granted_by, stepUpBy: policy.step_up_by, effectiveApp: policy.effective_app, secondFactorRequired: policy.second_factor_required }
        : { available: false, ...(stepUpBy ? { stepUpByInferred: stepUpBy } : {}), note: 'rbac.explain is not in the loaded policy: the clause that fired cannot be named' },
      matchingRules: matching,
      storedRouteRows: storedRows.ok ? storedRows.value : null,
    },
  })

  // ── org ──
  const org = orgOf(row, pattern, params)
  if (org) {
    const [members, byOrg, assigned, entitled] = await Promise.all([
      attempt(() => memberOrgs(email)),
      attempt(() => orgPermissionsByOrg(email)),
      attempt(async () => (subject.id ? orgRolesRepository.getForMember(org, subject.id) : [])),
      attempt(async () => (await redisRbacRepository.getOrgSites())[org] ?? []),
    ])
    steps.push({
      step: 'org',
      verdict: members.ok && byOrg.ok ? 'info' : 'unavailable',
      input: { org },
      detail: {
        org,
        member: members.ok ? members.value.includes(org) : null,
        roles: assigned.ok ? assigned.value : null,
        permissions: byOrg.ok ? byOrg.value[org] ?? [] : null,
        holdsRoutePermissionHere: byOrg.ok && permission ? (byOrg.value[org] ?? []).includes(permission) : null,
        sites: entitled.ok ? ['jinbe', ...entitled.value] : null,
      },
    })
  } else {
    steps.push({ step: 'org', verdict: 'skipped', detail: { message: 'Not an organisation route' } })
  }

  // ── guard ──
  let run: ChainVerdict
  try {
    run = await dryRunChain(chain, request)
  } catch (err) {
    run = { status: 500, decidedBy: 'explainer', guards: [], body: { error: (err as Error).message } }
  }
  const allowed = run.status < 400
  steps.push({
    step: 'guard',
    verdict: allowed ? 'pass' : 'refuse',
    detail: { status: run.status, decidedBy: run.decidedBy, guards: run.guards, ...(run.body !== undefined ? { body: run.body } : {}) },
  })

  const disagreements = findDisagreements({
    opaAllow,
    opaReason,
    guardAllowed: allowed,
    guardDecidedBy: run.decidedBy,
    policy,
    decisionFromPolicy: decision.ok ? decision.value ?? null : null,
    storedRows: storedRows.ok ? storedRows.value : null,
    matchingRules: matching,
    stepUpBy: stepUpBy ?? [],
  })

  return {
    subject: subjectOut,
    route: { method, path, pattern, params },
    verdict: {
      status: run.status,
      allowed,
      ...(bodyField(run.body, 'code') ? { code: bodyField(run.body, 'code') } : {}),
      ...(bodyField(run.body, 'reason') ? { reason: bodyField(run.body, 'reason') } : {}),
      ...(bodyField(run.body, 'message') ? { message: bodyField(run.body, 'message') } : {}),
    },
    decidedBy: run.decidedBy,
    steps,
    disagreements,
  }
}
