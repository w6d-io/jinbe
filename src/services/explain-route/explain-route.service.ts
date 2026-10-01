import type { FastifyInstance } from 'fastify'
import { decisionInput, isSuperAdmin, manageableOrgs, memberOrgs, rights } from '../../authz/opa.js'
import { queryOpa } from '../opa-client.js'
import { ALIASES, grants, isCatalogPermission, specOf } from '../../policy/catalog.js'
import { declaredRoute, type DeclaredRoute } from '../../policy/declared-routes.js'
import { patternFor, routeChain } from '../../policy/route-guards.js'
import { delegationOf, isClient } from '../../middleware/require-service-admin.js'
import { delegationRefusal } from '../../middleware/delegation-gate.js'
import type { UserContext } from '../../middleware/identity-extractor.js'
import { redisRbacRepository, type RouteRule } from '../redis-rbac.repository.js'
import { orgGrantsRepository } from '../org-grants.repository.js'
import { orgAdminView, type OrgAdminView } from '../org-admin.js'
import { dryRequest, dryRunChain, type ChainVerdict } from './guard-dry-run.js'
import { findDisagreements, type Disagreement } from './disagreements.js'

/**
 * "Why did jinbe accept or refuse THIS call?" — the chain the request runs, each step with what it
 * read and what it answered (POST /api/admin/rbac/explain-route):
 *
 *   route       → the pattern, its declaration, the guards Fastify runs for it
 *   catalogue   → the permission's spec (delegable, step-up, the legacy names that grant it)
 *   delegation  → the delegation gate's verdict for a user through a client
 *   platform    → what the subject holds in jinbe across the platform (OPA user_info, super_admin)
 *   opa         → rbac.decision with EXACTLY the guard's input, rbac.explain (which clause fired;
 *                 optional — absent on a policy that predates it) and the matching route rows
 *   org         → for an org route: membership, the roster in Redis vs in OPA, manageable_orgs,
 *                 org grants, the org's services, and get_user_access's `admin` for it
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
  super_admin: boolean
  orgs: Array<{ org: string; member: boolean; rostered: boolean; services: string[]; org_grants: string[] }>
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
          ...(spec ? { delegable: spec.delegable, stepUp: spec.stepUp, sensitivity: spec.sensitivity } : {}),
          grantedAlsoBy: Object.entries(ALIASES).filter(([, to]) => (to as readonly string[]).includes(permission)).map(([from]) => from).sort(),
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
  const superAdmin = await attempt(() => isSuperAdmin(email))
  const holder = held.ok && permission && isCatalogPermission(permission) ? grants(held.value.permissions, permission) : false
  steps.push({
    step: 'platform',
    verdict: !held.ok ? 'unavailable' : holder || (superAdmin.ok && superAdmin.value) ? 'pass' : 'info',
    input: { email, app: 'jinbe' },
    detail: held.ok
      ? { ...held.value, superAdmin: superAdmin.ok ? superAdmin.value : null, holdsRoutePermissionGlobally: holder }
      : { error: held.error },
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
  let userAccess: OrgAdminView | null = null
  let orgAdminFamily: boolean | null = null
  let redisRostered: boolean | null = null
  let opaRostered: boolean | null = null
  if (org) {
    const [members, manageable, roster, orgGrants, services, opaRoster] = await Promise.all([
      attempt(() => memberOrgs(email)),
      attempt(() => manageableOrgs(email)),
      attempt(() => redisRbacRepository.getOrgAdmins(org)),
      attempt(() => orgGrantsRepository.getForMember(org, email)),
      attempt(async () => (await redisRbacRepository.getOrgServiceMap())[org] ?? []),
      // OPA's own copy of the roster (data.org_admin_map[org]), as OPAL delivered it.
      attempt(async () => (await queryOpa<string[]>(`org_admin_map/${encodeURIComponent(org)}`, {})) ?? []),
    ])
    const opaOrg = policy?.orgs.find((o) => o.org === org)
    // rbac.explain compares as the policy does; without it, the copy is read as the unpatched
    // policy compares (exactly).
    opaRostered = opaOrg ? opaOrg.rostered : opaRoster.ok ? opaRoster.value.includes(email) : null
    redisRostered = roster.ok ? roster.value.includes(email.toLowerCase()) : null
    if (members.ok && manageable.ok && roster.ok) {
      userAccess = orgAdminView(email, org, {
        manageable: manageable.value,
        memberOrgs: members.value,
        roster: roster.value,
        ...(opaRoster.ok ? { opaRoster: opaRoster.value } : {}),
      })
    }
    if (manageable.ok && superAdmin.ok) orgAdminFamily = superAdmin.value || holder || manageable.value.includes(org)
    steps.push({
      step: 'org',
      verdict: members.ok && manageable.ok ? 'info' : 'unavailable',
      input: { org },
      detail: {
        org,
        member: members.ok ? members.value.includes(org) : null,
        rosteredInRedis: redisRostered,
        rosteredInOpa: opaRostered,
        opaRosterSpellings: opaRoster.ok ? opaRoster.value.filter((e) => e.toLowerCase() === email.toLowerCase()) : null,
        manageable: manageable.ok ? manageable.value.includes(org) : null,
        orgGrants: orgGrants.ok ? orgGrants.value : null,
        services: services.ok ? services.value : null,
        userAccess,
        requireOrgAdminWouldAllow: orgAdminFamily,
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
    holder,
    policy,
    decisionFromPolicy: decision.ok ? decision.value ?? null : null,
    org,
    redisRostered,
    opaRostered,
    userAccess,
    orgAdminFamily,
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
