import { env } from '../config/env.js'
import { redisRbacRepository, type RouteMap } from './redis-rbac.repository.js'
import { kratosService } from './kratos.service.js'
import { auditEventService } from './audit-event.service.js'

/**
 * Impact preview — "who gains/loses access if I apply this change?"
 *
 * Before an RBAC edit (group roles, role permissions, route maps, user group
 * assignment) is saved, this evaluates a sample of access tuples
 * (email, method, path) against the CURRENT config and the PROPOSED config,
 * and returns every decision that flips.
 *
 * Evaluation runs on the REAL rego inside the live OPA instance — via
 * `POST /v1/query` with `with data.<x> as <proposed>` overrides — so the
 * preview can NEVER drift from what the gateway will actually decide. No
 * TypeScript reimplementation of the policy exists here by design.
 *
 * The tuple sample is two-source:
 *   - audit: distinct real request tuples from the recent audit stream
 *     (what people actually do today — catches surprise losses),
 *   - synthetic: affected users × declared routes of affected services
 *     (full declared surface for the entities the change touches).
 */

export interface ProposedChange {
  /** Full group-definition map AFTER the change (only changed groups needed). */
  groups?: Record<string, Record<string, string[]>>
  /** Per-service role maps AFTER the change. */
  roles?: Record<string, Record<string, string[]>>
  /** Per-service route maps AFTER the change. */
  routeMaps?: Record<string, RouteMap>
  /** Per-user group membership AFTER the change (user group assignment edits). */
  groupMembership?: Record<string, string[]>
}

export interface ImpactTuple {
  email: string
  action: string
  object: string
}

export interface ImpactFlip extends ImpactTuple {
  before: boolean
  after: boolean
}

export interface ImpactPreviewResult {
  /** allow → deny: someone loses access they have today. */
  losses: ImpactFlip[]
  /** deny → allow: someone gains access they don't have today. */
  gains: ImpactFlip[]
  unchanged: number
  sample: { audit: number; synthetic: number; total: number }
  /** OPA unreachable or policy not loaded — preview unavailable, NOT "no impact". */
  evaluated: boolean
}

interface OpaDataset {
  bindings: {
    group_membership: Record<string, string[]>
    emails: Record<string, unknown>
    groups: Record<string, Record<string, string[]>>
    // Absent map would make the rego org gate fail-closed and skew the whole
    // preview to deny — an EMPTY map means "nobody is org'd" (ungated), which
    // matches deployments that don't feed user_organizations.
    user_organizations: Record<string, string[]>
  }
  roles: Record<string, Record<string, string[]>>
  route_map: Record<string, RouteMap>
  org_service_map: Record<string, string[]>
  org_admin_map: Record<string, string[]>
}

const AUDIT_SAMPLE_LIMIT = 300
const TOTAL_SAMPLE_LIMIT = 600

export class ImpactPreviewService {
  async preview(proposed: ProposedChange): Promise<ImpactPreviewResult> {
    const current = await this.buildCurrentDataset()
    const next = this.mergeProposed(current, proposed)

    const { affectedUsers, affectedServices } = this.affectedBy(current, proposed)
    const tuples = await this.sampleTuples(current, next, affectedUsers, affectedServices)

    if (tuples.list.length === 0) {
      return { losses: [], gains: [], unchanged: 0, sample: { ...tuples.counts, total: 0 }, evaluated: true }
    }

    const [before, after] = await Promise.all([
      this.evaluate(tuples.list, current),
      this.evaluate(tuples.list, next),
    ])
    if (!before || !after) {
      return { losses: [], gains: [], unchanged: 0, sample: { ...tuples.counts, total: tuples.list.length }, evaluated: false }
    }

    const losses: ImpactFlip[] = []
    const gains: ImpactFlip[] = []
    let unchanged = 0
    for (let i = 0; i < tuples.list.length; i++) {
      const b = before[i]
      const a = after[i]
      if (b === a) { unchanged++; continue }
      const flip = { ...tuples.list[i], before: b, after: a }
      if (b && !a) losses.push(flip)
      else gains.push(flip)
    }
    return { losses, gains, unchanged, sample: { ...tuples.counts, total: tuples.list.length }, evaluated: true }
  }

  // ── Datasets ──────────────────────────────────────────────────────────────

  private async buildCurrentDataset(): Promise<OpaDataset> {
    const [rbacData, membership, orgServiceMap, orgAdminMap] = await Promise.all([
      redisRbacRepository.getAllForBundle(),
      kratosService.getAllIdentitiesWithGroups().catch(() => new Map<string, string[]>()),
      redisRbacRepository.getOrgServiceMap().catch(() => ({})),
      redisRbacRepository.getOrgAdminMap().catch(() => ({})),
    ])
    const group_membership: Record<string, string[]> = {}
    for (const [email, groups] of membership) group_membership[email] = groups
    return {
      bindings: { group_membership, emails: {}, groups: rbacData.groups, user_organizations: {} },
      roles: rbacData.roles,
      route_map: rbacData.routeMaps,
      org_service_map: orgServiceMap,
      org_admin_map: orgAdminMap,
    }
  }

  private mergeProposed(current: OpaDataset, proposed: ProposedChange): OpaDataset {
    return {
      ...current,
      bindings: {
        ...current.bindings,
        groups: { ...current.bindings.groups, ...(proposed.groups ?? {}) },
        group_membership: { ...current.bindings.group_membership, ...(proposed.groupMembership ?? {}) },
      },
      roles: { ...current.roles, ...(proposed.roles ?? {}) },
      route_map: { ...current.route_map, ...(proposed.routeMaps ?? {}) },
    }
  }

  // ── Blast-radius computation (bounds the synthetic sample) ────────────────

  private affectedBy(current: OpaDataset, proposed: ProposedChange): {
    affectedUsers: Set<string>
    affectedServices: Set<string>
  } {
    const affectedServices = new Set<string>()
    const changedGroups = new Set<string>()

    for (const [g, def] of Object.entries(proposed.groups ?? {})) {
      if (JSON.stringify(current.bindings.groups[g] ?? null) === JSON.stringify(def)) continue
      changedGroups.add(g)
      for (const svc of new Set([
        ...Object.keys(def ?? {}),
        ...Object.keys(current.bindings.groups[g] ?? {}),
      ])) affectedServices.add(svc)
    }
    for (const svc of Object.keys(proposed.roles ?? {})) affectedServices.add(svc)
    for (const svc of Object.keys(proposed.routeMaps ?? {})) affectedServices.add(svc)

    const affectedUsers = new Set<string>(Object.keys(proposed.groupMembership ?? {}))
    // Members of a changed group, plus — for membership edits — the groups the
    // user is entering/leaving don't matter: the user IS the blast radius.
    for (const [email, groups] of Object.entries(current.bindings.group_membership)) {
      if (groups.some((g) => changedGroups.has(g))) affectedUsers.add(email)
    }
    // Membership edits also touch every service reachable via old+new groups.
    for (const [email, newGroups] of Object.entries(proposed.groupMembership ?? {})) {
      for (const g of new Set([...newGroups, ...(current.bindings.group_membership[email] ?? [])])) {
        for (const svc of Object.keys(current.bindings.groups[g] ?? {})) affectedServices.add(svc)
      }
    }
    // Role-map changes affect every user whose groups reference the service.
    if (Object.keys(proposed.roles ?? {}).length > 0 || Object.keys(proposed.routeMaps ?? {}).length > 0) {
      const svcNames = new Set([...Object.keys(proposed.roles ?? {}), ...Object.keys(proposed.routeMaps ?? {})])
      for (const [email, groups] of Object.entries(current.bindings.group_membership)) {
        const reaches = groups.some((g) => {
          const def = current.bindings.groups[g] ?? {}
          return Object.keys(def).some((s) => s === 'global' || svcNames.has(s))
        })
        if (reaches) affectedUsers.add(email)
      }
    }
    affectedServices.delete('global')
    return { affectedUsers, affectedServices }
  }

  // ── Tuple sampling ────────────────────────────────────────────────────────

  private async sampleTuples(
    current: OpaDataset,
    next: OpaDataset,
    affectedUsers: Set<string>,
    affectedServices: Set<string>
  ): Promise<{ list: ImpactTuple[]; counts: { audit: number; synthetic: number } }> {
    const seen = new Set<string>()
    const list: ImpactTuple[] = []
    const push = (t: ImpactTuple) => {
      const k = `${t.email}|${t.action}|${t.object}`
      if (seen.has(k) || list.length >= TOTAL_SAMPLE_LIMIT) return
      seen.add(k)
      list.push(t)
    }

    // (a) Real traffic from the audit stream — what would actually break.
    let auditCount = 0
    try {
      const events = await auditEventService.query({ limit: AUDIT_SAMPLE_LIMIT * 4 })
      for (const e of events) {
        if (!e.who || e.who === 'anon' || !e.method || !e.path) continue
        if (auditCount >= AUDIT_SAMPLE_LIMIT) break
        const before = list.length
        push({ email: e.who, action: e.method, object: e.path.split('?')[0] })
        if (list.length > before) auditCount++
      }
    } catch { /* audit stream unavailable — synthetic sample still applies */ }

    // (b) Declared surface of the affected services × affected users.
    let syntheticCount = 0
    for (const svc of affectedServices) {
      const rules = [
        ...(current.route_map[svc]?.rules ?? []),
        ...(next.route_map[svc]?.rules ?? []),
      ]
      for (const rule of rules) {
        // Wildcards become a representative concrete path (rego :param /
        // :any* segments match any value, so one probe per pattern suffices).
        const object = rule.path.replace(/:any\*/g, 'probe').split('/')
          .map((seg) => (seg.startsWith(':') ? 'probe' : seg)).join('/')
        for (const email of affectedUsers) {
          const before = list.length
          push({ email, action: rule.method, object })
          if (list.length > before) syntheticCount++
        }
      }
    }
    return { list, counts: { audit: auditCount, synthetic: syntheticCount } }
  }

  // ── OPA evaluation (real policy, proposed data via `with` overrides) ──────

  /**
   * One /v1/query round-trip evaluates every tuple against the given dataset.
   * Returns the per-tuple allow verdicts (same order), or null when OPA is
   * unreachable / the policy is not loaded — callers must surface
   * "preview unavailable", never "no impact".
   */
  private async evaluate(tuples: ImpactTuple[], ds: OpaDataset): Promise<boolean[] | null> {
    // `tuples[_]` iteration (not `some ... in`): valid in BOTH Rego v0 and v1
    // ad-hoc queries, so this works whatever mode the deployed OPA runs in.
    //
    // The dataset is embedded as LITERALS in the query text (JSON is valid
    // Rego term syntax) — NOT referenced through `input`. Inside a
    // comprehension, `with input as t` replaces the input document BEFORE the
    // other override values are read, so a `with data.bindings as
    // input.ds.bindings` silently resolves against the overridden input
    // (undefined) and the policy evaluates with no data — every decision
    // false, and the preview would claim "no impact". Verified empirically
    // against OPA 1.x --v0-compatible; literals are immune.
    const query = [
      'rs := [r |',
      '  t := input.tuples[_];',
      '  a := data.rbac.allow',
      '    with input as t',
      `    with data.bindings as ${JSON.stringify(ds.bindings)}`,
      `    with data.roles as ${JSON.stringify(ds.roles)}`,
      `    with data.route_map as ${JSON.stringify(ds.route_map)}`,
      `    with data.org_service_map as ${JSON.stringify(ds.org_service_map)}`,
      `    with data.org_admin_map as ${JSON.stringify(ds.org_admin_map)};`,
      '  r := {"k": sprintf("%s|%s|%s", [t.email, t.action, t.object]), "allow": a}',
      ']',
    ].join('\n')
    try {
      const res = await fetch(`${env.OPA_URL}/v1/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, input: { tuples, ds } }),
      })
      if (!res.ok) return null
      const data = (await res.json()) as { result?: Array<{ rs?: Array<{ k: string; allow: boolean }> }> }
      const rs = data.result?.[0]?.rs
      if (!Array.isArray(rs) || rs.length !== tuples.length) return null
      const byKey = new Map(rs.map((r) => [r.k, !!r.allow]))
      return tuples.map((t) => byKey.get(`${t.email}|${t.action}|${t.object}`) ?? false)
    } catch {
      return null
    }
  }
}

export const impactPreviewService = new ImpactPreviewService()
