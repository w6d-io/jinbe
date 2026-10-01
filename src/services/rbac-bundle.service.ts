import { randomUUID } from 'node:crypto'
import { redisRbacRepository, type GroupDefinition, type FlatRolesMap, type RouteMap, type OathkeeperRule, type ImportHistoryEntry, type ImportHistoryReason } from './redis-rbac.repository.js'
import { auditEventService, type AuditActorInput, type AuditFlag } from './audit-event.service.js'
import { rbacService } from './rbac.service.js'
import { defaultServiceRoles } from './rbac-defaults.js'
import { InvalidBindingError, bindingProblems } from './group-bindings.js'
import { oathkeeperRuleSchema } from '../schemas/rbac/access-rules.schema.js'
import { isHandlerEnabled, getEnabledHandlerNames, type HandlerKind } from './oathkeeper-handlers.js'
import { findAllRouteTies, loadPublishedRouteRules, routeTieConflict } from '../policy/route-ties.js'
import { assertOrgParams } from '../policy/route-org-param.js'
import { componentLogger } from '../telemetry/logger.js'
import { assertBundleWithinOwn } from './rbac-escalation-guard.js'
import { groupGrants, loadRoles, type PermissionsByScope, type RolesByScope } from './grant-subset.js'
import { directGrantsRepository, type DirectGrant } from './direct-grants.repository.js'
import { orgRolesRepository, type OrgAssignments } from './org-roles.repository.js'
import { JINBE, isStaffGroup } from '../policy/roles.js'

export interface AuthBundle {
  version: '1'
  exportedAt: string
  rbac: {
    services: string[]
    groups: Record<string, GroupDefinition>
    roles: Record<string, FlatRolesMap>
    routeMaps: Record<string, RouteMap>
    oathkeeperRules: OathkeeperRule[]
    /** Org → the sites it is entitled to (rbac:org_sites). */
    orgSites?: Record<string, string[]>
    /** Org → identity id → org roles (rbac:org_assignments): people's org roles, backed up with the rest. */
    orgAssignments?: OrgAssignments
    /** Identity id → direct grants (rbac:direct_grants): people's per-person roles and permissions. */
    directGrants?: Record<string, DirectGrant[]>
    /** Service → org roles; service → every-org map (with the roles section). */
    orgRoles?: Record<string, FlatRolesMap>
    everyOrg?: Record<string, FlatRolesMap>
    /** A bundle exported before org entitlements: read as orgSites on import, jinbe and kuma left out. */
    orgServiceMap?: Record<string, string[]>
  }
}

export type BundleSection = 'services' | 'groups' | 'roles' | 'routeMaps' | 'oathkeeperRules' | 'orgSites' | 'orgAssignments' | 'directGrants'
export const ALL_BUNDLE_SECTIONS: BundleSection[] = ['services', 'groups', 'roles', 'routeMaps', 'oathkeeperRules', 'orgSites', 'orgAssignments', 'directGrants']

/**
 * What an import may never write: what jinbe defines in code (its roles, route map, org roles,
 * every-org map, the staff groups) — the next boot would converge it back anyway, and an import is
 * not a way around "defined in code". A bundle from before the in-place model is read too: its
 * `global` roles and `kuma` service are dropped, its org → service map becomes org entitlements.
 */
export function withoutOwned(bundle: AuthBundle): AuthBundle {
  const r = bundle.rbac
  // `global` and `kuma` were services of the previous model; neither exists now.
  const drop = (svc: string) => svc === JINBE || svc === 'global' || svc === 'kuma'
  const keep = <T>(m: Record<string, T> | undefined) => Object.fromEntries(Object.entries(m ?? {}).filter(([svc]) => !drop(svc)))
  const orgSites = r.orgSites ?? Object.fromEntries(Object.entries(r.orgServiceMap ?? {})
    .map(([org, svcs]) => [org, (Array.isArray(svcs) ? svcs : [svcs as unknown as string]).filter((svc) => !drop(svc))] as const)
    .filter(([, svcs]) => svcs.length > 0))
  return {
    ...bundle,
    rbac: {
      services: (r.services ?? []).filter((svc) => !drop(svc)),
      groups: Object.fromEntries(Object.entries(r.groups ?? {})
        .filter(([name]) => !isStaffGroup(name))
        .map(([name, def]) => [name, Object.fromEntries(Object.entries(def).filter(([svc]) => !drop(svc)))])),
      roles: keep(r.roles),
      routeMaps: keep(r.routeMaps),
      oathkeeperRules: r.oathkeeperRules ?? [],
      orgSites,
      orgAssignments: r.orgAssignments ?? {},
      directGrants: r.directGrants ?? {},
      orgRoles: keep(r.orgRoles),
      everyOrg: keep(r.everyOrg),
    },
  }
}

export interface ImportResult {
  rbac: {
    services: number
    groups: number
    roles: number
    routeMaps: number
    oathkeeperRules: number
  }
}

export interface RuleValidationFailure { id: string; reason: string }

/**
 * Fail-closed rejection of a bundle whose oathkeeperRules would break the
 * gateway. Carries the per-rule failures so the route layer can return a 400
 * body naming WHICH rules failed and why (the global error handler only
 * forwards `message`, so routes catch this class to attach `failures`).
 */
export class BundleValidationError extends Error {
  statusCode = 400
  constructor(public failures: RuleValidationFailure[]) {
    super(
      `Bundle rejected — ${failures.length} invalid oathkeeper rule(s) (nothing was written): ` +
        failures.map((f) => `${f.id}: ${f.reason}`).join('; '),
    )
  }
}

/** History list item — the entry minus its (large) bundle payload, plus counts. */
export interface ImportHistorySummary {
  id: string
  takenAt: string
  actor: string | null
  reason: ImportHistoryReason
  counts: { services: number; groups: number; roles: number; routeMaps: number; oathkeeperRules: number; orgSites: number; orgAssignments: number; directGrants: number }
}

class RbacBundleService {
  // `sections` (optional) narrows a MANUAL export/download to selected parts.
  // Omitted → full 1:1 snapshot (what the backup CronJob + restore use).
  async export(sections?: BundleSection[]): Promise<AuthBundle> {
    const [services, groups, oathkeeperRules, orgSites, orgAssignments, directGrants] = await Promise.all([
      redisRbacRepository.getServices(),
      redisRbacRepository.getGroups(),
      redisRbacRepository.getAccessRules(),
      redisRbacRepository.getOrgSites(),
      orgRolesRepository.getAll(),
      directGrantsRepository.getAll(),
    ])

    const [rolesEntries, routeMapEntries, orgRoleEntries, everyOrgEntries] = await Promise.all([
      Promise.all(services.map(async svc => [svc, await redisRbacRepository.getRoles(svc)] as const)),
      Promise.all(services.map(async svc => [svc, await redisRbacRepository.getRouteMap(svc)] as const)),
      Promise.all(services.map(async svc => [svc, await redisRbacRepository.getOrgRoles(svc)] as const)),
      Promise.all(services.map(async svc => [svc, await redisRbacRepository.getEveryOrg(svc)] as const)),
    ])
    const orgRoles = Object.fromEntries(orgRoleEntries.filter((e): e is readonly [string, FlatRolesMap] => !!e[1]))
    const everyOrg = Object.fromEntries(everyOrgEntries.filter((e): e is readonly [string, FlatRolesMap] => !!e[1]))

    const roles: Record<string, FlatRolesMap> = {}
    for (const [svc, r] of rolesEntries) {
      if (r) roles[svc] = r
    }
    const routeMaps: Record<string, RouteMap> = {}
    for (const [svc, rm] of routeMapEntries) {
      if (rm) routeMaps[svc] = rm
    }

    const fullRbac = { services, groups, roles, routeMaps, oathkeeperRules, orgSites, orgAssignments, directGrants, orgRoles, everyOrg }
    let rbac: AuthBundle['rbac'] = fullRbac
    if (sections && sections.length && sections.length < ALL_BUNDLE_SECTIONS.length) {
      const picked: Partial<typeof fullRbac> = {}
      for (const s of sections) if (s in fullRbac) (picked as Record<string, unknown>)[s] = fullRbac[s]
      if (sections.includes('roles')) Object.assign(picked, { orgRoles, everyOrg })
      rbac = picked as AuthBundle['rbac']
    }
    return { version: '1', exportedAt: new Date().toISOString(), rbac }
  }

  /**
   * Fail-closed guard mirroring the rule-CRUD path (rbac.service): every rule
   * must pass the structural schema AND reference only handlers enabled in the
   * running gateway. One malformed rule makes Oathkeeper reject the ENTIRE
   * ruleset at load → total gateway outage, so an import that would store one
   * is rejected BEFORE any Redis write. Throws BundleValidationError listing
   * every offending rule (id + reason), not just the first.
   */
  validateOathkeeperRules(rules: OathkeeperRule[]): void {
    const failures: RuleValidationFailure[] = []
    for (const [i, rule] of rules.entries()) {
      const id = typeof rule?.id === 'string' && rule.id ? rule.id : `(rule #${i})`

      // (a) structural validation — same schema as the rule CRUD routes
      const parsed = oathkeeperRuleSchema.safeParse(rule)
      if (!parsed.success) {
        const issues = parsed.error.errors.map((e) => `${e.path.join('.') || '(root)'}: ${e.message}`).join(', ')
        failures.push({ id, reason: `schema: ${issues}` })
        continue
      }

      // (b) every stage's handler must be enabled in the gateway (fail-closed,
      // same check as rbacService.assertHandlersEnabled on the CRUD path)
      const stages: Array<{ kind: HandlerKind; name: string }> = []
      for (const a of rule.authenticators ?? []) stages.push({ kind: 'authenticator', name: a.handler })
      if (rule.authorizer) stages.push({ kind: 'authorizer', name: rule.authorizer.handler })
      for (const m of rule.mutators ?? []) stages.push({ kind: 'mutator', name: m.handler })
      for (const e of rule.errors ?? []) stages.push({ kind: 'error', name: e.handler })
      for (const { kind, name } of stages) {
        if (!isHandlerEnabled(kind, name)) {
          failures.push({
            id,
            reason: `${kind} handler '${name}' is not enabled in the gateway (enabled: ${getEnabledHandlerNames(kind).join(', ') || '(none)'})`,
          })
        }
      }
    }
    if (failures.length > 0) throw new BundleValidationError(failures)
  }

  /**
   * Rejects (409, before any write) an import whose resulting route maps — what OPA would see once
   * it is applied — hold two services tied on one route at the same specificity.
   */
  private async validateRouteTies(bundle: AuthBundle, want: (s: BundleSection) => boolean, isFull: boolean): Promise<void> {
    const current = await loadPublishedRouteRules()
    const services = !want('services') ? Object.keys(current)
      : isFull ? bundle.rbac.services
      : [...new Set([...Object.keys(current), ...bundle.rbac.services])]
    const incoming = want('routeMaps') ? bundle.rbac.routeMaps ?? {} : {}
    const after = Object.fromEntries(services.map((svc) => [svc, incoming[svc]?.rules ?? current[svc] ?? []]))
    const ties = findAllRouteTies(after)
    if (ties.length > 0) throw routeTieConflict(ties)
  }

  /** Rejects (422, before any write) a group binding naming a role its service will not define. */
  private async validateBindings(bundle: AuthBundle, want: (s: BundleSection) => boolean, isFull: boolean): Promise<void> {
    const { services, groups, roles } = bundle.rbac
    const after = new Map<string, Record<string, string[]> | null>()
    for (const svc of new Set(Object.values(groups).flatMap((def) => Object.keys(def)))) {
      if (want('roles') && roles[svc]) after.set(svc, { ...defaultServiceRoles(svc), ...roles[svc] })
      else if (want('services') && services.includes(svc) && !(svc in roles)) after.set(svc, defaultServiceRoles(svc))
      else if (want('services') && isFull && svc !== JINBE && !services.includes(svc)) after.set(svc, null)
      else after.set(svc, await redisRbacRepository.getRoles(svc))
    }
    const problems = Object.entries(groups).flatMap(([name, def]) => bindingProblems(name, def, (s) => after.get(s)))
    if (problems.length > 0) throw new InvalidBindingError(problems)
  }

  /**
   * The groups whose grants this import changes, with what each grants afterwards: the groups it
   * leaves (the bundle's, over the current ones unless a full restore), resolved against the roles it
   * leaves (validateBindings' reading of the roles section, services and defaults).
   */
  private async changedGroupGrants(
    bundle: AuthBundle, want: (s: BundleSection) => boolean, isFull: boolean,
  ): Promise<Array<{ name: string; after: PermissionsByScope }>> {
    const { services, groups, roles } = bundle.rbac
    const current = await redisRbacRepository.getGroups()
    const afterGroups = want('groups') ? (isFull ? groups : { ...current, ...groups }) : current
    const scopes = new Set([...Object.values(current), ...Object.values(afterGroups)].flatMap((d) => Object.keys(d ?? {})))
    const before = await loadRoles(scopes)
    const after: RolesByScope = {}
    for (const svc of scopes) {
      if (want('roles') && roles[svc]) after[svc] = { ...defaultServiceRoles(svc), ...roles[svc] }
      else if (want('roles') && want('services') && services.includes(svc)) after[svc] = defaultServiceRoles(svc)
      else if (want('services') && isFull && svc !== JINBE && !services.includes(svc)) after[svc] = null
      else after[svc] = before[svc]
    }
    const same = (a: PermissionsByScope, b: PermissionsByScope) => JSON.stringify(Object.entries(a).sort()) === JSON.stringify(Object.entries(b).sort())
    return Object.entries(afterGroups)
      .map(([name, def]) => ({ name, after: groupGrants(def, after), before: groupGrants(current[name], before) }))
      .filter((g) => !same(g.after, g.before))
      .map(({ name, after: grants }) => ({ name, after: grants }))
  }

  async import(incoming: AuthBundle, actor?: AuditActorInput, sections?: BundleSection[], historyReason: ImportHistoryReason = 'pre-import'): Promise<ImportResult> {
    // What jinbe defines in code is never imported (withoutOwned); a pre-in-place bundle is read too.
    const bundle = withoutOwned(incoming)
    const { services, groups, roles, routeMaps, oathkeeperRules } = bundle.rbac
    // `sections` (optional) restricts a selective import to the chosen parts.
    // Full 1:1 restore (prune orphans) happens ONLY when applying the whole
    // bundle; a selective import overrides/adds the chosen sections and NEVER
    // prunes anything outside them.
    const want = (s: BundleSection) => !sections || sections.length === 0 || sections.includes(s)
    const isFull = !sections || sections.length === 0 || sections.length >= ALL_BUNDLE_SECTIONS.length

    // Fail-closed: reject the whole import BEFORE any write if a rule is
    // malformed or references a non-enabled handler (see validateOathkeeperRules).
    if (want('oathkeeperRules')) this.validateOathkeeperRules(oathkeeperRules ?? [])

    // Same refusals as a route write: an unreadable org_param, or two services tied on one route.
    if (want('routeMaps')) {
      for (const [svc, rm] of Object.entries(routeMaps ?? {})) assertOrgParams(svc, rm?.rules ?? [])
    }
    if (want('routeMaps') || want('services')) await this.validateRouteTies(bundle, want, isFull)
    // Every group binding names roles its service will define once applied (group-bindings.ts).
    if (want('groups')) await this.validateBindings(bundle, want, isFull)
    // Grant only what you hold: a non-super-admin's import changes no group beyond what they hold
    // (rbac-escalation-guard.ts). The bootstrap's own restore names no actor and is not a person.
    if (actor) await assertBundleWithinOwn(await this.changedGroupGrants(bundle, want, isFull), actor)

    // Pre-apply snapshot → rollback point. Taken AFTER validation so a rejected
    // import leaves no trace, but BEFORE any write so a partial failure (below)
    // and any later regret both have a full restore point.
    const snapshot = await this.export()
    const historyEntry: ImportHistoryEntry = {
      id: randomUUID(),
      takenAt: new Date().toISOString(),
      actor: actor?.email ?? null,
      reason: historyReason,
      bundle: snapshot,
    }
    await redisRbacRepository.pushImportHistory(historyEntry)

    // Apply with compensation: the write sequence is NOT transactional (many
    // sequential Redis writes), so a mid-way throw would leave half-applied
    // state. Best-effort restore the just-taken snapshot, then re-throw.
    let orphanServices: string[] = []
    try {
      orphanServices = await this.applyBundle(bundle, sections)
    } catch (err) {
      try {
        await this.applyBundle(snapshot)
        componentLogger('rbac-bundle').error({ err }, 'import failed mid-way — pre-import snapshot restored')
      } catch (restoreErr) {
        componentLogger('rbac-bundle').fatal({ err, restoreError: restoreErr instanceof Error ? restoreErr.message : String(restoreErr) }, 'import failed mid-way AND compensating restore failed — state may be inconsistent')
      }
      throw err
    }

    // A full restore is high-signal — flag it if any imported group binds a role named super_admin
    // (structural, no secrets in the envelope).
    const flags: AuditFlag[] = []
    const grantsSuper = Object.values(groups).some((def) => Object.values(def).some((rs) => rs.includes('super_admin')))
    if (grantsSuper) flags.push('grants_super_admin')

    auditEventService.emit({
      category: 'rbac',
      kind:     'change',
      verb:     'import',
      target:   'bundle',
      result:   'applied',
      severity: grantsSuper ? 'high' : 'warn',
      actor:    { email: actor?.email ?? null, ip: actor?.ip ?? null, name: actor?.name, ua: actor?.ua, sessionId: actor?.sessionId, ...(actor?.act ? { act: actor?.act } : {}) },
      requestId: actor?.requestId,
      reason:   `services=${services.length}`,
      changes: {
        resource: 'bundle',
        added:    want('services') ? services : [],
        removed:  orphanServices,
        flags:    flags.length ? flags : undefined,
        summary:  isFull
          ? `full restore — ${services.length} services, ${Object.keys(groups).length} groups, ${oathkeeperRules.length} rules`
          : `imported sections: ${(sections ?? []).join(', ')}`,
      },
    }).catch(() => {})

    // Propagate to OPAL/OPA immediately (the fix): etag bump + real-time push +
    // OPAL data refresh — otherwise OPA serves the pre-restore dataset until the
    // next unrelated mutation or a jinbe restart. [P2-4] Pass eventType=undefined
    // so invalidateBundle does NOT emit a second (diff-less) event — the rich
    // event above is the single audit record for the import.
    await rbacService.invalidateBundle(undefined, { type: 'bundle' }, actor)

    return {
      rbac: {
        services: services.length,
        groups: Object.keys(groups).length,
        roles: Object.keys(roles).length,
        routeMaps: Object.keys(routeMaps).length,
        oathkeeperRules: oathkeeperRules.length,
      },
    }
  }

  /**
   * The raw (non-transactional) Redis write sequence of an import — extracted
   * so import() can re-run it with the pre-import snapshot as compensation when
   * it throws mid-way. Returns the services pruned by a full restore.
   */
  private async applyBundle(bundle: AuthBundle, sections?: BundleSection[]): Promise<string[]> {
    const { services, groups, roles, routeMaps, oathkeeperRules, orgSites, orgAssignments, directGrants, orgRoles, everyOrg } = bundle.rbac
    const want = (s: BundleSection) => !sections || sections.length === 0 || sections.includes(s)
    const isFull = !sections || sections.length === 0 || sections.length >= ALL_BUNDLE_SECTIONS.length

    const existingServices = await redisRbacRepository.getServices()
    let orphanServices: string[] = []

    // ── Service registry ──
    if (want('services')) {
      await Promise.all(services.map(svc => redisRbacRepository.addService(svc)))
      if (isFull) {
        // True 1:1 restore: drop services (and their roles/routeMaps) not in the bundle.
        const bundleServices = new Set(services)
        orphanServices = existingServices.filter(svc => !bundleServices.has(svc) && svc !== JINBE)
        await Promise.all(orphanServices.map(svc => redisRbacRepository.removeService(svc)))
        await Promise.all(orphanServices.flatMap(svc => [
          redisRbacRepository.deleteRoles(svc),
          redisRbacRepository.deleteRouteMap(svc),
        ]))
      }
    }

    // ── Groups: overwrite the bundle's; prune absent ones only on a full restore ──
    if (want('groups')) {
      if (isFull) {
        const existingGroups = await redisRbacRepository.getGroups()
        for (const name of Object.keys(existingGroups)) {
          if (!(name in groups) && !isStaffGroup(name)) await redisRbacRepository.deleteGroup(name)
        }
      }
      for (const [name, def] of Object.entries(groups)) {
        await redisRbacRepository.setGroup(name, def)
      }
    }

    // ── Roles: AUTOFIX — defaults fill gaps; the bundle's definitions win. Org roles and the
    // every-org map travel with them. ──
    if (want('roles')) {
      for (const [svc, r] of Object.entries(roles)) {
        await redisRbacRepository.setRoles(svc, { ...defaultServiceRoles(svc), ...r })
      }
      for (const [svc, r] of Object.entries(orgRoles ?? {})) await redisRbacRepository.setOrgRoles(svc, r)
      for (const [svc, r] of Object.entries(everyOrg ?? {})) await redisRbacRepository.setEveryOrg(svc, r)
      // A newly-added service with no roles entry still gets defaults (only when
      // the services section was also applied, so we don't seed untouched services).
      if (want('services')) {
        for (const svc of services) {
          if (!(svc in roles)) await redisRbacRepository.setRoles(svc, defaultServiceRoles(svc))
        }
      }
    }

    if (want('routeMaps')) {
      for (const [svc, rm] of Object.entries(routeMaps)) {
        await redisRbacRepository.setRouteMap(svc, rm)
      }
    }

    if (want('oathkeeperRules')) {
      await redisRbacRepository.setAccessRules(oathkeeperRules)
    }

    if (want('orgSites')) {
      for (const [orgId, sites] of Object.entries(orgSites ?? {})) await redisRbacRepository.setOrgSites(orgId, sites)
    }

    if (want('orgAssignments')) {
      for (const [orgId, members] of Object.entries(orgAssignments ?? {})) {
        for (const [subject, orgRoleList] of Object.entries(members)) await orgRolesRepository.setForMember(orgId, subject, orgRoleList)
      }
    }

    if (want('directGrants')) {
      for (const [subject, grants] of Object.entries(directGrants ?? {})) await directGrantsRepository.restore(subject, grants)
    }

    return orphanServices
  }

  /** History entries WITHOUT their bundle payload — id/takenAt/actor/reason + per-section counts. */
  async listImportHistory(): Promise<ImportHistorySummary[]> {
    const entries = await redisRbacRepository.getImportHistory()
    return entries.map((e) => {
      const rbac = (e.bundle as AuthBundle | undefined)?.rbac
      return {
        id: e.id,
        takenAt: e.takenAt,
        actor: e.actor,
        reason: e.reason,
        counts: {
          services: rbac?.services?.length ?? 0,
          groups: Object.keys(rbac?.groups ?? {}).length,
          roles: Object.keys(rbac?.roles ?? {}).length,
          routeMaps: Object.keys(rbac?.routeMaps ?? {}).length,
          oathkeeperRules: rbac?.oathkeeperRules?.length ?? 0,
          orgSites: Object.keys(rbac?.orgSites ?? rbac?.orgServiceMap ?? {}).length,
          orgAssignments: Object.keys(rbac?.orgAssignments ?? {}).length,
          directGrants: Object.keys(rbac?.directGrants ?? {}).length,
        },
      }
    })
  }

  /**
   * Roll back to a history entry's snapshot: a full-restore import() of that
   * bundle, which itself (a) re-validates the rules fail-closed, (b) snapshots
   * the CURRENT state first (reason 'pre-rollback') so the rollback is
   * reversible, and (c) compensates on a mid-way failure.
   */
  async rollback(id: string, actor?: AuditActorInput): Promise<{ entry: Omit<ImportHistoryEntry, 'bundle'>; result: ImportResult }> {
    const entry = await redisRbacRepository.getImportHistoryEntry(id)
    if (!entry) {
      throw Object.assign(new Error(`Import history entry not found: ${id}`), { statusCode: 404 })
    }
    const result = await this.import(entry.bundle as AuthBundle, actor, undefined, 'pre-rollback')
    const { bundle: _bundle, ...meta } = entry
    return { entry: meta, result }
  }
}

export const rbacBundleService = new RbacBundleService()
