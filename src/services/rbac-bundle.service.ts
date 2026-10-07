import { forgetGroupMembers } from './group-cascade.js'
import { randomUUID } from 'node:crypto'
import { redisRbacRepository, type FlatRolesMap, type RouteMap, type ImportHistoryEntry, type ImportHistoryReason } from './redis-rbac.repository.js'
import { auditEventService, type AuditActorInput, type AuditFlag } from './audit-event.service.js'
import { rbacService } from './rbac.service.js'
import { defaultServiceRoles } from './rbac-defaults.js'
import { InvalidBindingError, bindingProblems } from './group-bindings.js'
import { findAllRouteTies, loadPublishedRouteRules, routeTieConflict } from '../policy/route-ties.js'
import { assertOrgParams } from '../policy/route-org-param.js'
import { componentLogger } from '../telemetry/logger.js'
import { assertBundleWithinOwn } from './rbac-escalation-guard.js'
import { groupGrants, loadRoles, type PermissionsByScope, type RolesByScope } from './grant-subset.js'
import { directGrantsRepository, grantKey, type DirectGrant } from './direct-grants.repository.js'
import { orgRolesRepository } from './org-roles.repository.js'
import { JINBE, isStaffGroup } from '../policy/roles.js'
import { republishAppliedSites } from '../sites/republish.js'
import { applyStores, exportStores, newProgress, orgsInSnapshot, takeBack, type ImportProgress, type StoresResult } from './bundle-stores.js'
import { BUNDLE_VERSION, bundleProblem, importNotes, isFullImport, withoutOwned, type AuthBundle, type BundleSection } from './bundle-format.js'

export { ALL_BUNDLE_SECTIONS, BUNDLE_VERSION, READABLE_VERSIONS, bundleProblem, withoutOwned, type AuthBundle, type BundleSection } from './bundle-format.js'

export interface ImportResult {
  rbac: {
    services: number
    groups: number
    roles: number
    routeMaps: number
    orgSites: number
    orgAssignments: number
    directGrants: number
  }
  /** The stores written (sections the file carried and the import asked for). */
  stores: StoresResult
  /** Every applied site published again from its applied version, after the import. */
  sites: { published: string[]; failed: Array<{ site: string; error: string }> }
  /** What the import left out, and why (gateway rules of a format-1 file, sections it lacks). */
  notes: string[]
}

/** History list item — the entry minus its (large) bundle payload, plus counts. */
export interface ImportHistorySummary {
  id: string
  takenAt: string
  actor: string | null
  reason: ImportHistoryReason
  counts: { services: number; groups: number; roles: number; routeMaps: number; orgSites: number; orgAssignments: number; directGrants: number; sites: number; organizations: number }
}

class RbacBundleService {
  // `sections` (optional) narrows a MANUAL export/download to selected parts.
  // Omitted → full 1:1 snapshot (what the scheduled backup and every restore use).
  async export(sections?: BundleSection[]): Promise<AuthBundle> {
    const [services, groups, orgSites, orgAssignments, directGrants, stores] = await Promise.all([
      redisRbacRepository.getServices(),
      redisRbacRepository.getGroups(),
      redisRbacRepository.getOrgSites(),
      orgRolesRepository.getAll(),
      directGrantsRepository.getAll(),
      exportStores(),
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

    const fullRbac = { services, groups, roles, routeMaps, orgSites, orgAssignments, directGrants, orgRoles, everyOrg, ...stores }
    let rbac: AuthBundle['rbac'] = fullRbac
    if (sections && sections.length && !isFullImport(sections)) {
      const picked: Partial<typeof fullRbac> = {}
      for (const s of sections) if (s in fullRbac) (picked as Record<string, unknown>)[s] = fullRbac[s]
      if (sections.includes('roles')) Object.assign(picked, { orgRoles, everyOrg })
      rbac = picked as AuthBundle['rbac']
    }
    return { version: BUNDLE_VERSION, exportedAt: new Date().toISOString(), rbac }
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
   * What this import asks the holding rule about (rbac.delegation, via assertBundleWithinOwn): the
   * groups it leaves (the bundle's, over the current ones unless a full restore) whose grants change,
   * the roles it leaves (validateBindings' reading of the roles section, services and defaults), and
   * every one of those roles that changes or is new.
   */
  private async holdingQuestion(
    bundle: AuthBundle, want: (s: BundleSection) => boolean, isFull: boolean,
  ): Promise<Parameters<typeof assertBundleWithinOwn>[0]> {
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
    const groupsChanged = Object.entries(afterGroups)
      .filter(([name, def]) => !same(groupGrants(def, after), groupGrants(current[name], before)))
      .map(([name, definition]) => ({ name, definition }))
    // Every changed or new role, bound or not: a role no group binds can be held directly.
    const sorted = (xs: readonly string[] = []) => JSON.stringify([...xs].sort())
    const rolesChanged: Record<string, Record<string, string[]>> = {}
    for (const [svc, map] of Object.entries(after)) {
      if (!map) continue
      const changed = Object.entries(map).filter(([role, perms]) => sorted(perms) !== sorted(before[svc]?.[role]))
      if (changed.length) rolesChanged[svc] = Object.fromEntries(changed)
    }
    const proposedRoles = Object.fromEntries(Object.entries(after).filter((e): e is [string, FlatRolesMap] => !!e[1]))
    return { roles: rolesChanged, groups: groupsChanged, proposedRoles }
  }

  async import(incoming: AuthBundle, actor?: AuditActorInput, sections?: BundleSection[], historyReason: ImportHistoryReason = 'pre-import'): Promise<ImportResult> {
    const problem = bundleProblem(incoming)
    if (problem) throw Object.assign(new Error(problem), { statusCode: 400 })
    // What jinbe defines in code is never imported (withoutOwned); a pre-in-place bundle is read too.
    const bundle = withoutOwned(incoming)
    const { services, groups, roles, routeMaps } = bundle.rbac
    // `sections` (optional) restricts a selective import to the chosen parts.
    // Full 1:1 restore (prune orphans) happens ONLY when applying the whole
    // bundle; a selective import overrides/adds the chosen sections and NEVER
    // prunes anything outside them.
    const want = (s: BundleSection) => !sections || sections.length === 0 || sections.includes(s)
    const isFull = isFullImport(sections)

    // Same refusals as a route write: an unreadable org_param, or two services tied on one route.
    if (want('routeMaps')) {
      for (const [svc, rm] of Object.entries(routeMaps ?? {})) assertOrgParams(svc, rm?.rules ?? [])
    }
    if (want('routeMaps') || want('services')) await this.validateRouteTies(bundle, want, isFull)
    // Every group binding names roles its service will define once applied (group-bindings.ts).
    if (want('groups')) await this.validateBindings(bundle, want, isFull)
    // Grant only what you hold: a non-super-admin's import changes no group beyond what they hold
    // (rbac-escalation-guard.ts). The bootstrap's own restore names no actor and is not a person.
    if (actor) await assertBundleWithinOwn(await this.holdingQuestion(bundle, want, isFull), actor)

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
    // state. Best-effort restore the just-taken snapshot (and take back the
    // sites and organization records this import added), then re-throw.
    const progress = newProgress()
    let applied: { orphanServices: string[]; stores: StoresResult }
    try {
      applied = await this.applyBundle(bundle, sections, progress)
    } catch (err) {
      try {
        await takeBack(progress)
        await this.applyBundle(snapshot, undefined, newProgress())
        componentLogger('rbac-bundle').error({ err }, 'import failed mid-way — pre-import snapshot restored')
      } catch (restoreErr) {
        componentLogger('rbac-bundle').fatal({ err, restoreError: restoreErr instanceof Error ? restoreErr.message : String(restoreErr) }, 'import failed mid-way AND compensating restore failed — state may be inconsistent')
      }
      throw err
    }

    // The import rewrote the services, groups and org entitlements the published sites live in:
    // every applied site is published again from its applied version (what its gateway rules serve),
    // so a site published after the snapshot keeps its permissions. One site failing stops no other.
    const sites = await republishAppliedSites(actor ?? { email: 'jinbe (restore)' })
      .catch((err: unknown) => ({ published: [] as string[], failed: [{ site: '*', error: (err as Error).message }] }))
    if (sites.failed.length) componentLogger('rbac-bundle').warn({ failed: sites.failed }, 'import applied, some sites could not be published again')

    const notes = importNotes(incoming, want)

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
        removed:  applied.orphanServices,
        flags:    flags.length ? flags : undefined,
        summary:  isFull
          ? `full restore — ${services.length} services, ${Object.keys(groups).length} groups, ${applied.stores.sites?.restored.length ?? 0} sites written back, ${sites.published.length} sites published again`
          : `imported sections: ${(sections ?? []).join(', ')}`,
      },
      details: { format: incoming.version, sitesFailed: sites.failed, notes },
    }).catch(() => {})

    // Propagate to OPAL/OPA immediately (the fix): etag bump + real-time push +
    // OPAL data refresh — otherwise OPA serves the pre-restore dataset until the
    // next unrelated mutation or a jinbe restart. [P2-4] Pass eventType=undefined
    // so invalidateBundle does NOT emit a second (diff-less) event — the rich
    // event above is the single audit record for the import.
    await rbacService.invalidateBundle(undefined, { type: 'bundle' }, actor)

    const r = bundle.rbac
    return {
      rbac: {
        services: services.length,
        groups: Object.keys(groups).length,
        roles: Object.keys(roles).length,
        routeMaps: Object.keys(routeMaps).length,
        orgSites: Object.keys(r.orgSites ?? {}).length,
        orgAssignments: Object.keys(r.orgAssignments ?? {}).length,
        directGrants: Object.keys(r.directGrants ?? {}).length,
      },
      stores: applied.stores,
      sites,
      notes,
    }
  }

  /**
   * The raw (non-transactional) Redis write sequence of an import — extracted
   * so import() can re-run it with the pre-import snapshot as compensation when
   * it throws mid-way. Returns the services pruned by a full restore.
   *
   * A full restore makes each section the file carries exactly the file's; a section the file lacks
   * (an older format) is left as it is. Org data (entitlements, org roles, org-scoped direct grants)
   * is restored exactly for the organizations the snapshot has, and an organization it does not have
   * is left untouched: a restore never deletes an organization (bundle-stores.ts).
   * Gateway rules are never written: built-in ones are code (bootstrap/upsert-rules.ts), site ones
   * are the published sites' Rule CRs.
   */
  private async applyBundle(bundle: AuthBundle, sections: BundleSection[] | undefined, progress: ImportProgress): Promise<{ orphanServices: string[]; stores: StoresResult }> {
    const { services, groups, roles, routeMaps, orgSites, orgAssignments, directGrants, orgRoles, everyOrg } = bundle.rbac
    const want = (s: BundleSection) => !sections || sections.length === 0 || sections.includes(s)
    const isFull = isFullImport(sections)

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
        const pruned = Object.keys(existingGroups).filter((name) => !(name in groups) && !isStaffGroup(name))
        for (const name of pruned) await redisRbacRepository.deleteGroup(name)
        // A group the snapshot does not have leaves nobody holding it (group-cascade.ts).
        await forgetGroupMembers(pruned)
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

    // The snapshot's organizations: the only ones whose org data this import touches.
    const orgs = orgsInSnapshot(bundle.rbac)
    const ours = <T>(m: Record<string, T>) => Object.entries(m).filter(([org]) => orgs.has(org))

    if (want('orgSites') && orgSites) {
      if (isFull) {
        for (const org of Object.keys(await redisRbacRepository.getOrgSites())) {
          if (orgs.has(org) && !(org in orgSites)) await redisRbacRepository.setOrgSites(org, [])
        }
      }
      for (const [orgId, sites] of ours(orgSites)) await redisRbacRepository.setOrgSites(orgId, sites)
    }

    if (want('orgAssignments') && orgAssignments) {
      if (isFull) {
        for (const [orgId, members] of ours(await orgRolesRepository.getAll())) {
          for (const subject of Object.keys(members)) {
            if (!orgAssignments[orgId]?.[subject]) await orgRolesRepository.setForMember(orgId, subject, [])
          }
        }
      }
      for (const [orgId, members] of ours(orgAssignments)) {
        for (const [subject, orgRoleList] of Object.entries(members)) await orgRolesRepository.setForMember(orgId, subject, orgRoleList)
      }
    }

    if (want('directGrants') && directGrants) {
      // Platform grants and those of the snapshot's orgs come from the file; a grant in any other org
      // is kept. A full restore makes the former exactly the file's, a sectioned one adds to them.
      const fromFile = (g: DirectGrant) => g.scope === 'platform' || orgs.has(g.scope)
      const current = await directGrantsRepository.getAll()
      for (const subject of new Set([...Object.keys(current), ...Object.keys(directGrants)])) {
        const now = current[subject] ?? []
        const file = (directGrants[subject] ?? []).filter(fromFile)
        const kept = isFull ? now.filter((g) => !fromFile(g)) : now
        const next = new Map([...kept, ...file].map((g) => [grantKey(g), g]))
        if (subject in directGrants || isFull) await directGrantsRepository.restore(subject, [...next.values()])
      }
    }

    const stores = await applyStores(bundle.rbac, want, isFull, progress, orgs)
    return { orphanServices, stores }
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
          orgSites: Object.keys(rbac?.orgSites ?? rbac?.orgServiceMap ?? {}).length,
          orgAssignments: Object.keys(rbac?.orgAssignments ?? {}).length,
          directGrants: Object.keys(rbac?.directGrants ?? {}).length,
          sites: rbac?.sites?.records?.length ?? 0,
          organizations: Object.keys(rbac?.organizations?.registry ?? {}).length,
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
