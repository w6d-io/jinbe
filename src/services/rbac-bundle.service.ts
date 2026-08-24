import { randomUUID } from 'node:crypto'
import { redisRbacRepository, type GroupDefinition, type FlatRolesMap, type RouteMap, type OathkeeperRule, type ImportHistoryEntry, type ImportHistoryReason } from './redis-rbac.repository.js'
import { auditEventService, type AuditActorInput, type AuditFlag } from './audit-event.service.js'
import { rbacService } from './rbac.service.js'
import { defaultServiceRoles } from './rbac-defaults.js'
import { oathkeeperRuleSchema } from '../schemas/rbac/access-rules.schema.js'
import { isHandlerEnabled, getEnabledHandlerNames, type HandlerKind } from './oathkeeper-handlers.js'

export interface AuthBundle {
  version: '1'
  exportedAt: string
  rbac: {
    services: string[]
    groups: Record<string, GroupDefinition>
    roles: Record<string, FlatRolesMap>
    routeMaps: Record<string, RouteMap>
    oathkeeperRules: OathkeeperRule[]
    // Org → service bundle. Exported as arrays; legacy bundles that stored a
    // scalar per org are tolerated on import (see import() below).
    orgServiceMap?: Record<string, string[]>
  }
}

export type BundleSection = 'services' | 'groups' | 'roles' | 'routeMaps' | 'oathkeeperRules' | 'orgServiceMap'
export const ALL_BUNDLE_SECTIONS: BundleSection[] = ['services', 'groups', 'roles', 'routeMaps', 'oathkeeperRules', 'orgServiceMap']

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
  counts: { services: number; groups: number; roles: number; routeMaps: number; oathkeeperRules: number; orgServiceMap: number }
}

class RbacBundleService {
  // `sections` (optional) narrows a MANUAL export/download to selected parts.
  // Omitted → full 1:1 snapshot (what the backup CronJob + restore use).
  async export(sections?: BundleSection[]): Promise<AuthBundle> {
    const [services, groups, oathkeeperRules, orgServiceMap] = await Promise.all([
      redisRbacRepository.getServices(),
      redisRbacRepository.getGroups(),
      redisRbacRepository.getAccessRules(),
      redisRbacRepository.getOrgServiceMap(),
    ])

    const allServiceKeys = [...services, 'global']
    const [rolesEntries, routeMapEntries] = await Promise.all([
      Promise.all(allServiceKeys.map(async svc => [svc, await redisRbacRepository.getRoles(svc)] as const)),
      Promise.all(services.map(async svc => [svc, await redisRbacRepository.getRouteMap(svc)] as const)),
    ])

    const roles: Record<string, FlatRolesMap> = {}
    for (const [svc, r] of rolesEntries) {
      if (r) roles[svc] = r
    }
    const routeMaps: Record<string, RouteMap> = {}
    for (const [svc, rm] of routeMapEntries) {
      if (rm) routeMaps[svc] = rm
    }

    const fullRbac = { services, groups, roles, routeMaps, oathkeeperRules, orgServiceMap }
    let rbac: AuthBundle['rbac'] = fullRbac
    if (sections && sections.length && sections.length < ALL_BUNDLE_SECTIONS.length) {
      const picked: Partial<typeof fullRbac> = {}
      for (const s of sections) if (s in fullRbac) (picked as Record<string, unknown>)[s] = fullRbac[s]
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

  async import(bundle: AuthBundle, actor?: AuditActorInput, sections?: BundleSection[], historyReason: ImportHistoryReason = 'pre-import'): Promise<ImportResult> {
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
        console.error('[rbac-bundle] import failed mid-way — pre-import snapshot restored:', err)
      } catch (restoreErr) {
        console.error('[rbac-bundle] import failed mid-way AND compensating restore failed — state may be inconsistent. Import error:', err, 'Restore error:', restoreErr)
      }
      throw err
    }

    // A full restore is high-signal — flag it if any imported group grants the
    // global super_admin role (structural, no secrets in the envelope).
    const flags: AuditFlag[] = []
    const grantsSuper = Object.values(groups).some((def) => (def.global ?? []).includes('super_admin'))
    if (grantsSuper) flags.push('grants_super_admin')

    auditEventService.emit({
      category: 'rbac',
      kind:     'change',
      verb:     'import',
      target:   'bundle',
      result:   'applied',
      severity: grantsSuper ? 'high' : 'warn',
      actor:    { email: actor?.email ?? null, ip: actor?.ip ?? null, name: actor?.name, ua: actor?.ua, sessionId: actor?.sessionId },
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
    const { services, groups, roles, routeMaps, oathkeeperRules, orgServiceMap } = bundle.rbac
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
        orphanServices = existingServices.filter(svc => !bundleServices.has(svc))
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
          if (!(name in groups)) await redisRbacRepository.deleteGroup(name)
        }
      }
      for (const [name, def] of Object.entries(groups)) {
        await redisRbacRepository.setGroup(name, def)
      }
    }

    // ── Roles: AUTOFIX — defaults fill gaps; the bundle's definitions win.
    // 'global' is not a service, so it passes through untouched. ──
    if (want('roles')) {
      for (const [svc, r] of Object.entries(roles)) {
        const merged = svc === 'global' ? r : { ...defaultServiceRoles(svc), ...r }
        await redisRbacRepository.setRoles(svc, merged)
      }
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

    if (want('orgServiceMap') && orgServiceMap && Object.keys(orgServiceMap).length > 0) {
      for (const [orgId, svcs] of Object.entries(orgServiceMap)) {
        // Tolerate a legacy bundle whose values are a scalar service name
        // (pre-migration export) as well as the current array shape.
        const mapped = Array.isArray(svcs) ? svcs : [svcs as unknown as string]
        await redisRbacRepository.setOrgServiceMapping(orgId, mapped)
      }
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
          orgServiceMap: Object.keys(rbac?.orgServiceMap ?? {}).length,
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
