import { kratosService } from './kratos.service.js'
import { redisRbacRepository, type GroupDefinition, type FlatRolesMap, type RouteMap, type OathkeeperRule } from './redis-rbac.repository.js'
import { withRedisLock } from './redis-lock.js'
import { auditEventService } from './audit-event.service.js'
import { opaService } from './opa.service.js'
import { realtimeService } from './realtime.service.js'
import { env } from '../config/env.js'
import {
  DEFAULT_GROUP_SERVICE_ROLES,
  getUserGroups,
} from '../schemas/rbac/index.js'

// =============================================================================
// Helpers (kept for backward compatibility with controllers/tests)
// =============================================================================

export interface GroupsFile {
  groups: Record<string, GroupDefinition>
  emails: Record<string, unknown>
}

/** Directory counts for the dashboard — see rbacService.getDirectoryStats. */
export interface DirectoryStats {
  total: number
  active: number
  /** Users holding a group that grants a wildcard ('*') permission. */
  fullAccess: number
  /** Users with only the default membership (can't reach anything). */
  unassigned: number
  perGroup: Record<string, number>
  perOrg: Record<string, number>
  /** Distinct users who can reach each service via their groups. */
  perService: Record<string, number>
  computedAt: string // ISO timestamp of the walk this reflects
}

// Dynamic freshness: any mutation through jinbe busts rbac:stats immediately
// (invalidateBundle + the setUserState/create gaps), so console changes are
// reflected at once. This short window only bounds drift from changes made
// OUTSIDE jinbe (Kratos self-registration, another service): a read older than
// STATS_FRESH_MS serves the cached value at once and refreshes in the
// background, so counts converge within ~15s without ever blocking on the walk.
// The Redis key also carries a long safety TTL so counts can't go unboundedly
// stale if the process dies mid-window.
const STATS_FRESH_MS = 15_000
const STATS_TTL_S = 3_600

export function parseGroupsFile(raw: unknown): GroupsFile {
  if (!raw || typeof raw !== 'object') return { groups: {}, emails: {} }
  const obj = raw as Record<string, unknown>
  if (obj.groups && typeof obj.groups === 'object' && !Array.isArray(obj.groups)) {
    return { groups: obj.groups as Record<string, GroupDefinition>, emails: (obj.emails as Record<string, unknown>) || {} }
  }
  const groups: Record<string, GroupDefinition> = {}
  for (const [key, value] of Object.entries(obj)) {
    if (key === 'emails') continue
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      groups[key] = value as GroupDefinition
    }
  }
  return { groups, emails: (obj.emails as Record<string, unknown>) || {} }
}

export function parseRolesContent(raw: unknown): Array<{ name: string; permissions: string[]; description?: string; inherits?: string[] }> {
  if (!raw || typeof raw !== 'object') return []
  const obj = raw as Record<string, unknown>
  if (Array.isArray(obj.roles)) {
    return obj.roles as Array<{ name: string; permissions: string[]; description?: string; inherits?: string[] }>
  }
  const roles: Array<{ name: string; permissions: string[] }> = []
  for (const [key, value] of Object.entries(obj)) {
    if (key === 'version' || key === 'service') continue
    if (Array.isArray(value)) roles.push({ name: key, permissions: value as string[] })
  }
  return roles
}

// =============================================================================
// Types
// =============================================================================

export interface UserWithGroups {
  email: string
  name?: string
  groupMembership: Record<string, boolean>
  /** Identity has at least one second factor (TOTP, WebAuthn, lookup_secret). */
  mfa?: boolean
  /** Underlying Kratos identity id — needed for client-side MFA enrollment links. */
  identityId?: string
}

export interface GroupInfo {
  name: string
  services: GroupDefinition
  /** True when this group is bootstrap-protected (cannot be deleted, may need super_admin to mutate). */
  system?: boolean
  description?: string
}

export interface UsersResponse {
  users: UserWithGroups[]
}

export interface GroupsResponse {
  groups: GroupInfo[]
}

export interface ServiceInfo {
  name: string
  rolesCount: number
  routesCount: number
  /** True when this service is bootstrap-protected (cannot be deleted). */
  system?: boolean
  description?: string
}

export interface ServicesResponse {
  services: ServiceInfo[]
}

export interface CreateServiceOptions {
  name: string
  displayName?: string
  upstreamUrl?: string
  matchUrl?: string
  matchMethods?: string[]
  stripPath?: string
}

export interface UpdateServiceOptions {
  upstreamUrl?: string
  matchUrl?: string
  matchMethods?: string[]
  stripPath?: string | null  // null = remove strip_path
}

export interface AccessRulesResponse {
  rules: OathkeeperRule[]
}

export interface MutationResult {
  success: boolean
  message: string
  timestamp: string
}

export interface KratosBindingsResponse {
  emails: Record<string, unknown>
  group_membership: Record<string, string[]>
  /** email → organizations[] (multi-org membership from metadata_admin.organizations). */
  user_organizations: Record<string, string[]>
  /** email → primary org id (legacy single-org, from the native organization_id). */
  user_organization_primary: Record<string, string>
}

// Re-export types from repository for convenience
export type { GroupDefinition, FlatRolesMap, RouteMap, OathkeeperRule }

// =============================================================================
// System-protected resources — gated by RBAC, not hardcoded
// =============================================================================

/**
 * Thrown when a regular admin tries to mutate a `system: true` group/service
 * without holding the global super_admin role. The check is *data-driven*:
 * group/service metadata stored in Redis (`rbac:groups:meta`,
 * `rbac:services:meta`) flags resources as system, and the actor's effective
 * role is queried via OPA — same code path as request-time authorization, so
 * there is no hardcoded list inside this service file.
 */
export class SystemResourceImmutable extends Error {
  statusCode = 403
  constructor(kind: string, name: string) {
    super(`Refusing to mutate system ${kind} '${name}' — only super_admins may modify system resources`)
    this.name = 'SystemResourceImmutable'
  }
}

// =============================================================================
// RBAC Service — Redis-backed
// =============================================================================

export class RbacService {
  // ===========================================================================
  // Private Helpers
  // ===========================================================================

  private result(message: string): MutationResult {
    return { success: true, message, timestamp: new Date().toISOString() }
  }

  /**
   * Privilege escalation guard: refuses the mutation unless the actor holds
   * a global wildcard role (super_admin). Lookup goes through OPA so the
   * decision matches request-time authorization exactly.
   */
  private async requireSuperAdmin(reason: string, actor?: { email?: string }): Promise<void> {
    if (!actor?.email) {
      throw Object.assign(new Error('Authentication required for this operation'), { statusCode: 401 })
    }
    const result = await opaService.simulate(actor.email, 'jinbe', 'POST', '/api/admin/rbac/groups')
    if (!result?.super_admin) {
      throw Object.assign(
        new Error(`Only super_admins may ${reason}`),
        { statusCode: 403 },
      )
    }
  }

  /**
   * Non-throwing global super_admin check (same OPA signal as requireSuperAdmin:
   * a global role resolving to "*"). Used where super_admin status changes the
   * RESPONSE rather than gating a mutation — e.g. /me/organizations returns ALL
   * mapped orgs to a super_admin instead of just their membership.
   *
   * FAIL-CLOSED: returns false on missing email or any OPA error, so an
   * unreachable OPA never widens visibility.
   */
  async isSuperAdmin(actor: { email?: string }): Promise<boolean> {
    if (!actor?.email) return false
    try {
      const result = await opaService.simulate(actor.email, 'jinbe', 'POST', '/api/admin/rbac/groups')
      return result?.super_admin === true
    } catch {
      return false
    }
  }

  /**
   * Returns true when the resource is flagged `system: true` in its
   * metadata. Used by mutation methods to decide whether the operation
   * needs super_admin authority instead of plain rbac:write.
   */
  private async isSystemGroup(name: string): Promise<boolean> {
    const meta = await redisRbacRepository.getGroupMetadata(name)
    return meta?.system === true
  }

  private async isSystemService(name: string): Promise<boolean> {
    const meta = await redisRbacRepository.getServiceMetadata(name)
    return meta?.system === true
  }

  /**
   * Returns true when membership of `groupName` grants either the global
   * super_admin role or a service-scoped admin role (i.e. holds the
   * wildcard "*"). Such groups are considered "privileged" — adding a
   * user to one of them is a privilege-escalation operation, so we
   * gate it on the target identity having a second factor configured.
   */
  /**
   * Public wrapper for the admin-power check — used by the user-group
   * assignment endpoint to refuse privilege escalation by non-super_admin
   * actors. Mirrors the private helper used by the MFA gate.
   */
  async isAdminPowerGroup(groupName: string): Promise<boolean> {
    return this.groupGrantsAdminPower(groupName)
  }

  /**
   * Public wrapper exposing the super_admin authority check used internally
   * by mutation guards. Throws 403 if the actor is not a super_admin.
   */
  async assertSuperAdmin(reason: string, actor?: { email?: string }): Promise<void> {
    return this.requireSuperAdmin(reason, actor)
  }

  /**
   * Public: returns true iff membership of `groupName` grants GLOBAL admin
   * power — the literal global `super_admin` role, or a global role that
   * resolves to the wildcard "*" permission. Strictly narrower than
   * groupGrantsAdminPower, which ALSO returns true for a merely service-scoped
   * wildcard role.
   *
   * The user-group assignment gate uses this as a hard backstop (finding J1):
   * a global group must require the actor to BE a super_admin, so an
   * org-scoped ("*"-in-org) admin cannot cross the tenant boundary and mint a
   * global super_admin.
   *
   * Fail-closed: only affirmative global signals return true. A missing group
   * returns false — and in the assignment flow that group never reaches the
   * gate, because it would not have registered as admin-power in the first
   * place. A Redis failure THROWS (getGroup/getRoles reject) rather than
   * silently returning false, so it surfaces as a request-level deny, never a
   * bypass.
   */
  async groupGrantsGlobalPower(groupName: string): Promise<boolean> {
    const def = await redisRbacRepository.getGroup(groupName)
    if (!def) return false
    return this.defGrantsGlobalPower(def)
  }

  /**
   * True iff the group confers NO roles in any service (an empty definition,
   * e.g. the reserved base `users` group `{}`). Lets a demotion to the base
   * group skip the delegation gate WITHOUT trusting the group NAME: if a
   * privileged actor ever redefined the base group to bind real roles this
   * returns false, so the grant is re-subjected to can_grant rather than waved
   * through. A missing group confers nothing → true.
   */
  async isEmptyGroup(groupName: string): Promise<boolean> {
    const def = await redisRbacRepository.getGroup(groupName)
    if (!def) return true
    return !Object.values(def).some((roles) => Array.isArray(roles) && roles.length > 0)
  }

  /**
   * Shared "does this group definition grant GLOBAL power" predicate. Reused
   * by both groupGrantsGlobalPower (the public assignment gate) and
   * groupGrantsAdminPower (the MFA / admin-power gate) so the notion of
   * "global" cannot drift between them.
   */
  private async defGrantsGlobalPower(def: GroupDefinition): Promise<boolean> {
    const globalRoles = def.global ?? []
    if (globalRoles.length === 0) return false
    // The literal global super_admin role is the absolute trigger.
    if (globalRoles.includes('super_admin')) return true
    // Otherwise resolve the named global roles against the global roles map;
    // any wildcard permission is global admin power.
    const allGlobalRoles = await redisRbacRepository.getRoles('global')
    if (!allGlobalRoles) return false
    for (const role of globalRoles) {
      if ((allGlobalRoles[role] ?? []).includes('*')) return true
    }
    return false
  }

  private async groupGrantsAdminPower(groupName: string): Promise<boolean> {
    const def = await redisRbacRepository.getGroup(groupName)
    if (!def) return false

    // Global power (super_admin, or a global role resolving to "*") is the
    // absolute trigger — reuse the shared predicate so it stays in lock-step
    // with groupGrantsGlobalPower.
    if (await this.defGrantsGlobalPower(def)) return true

    // For each service the group binds, check whether any of its roles
    // resolves to a wildcard permission (admin role typically has "*").
    for (const [svc, roles] of Object.entries(def)) {
      if (svc === 'global' || !roles?.length) continue
      const allRoles = await redisRbacRepository.getRoles(svc)
      if (!allRoles) continue
      for (const role of roles) {
        const perms = allRoles[role] ?? []
        if (perms.includes('*')) return true
      }
    }
    return false
  }

  /**
   * Iterates `candidateGroups`; for each one that grants admin power AND
   * is system-protected, returns the first group name that the target
   * identity cannot currently join because they have no second factor.
   * Returns null if no such gate trips.
   *
   * Used by the user-group assignment endpoint to refuse one-click
   * elevation of a user without MFA — required for SOC2-style controls.
   */
  async findPrivilegedGroupRequiringMFA(
    candidateGroups: string[],
    targetIdentityId: string,
  ): Promise<string | null> {
    let mfaCheckResult: boolean | null = null

    for (const groupName of candidateGroups) {
      const isSystem = await this.isSystemGroup(groupName)
      if (!isSystem) continue
      const grantsAdmin = await this.groupGrantsAdminPower(groupName)
      if (!grantsAdmin) continue

      // Lazy-load MFA check — only pay the Kratos round-trip if at least
      // one candidate group qualifies as privileged.
      if (mfaCheckResult === null) {
        try {
          mfaCheckResult = await kratosService.hasMFA(targetIdentityId)
        } catch {
          // Treat lookup failure as "no MFA" — fail closed for safety.
          mfaCheckResult = false
        }
      }
      if (!mfaCheckResult) return groupName
    }
    return null
  }

  // Public: call after any user-group mutation that bypasses rbacService methods
  async notifyBindingsChanged(reason: string, actor?: { email?: string; ip?: string }): Promise<void> {
    await this.invalidateBundle(`user.${reason}`, { type: 'user' }, actor)
  }

  private async invalidateBundle(eventType?: string, target?: { type?: string; id?: string; service?: string }, actor?: { email?: string; ip?: string }): Promise<void> {
    await redisRbacRepository.invalidateBundleEtag()

    // Directory counts (total/active/perGroup/perOrg) may have moved — drop the
    // stats cache so the next dashboard read recomputes. Best-effort; covers
    // every mutation flowing through here (groups/services/org-map + all
    // notifyBindingsChanged user mutations).
    redisRbacRepository.invalidateStats().catch(() => {})
    // Push a real-time signal so connected admin browsers refetch at once.
    realtimeService.publish(eventType ?? 'rbac')

    // Notify OPAL server for real-time WebSocket push to all OPA clients (<100ms)
    this.notifyOpal(eventType).catch(() => {})

    if (eventType) {
      auditEventService.emit({ type: eventType, target, actor, source: 'jinbe-api' }).catch(() => {})
    }
  }

  /**
   * Push a full datasource refresh to opal-server, covering bindings,
   * groups, plus per-service roles + route_map. Mirrors the entries returned
   * by GET /api/admin/rbac/opal-datasource so opal-server has no excuse for
   * a stale dataset.
   *
   * Called from server.ts post-waitForBootstrap so that even if opal-server
   * booted first and got a 503 on its initial fetch, this push refills OPA's
   * dataset within seconds — without requiring an opal-server pod restart.
   */
  async refreshAllDataSources(reason: string = 'jinbe-startup'): Promise<void> {
    try {
      const jinbeUrl = env.JINBE_INTERNAL_URL
      const services = await redisRbacRepository.getServices()

      const entries = [
        { url: `${jinbeUrl}/api/admin/rbac/bindings`, topics: ['policy_data'], dst_path: '/bindings' },
        { url: `${jinbeUrl}/api/admin/rbac/opal/groups`, topics: ['policy_data'], dst_path: '/bindings/groups' },
        // Global roles are always part of OPA's dataset even though "global"
        // is not in the services registry (getServices()), so the loop below
        // never emits it. Push it explicitly, matching GET /opal-datasource:
        // data.roles.global holds the platform-wide "*" wildcard the
        // super_admin role resolves to. If a dataset is ever rebuilt solely
        // from a push (e.g. opal-client's initial pull 503s and this refresh
        // back-fills the store), omitting it would drop the wildcard and 403
        // every privileged operation with no recovery path.
        { url: `${jinbeUrl}/api/admin/rbac/opal/roles/global`, topics: ['policy_data'], dst_path: '/roles/global' },
        // Keep in lock-step with GET /opal-datasource so an org_service_map
        // mutation re-publishes data.org_service_map to OPA (else it goes stale).
        { url: `${jinbeUrl}/api/admin/rbac/opal/org_service_map`, topics: ['policy_data'], dst_path: '/org_service_map' },
      ]
      for (const svc of services) {
        entries.push({ url: `${jinbeUrl}/api/admin/rbac/opal/roles/${svc}`, topics: ['policy_data'], dst_path: `/roles/${svc}` })
        const routeMap = await redisRbacRepository.getRouteMap(svc)
        if (routeMap) {
          entries.push({ url: `${jinbeUrl}/api/admin/rbac/opal/route_map/${svc}`, topics: ['policy_data'], dst_path: `/route_map/${svc}` })
        }
      }

      const res = await fetch(`${env.OPAL_SERVER_URL}/data/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entries, reason }),
      })
      if (!res.ok) throw new Error(`opal-server ${res.status}`)
      console.log(`[opal-refresh] ${entries.length} entries pushed (${reason})`)
    } catch (err) {
      console.error('[opal-refresh] Failed:', err)
      throw err
    }
  }

  private async notifyOpal(reason?: string): Promise<void> {
    // Delegate to refreshAllDataSources so every mutation re-publishes
    // the full entries list (/bindings, /bindings/groups, /roles/{svc}
    // AND /route_map/{svc} for every service). The slim previous
    // payload pushed only /bindings + /bindings/groups, which meant
    // adding or editing a route_map entry never propagated to OPA —
    // OPA only picked it up after an opal-client restart pulled all
    // sources at boot. Over-publishing is cheap (OPAL clients
    // re-fetch the same URLs they already know) and the alternative
    // (per-mutation entry mapping) is brittle: every new RBAC path
    // would need a matching publish call somewhere.
    try {
      await this.refreshAllDataSources(reason || 'rbac-mutation')
    } catch (err) {
      console.error('[opal-notify] Failed:', err)
    }
  }

  private async notifyOpalRoles(serviceName: string): Promise<void> {
    // Same reasoning as notifyOpal — full refresh keeps OPA's view in
    // sync without per-path bookkeeping. serviceName is preserved in
    // the reason string for traceability in OPAL server logs.
    try {
      await this.refreshAllDataSources(`roles.updated.${serviceName}`)
    } catch (err) {
      console.error('[opal-notify-roles] Failed:', err)
    }
  }

  // ===========================================================================
  // Users & Bindings
  // ===========================================================================

  async getUsers(): Promise<UsersResponse> {
    const bindings = await this.getBindingsFromKratos()
    const groups = await redisRbacRepository.getGroups()
    const groupNames = Object.keys(groups)

    const users: UserWithGroups[] = []

    for (const [email, membership] of Object.entries(bindings.group_membership)) {
      const userGroups = getUserGroups(membership)
      const groupMembership: Record<string, boolean> = {}
      for (const groupName of groupNames) {
        groupMembership[groupName] = userGroups.includes(groupName)
      }
      users.push({ email, groupMembership })
    }

    // Enrich with names + identity ids from Kratos. The credentials
    // payload (TOTP / WebAuthn / lookup_secret) is only present if the
    // request includes ?include_credential=…; we still surface mfa when
    // it is, so kuma can disable admin-group assignment on un-enrolled
    // users without an extra round trip per user.
    try {
      const kratosResponse = await kratosService.listIdentities(250, undefined, undefined, ['totp', 'webauthn', 'lookup_secret'])
      const byEmail = new Map(kratosResponse.identities.map((u) => [u.traits.email as string, u]))
      for (const user of users) {
        const ident = byEmail.get(user.email)
        if (!ident) continue
        user.name = ident.traits.name || undefined
        user.identityId = ident.id
        const creds = (ident.credentials ?? {}) as Record<string, unknown>
        // mfa = true only when a real factor is ENROLLED. Absence of
        // `credentials` (listIdentities called without include_credential)
        // leaves mfa unset rather than defaulting to false — the UI decides
        // whether to fail closed. Use the shared enrolment-artefact check so
        // this agrees with the authoritative hasMFA(); key presence alone
        // (esp. Kratos's auto-created empty webauthn) is a false positive.
        if (Object.keys(creds).length > 0) {
          user.mfa = kratosService.mfaFromCredentials(creds)
        }
      }
    } catch { /* Kratos unavailable */ }

    return { users }
  }

  // ===========================================================================
  // Directory stats (dashboard counts)
  // ===========================================================================
  //
  // Derived from the LIGHT, no-credential identity walk
  // (kratosService.getAllIdentitiesWithBindings) — it never pays the per-row
  // credential + RBAC enrichment that makes the enriched directory scan slow
  // (~45s at 9k identities). Cached in Redis `rbac:stats` and served
  // stale-while-revalidate: a request returns the last computed value at once
  // and refreshes in the background when it's older than STATS_FRESH_MS, so no
  // request ever blocks on the walk. A single-flight guard collapses concurrent
  // refreshes into one walk (no thundering herd on a cold cache). MFA is
  // intentionally excluded — counting it needs credential expansion, which
  // would tax the shared OPAL bindings feed; add it later behind its own field.

  private statsRefresh: Promise<DirectoryStats> | null = null
  // Monotonic generation counter, bumped by every invalidateDirectoryStats().
  // A background refresh captures it at the start and only publishes its result
  // if it's unchanged at the end — otherwise the refresh read its bindings
  // pre-image BEFORE a mutation invalidated the cache, and writing it would pin
  // stale counts stamped "fresh" for STATS_FRESH_MS. See audit finding #10.
  private statsEpoch = 0

  /** Group names that grant a wildcard ('*') permission — a global super_admin
   *  role, or any (service, role) whose permission set includes '*'. Used to
   *  count full-access users in the stats walk. */
  private async wildcardGroupNames(): Promise<Set<string>> {
    const groups = await redisRbacRepository.getGroups()
    const services = new Set<string>()
    for (const def of Object.values(groups)) {
      for (const svc of Object.keys(def)) services.add(svc)
    }
    const rolesByService: Record<string, FlatRolesMap> = {}
    await Promise.all(
      [...services].map(async (svc) => {
        rolesByService[svc] = (await redisRbacRepository.getRoles(svc)) ?? {}
      }),
    )
    const wild = new Set<string>()
    for (const [name, def] of Object.entries(groups)) {
      const isWild = Object.entries(def).some(([svc, roles]) =>
        roles.some(
          (r) =>
            (svc === 'global' && r === 'super_admin') ||
            (rolesByService[svc]?.[r] ?? []).includes('*'),
        ),
      )
      if (isWild) wild.add(name)
    }
    return wild
  }

  async getDirectoryStats(): Promise<DirectoryStats> {
    let cached: { computedAt: number; stats: DirectoryStats } | null = null
    try {
      const raw = await redisRbacRepository.getStats()
      if (raw) cached = JSON.parse(raw)
    } catch { /* redis blip — fall through to compute */ }

    if (cached) {
      if (Date.now() - cached.computedAt >= STATS_FRESH_MS) {
        // Stale → refresh in the background; serve the stale value now.
        void this.refreshDirectoryStats().catch(() => {})
      }
      return cached.stats
    }
    // Cold cache: compute once (single-flight). Only this request waits, and on
    // the light walk that's seconds, not the ~45s enriched scan.
    return this.refreshDirectoryStats()
  }

  private refreshDirectoryStats(): Promise<DirectoryStats> {
    if (this.statsRefresh) return this.statsRefresh
    // Capture the generation before we start reading. If an invalidation bumps
    // it while we compute, our bindings pre-image is stale and we must NOT cache.
    const startEpoch = this.statsEpoch
    const p = (async (): Promise<DirectoryStats> => {
      const [bindings, wildGroups, groupDefs] = await Promise.all([
        kratosService.getAllIdentitiesWithBindings(),
        this.wildcardGroupNames(),
        redisRbacRepository.getGroups(),
      ])
      // group → the services it grants roles on (for per-service reach counts)
      const groupServices: Record<string, string[]> = {}
      for (const [g, def] of Object.entries(groupDefs)) groupServices[g] = Object.keys(def)

      let active = 0
      let fullAccess = 0
      let unassigned = 0
      const perGroup: Record<string, number> = {}
      const perOrg: Record<string, number> = {}
      const perService: Record<string, number> = {}
      for (const b of bindings.values()) {
        if (b.active) active++
        // Raw metadata group names (may include orphans not in rbac:groups).
        // The UI reads only the groups it knows, so reporting raw keys is safe.
        for (const g of b.groups) perGroup[g] = (perGroup[g] ?? 0) + 1
        if (b.primaryOrganization) perOrg[b.primaryOrganization] = (perOrg[b.primaryOrganization] ?? 0) + 1
        // Only the default 'users' membership → can't reach anything.
        if (b.groups.every((g) => g === 'users')) unassigned++
        if (b.groups.some((g) => wildGroups.has(g))) fullAccess++
        // Distinct services this user can reach via their groups.
        const svcs = new Set<string>()
        for (const g of b.groups) for (const s of groupServices[g] ?? []) svcs.add(s)
        for (const s of svcs) perService[s] = (perService[s] ?? 0) + 1
      }
      const stats: DirectoryStats = {
        total: bindings.size,
        active,
        fullAccess,
        unassigned,
        perGroup,
        perOrg,
        perService,
        computedAt: new Date().toISOString(),
      }
      // Only publish if no invalidation happened while we computed. If the epoch
      // moved, a mutation invalidated the cache after we read our (now stale)
      // bindings pre-image; caching would pin those stale counts as "fresh".
      // Skip the write and let the next read recompute from fresh state — the
      // caller still gets these stats, we just don't persist them.
      if (this.statsEpoch === startEpoch) {
        try {
          await redisRbacRepository.setStats(JSON.stringify({ computedAt: Date.now(), stats }), STATS_TTL_S)
        } catch { /* best-effort cache write */ }
      }
      return stats
    })()
    this.statsRefresh = p
    p.finally(() => { if (this.statsRefresh === p) this.statsRefresh = null })
    return p
  }

  /** Bust the directory-stats cache (counts changed). Next read recomputes
   *  from the light walk. Best-effort; safe to call from any mutation path. */
  async invalidateDirectoryStats(): Promise<void> {
    // Bump the generation FIRST so any in-flight background refresh that already
    // read a pre-mutation bindings snapshot will decline to cache its result
    // (finding #10). Do this before the deletes so there's no window where a
    // refresh could re-populate the key we're about to clear.
    this.statsEpoch++
    // Also drop the 5s identity-bindings cache so the immediate recompute reads
    // fresh counts — createUser-without-groups and setUserState reach here but
    // bypass the binding-cache invalidation their sibling mutation paths get.
    kratosService.invalidateGroupsCache()
    await redisRbacRepository.invalidateStats().catch(() => {})
    realtimeService.publish('directory')
  }

  // ===========================================================================
  // Groups
  // ===========================================================================

  async getGroups(): Promise<GroupsResponse> {
    const [groups, allMeta] = await Promise.all([
      redisRbacRepository.getGroups(),
      redisRbacRepository.getAllGroupMetadata(),
    ])
    const groupsInfo: GroupInfo[] = Object.entries(groups).map(([name, services]) => {
      const meta = allMeta[name]
      return {
        name,
        services,
        ...(meta?.system ? { system: true } : {}),
        ...(meta?.description ? { description: meta.description } : {}),
      }
    })
    return { groups: groupsInfo }
  }

  async createGroup(name: string, services: GroupDefinition, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    if (await redisRbacRepository.groupExists(name)) {
      throw Object.assign(new Error(`Group already exists: ${name}`), { statusCode: 409 })
    }
    // Block creating a group that grants the global super_admin role unless
    // the actor is themselves a super_admin.
    const grantsSuperAdmin = (services.global ?? []).includes('super_admin')
    if (grantsSuperAdmin) {
      await this.requireSuperAdmin('create a group with the super_admin role', actor)
    }
    await redisRbacRepository.setGroup(name, services)
    await this.invalidateBundle('rbac.group_created', { type: 'group', id: name }, actor)
    return this.result(`Group '${name}' created`)
  }

  async updateGroup(name: string, services: GroupDefinition, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    if (!(await redisRbacRepository.groupExists(name))) {
      throw Object.assign(new Error(`Group not found: ${name}`), { statusCode: 404 })
    }
    // Privilege escalation guard: editing super_admins (the wildcard group)
    // requires the caller to already be a super_admin themselves.
    if (name === 'super_admins') {
      await this.requireSuperAdmin(`modify the 'super_admins' group`, actor)
    }
    // PUT semantics: full replace. Earlier behavior merged the incoming
    // services map with the existing one, which silently dropped the
    // operator's intent when they unchecked every role for a service —
    // the API returned 200 but nothing changed in Redis. Replacing
    // matches the REST PUT contract and what kuma's UI implies.
    await redisRbacRepository.setGroup(name, services)
    await this.invalidateBundle('rbac.group_updated', { type: 'group', id: name }, actor)
    return this.result(`Group '${name}' updated`)
  }

  async deleteGroup(name: string, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    if (!(await redisRbacRepository.groupExists(name))) {
      throw Object.assign(new Error(`Group not found: ${name}`), { statusCode: 404 })
    }
    if (await this.isSystemGroup(name)) {
      // System groups are never deletable — even by super_admins. Removing
      // super_admins leaves the cluster with no path back to global admin.
      throw new SystemResourceImmutable('group', name)
    }
    await redisRbacRepository.deleteGroup(name)
    await redisRbacRepository.deleteGroupMetadata(name)

    // Cascade: remove group from all Kratos users
    try {
      const usersUpdated = await kratosService.removeGroupFromAllUsers(name)
      if (usersUpdated > 0) {
        console.log(`[rbac] Removed group '${name}' from ${usersUpdated} Kratos users`)
      }
    } catch (error) {
      console.error(`[rbac] Failed to remove group '${name}' from Kratos users:`, error)
    }

    await this.invalidateBundle('rbac.group_deleted', { type: 'group', id: name }, actor)
    return this.result(`Group '${name}' deleted`)
  }

  // ===========================================================================
  // Group Validation
  // ===========================================================================

  async getAvailableGroups(): Promise<string[]> {
    const groups = await redisRbacRepository.getGroups()
    return Object.keys(groups)
  }

  async validateGroups(groups: string[]): Promise<void> {
    const available = await this.getAvailableGroups()
    const invalid = groups.filter(g => !available.includes(g))
    if (invalid.length > 0) {
      throw new Error(`Invalid groups: ${invalid.join(', ')}. Available: ${available.join(', ')}`)
    }
  }

  // ===========================================================================
  // Services
  // ===========================================================================

  async getServices(): Promise<ServicesResponse> {
    const [serviceNames, allMeta] = await Promise.all([
      redisRbacRepository.getServices(),
      redisRbacRepository.getAllServiceMetadata(),
    ])
    const services: ServiceInfo[] = []

    for (const name of serviceNames) {
      const roles = await redisRbacRepository.getRoles(name)
      const routeMap = await redisRbacRepository.getRouteMap(name)
      const meta = allMeta[name]
      services.push({
        name,
        rolesCount: roles ? Object.keys(roles).length : 0,
        routesCount: routeMap?.rules?.length || 0,
        ...(meta?.system ? { system: true } : {}),
        ...(meta?.description ? { description: meta.description } : {}),
      })
    }

    return { services }
  }

  async createService(options: CreateServiceOptions, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    const { name } = options

    if (await redisRbacRepository.serviceExists(name)) {
      throw Object.assign(new Error(`Service already exists: ${name}`), { statusCode: 409 })
    }

    const namespace = env.SERVICE_DEFAULT_NAMESPACE
    const domain = env.SERVICE_DEFAULT_DOMAIN
    const port = env.SERVICE_DEFAULT_PORT

    const upstreamUrl = options.upstreamUrl || `http://${name}.${namespace}:${port}`
    const isDefaultPath = !options.matchUrl
    const matchUrl = options.matchUrl || `https://${domain}/api/${name}/<**>`
    const matchMethods = options.matchMethods || ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    const stripPath = options.stripPath

    // 1. Create default roles
    const defaultRoles: FlatRolesMap = {
      admin: ['*'],
      operator: [`${name}:list`, `${name}:read`, `${name}:create`, `${name}:update`, `${name}:delete`, `${name}:execute`],
      editor: [`${name}:list`, `${name}:read`, `${name}:create`, `${name}:update`],
      viewer: [`${name}:list`, `${name}:read`],
    }

    // 2. Create default route map with health endpoint
    const defaultRouteMap: RouteMap = {
      rules: [{ method: 'GET', path: `/api/${name}/health` }],
    }

    // 3. Create Oathkeeper rules
    // Per-rule authorizer config overrides the global one — sets app to this service name
    // so OPA evaluates RBAC against this service's roles/routes, not the global jinbe config
    const groupsTemplate = `{{ $ma := index .Extra.identity "metadata_admin" }}{{ if $ma }}{{ if index $ma "groups" }}{{ toJson (index $ma "groups") }}{{ else }}[]{{ end }}{{ else }}[]{{ end }}`
    // Build OPA payload — Go templates need literal "email" (unescaped), JSON.stringify handles escaping when stored
    const q = '"'
    const opaPayload = `{"input":{"sub":"{{ print .Subject }}","email":"{{ index .Extra.identity.traits ${q}email${q} }}","groups":${groupsTemplate},"object":"{{ .MatchContext.URL.Path }}","action":"{{ .MatchContext.Method }}","app":"${name}"}}`
    const mainRule: OathkeeperRule = {
      id: name,
      upstream: stripPath ? { url: upstreamUrl, strip_path: stripPath } : { url: upstreamUrl },
      match: { url: matchUrl, methods: matchMethods },
      authenticators: [{ handler: 'cookie_session' }],
      authorizer: {
        handler: 'remote_json',
        config: {
          remote: env.OPA_AUTHZ_REMOTE,
          payload: opaPayload,
        },
      },
      mutators: [{ handler: 'header' }],
    }

    // Health rule only for default path-prefix services — custom matchUrl domains
    // can't have a non-conflicting health sub-rule without negative lookahead
    const healthRule: OathkeeperRule | null = isDefaultPath ? {
      id: `${name}-health`,
      upstream: { url: `${upstreamUrl.replace(/\/?$/, '/')}health` },
      match: { url: `https://${domain}/api/${name}/health`, methods: ['GET', 'OPTIONS'] },
      authenticators: [{ handler: 'noop' }],
      authorizer: { handler: 'allow' },
      mutators: [{ handler: 'noop' }],
    } : null

    // 4. Write all to Redis
    await redisRbacRepository.addService(name)
    await redisRbacRepository.setRoles(name, defaultRoles)
    await redisRbacRepository.setRouteMap(name, defaultRouteMap)

    // Add oathkeeper rules
    try { await redisRbacRepository.addAccessRule(mainRule) } catch { /* already exists */ }
    if (healthRule) {
      try { await redisRbacRepository.addAccessRule(healthRule) } catch { /* already exists */ }
    }

    // 5. Auto-populate standard groups with default roles. This reads ALL groups
    // then writes each back — a read-modify-write on the rbac:groups hash. Two
    // concurrent service ops (or a concurrent group edit) would each read the
    // pre-image and the last writer would drop the other's group→service
    // bindings. Serialize the whole read+write under the `groups` lock (#8).
    await withRedisLock('groups', async () => {
      const groups = await redisRbacRepository.getGroups()
      for (const [groupName, defaultGroupRoles] of Object.entries(DEFAULT_GROUP_SERVICE_ROLES)) {
        if (groups[groupName]) {
          groups[groupName][name] = defaultGroupRoles
          await redisRbacRepository.setGroup(groupName, groups[groupName])
        }
      }
    })

    await this.invalidateBundle('rbac.service_created', { type: 'service', id: name }, actor)
    return this.result(`Service '${name}' created with roles, routes, and oathkeeper rules`)
  }

  async deleteService(name: string, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    if (!(await redisRbacRepository.serviceExists(name))) {
      throw Object.assign(new Error(`Service not found: ${name}`), { statusCode: 404 })
    }
    if (await this.isSystemService(name)) {
      throw new SystemResourceImmutable('service', name)
    }

    // Remove from all groups — same read-modify-write on the rbac:groups hash
    // as createService, under the same `groups` lock so concurrent service ops
    // can't drop each other's bindings (#8).
    await withRedisLock('groups', async () => {
      const groups = await redisRbacRepository.getGroups()
      for (const [groupName, services] of Object.entries(groups)) {
        if (name in services) {
          delete services[name]
          await redisRbacRepository.setGroup(groupName, services)
        }
      }
    })

    // Remove oathkeeper rules
    await redisRbacRepository.deleteAccessRule(name)
    await redisRbacRepository.deleteAccessRule(`${name}-health`)

    // Remove data
    await redisRbacRepository.deleteRoles(name)
    await redisRbacRepository.deleteRouteMap(name)
    await redisRbacRepository.removeService(name)
    await redisRbacRepository.deleteServiceMetadata(name)

    await this.invalidateBundle('rbac.service_deleted', { type: 'service', id: name }, actor)
    return this.result(`Service '${name}' deleted`)
  }

  async getServicePermissions(serviceName: string): Promise<{ service: string; permissions: string[] }> {
    if (!(await redisRbacRepository.serviceExists(serviceName))) {
      throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
    }
    const permSet = new Set<string>()
    // Collect from roles
    const roles = await redisRbacRepository.getRoles(serviceName)
    if (roles) {
      for (const perms of Object.values(roles)) {
        for (const p of perms) permSet.add(p)
      }
    }
    // Collect from route map
    const routeMap = await redisRbacRepository.getRouteMap(serviceName)
    if (routeMap?.rules) {
      for (const rule of routeMap.rules) {
        if (rule.permission) permSet.add(rule.permission)
      }
    }
    return { service: serviceName, permissions: [...permSet].sort() }
  }

  async updateServiceConfig(name: string, options: UpdateServiceOptions, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    if (!(await redisRbacRepository.serviceExists(name))) {
      throw Object.assign(new Error(`Service not found: ${name}`), { statusCode: 404 })
    }

    // Same read-modify-write on rbac:oathkeeper:rules as the repository's
    // add/update/deleteAccessRule — take the SAME lock so a service-config edit
    // can't clobber (or be clobbered by) a concurrent rule mutation (#7).
    await withRedisLock('oathkeeper:rules', async () => {
      const rules = await redisRbacRepository.getAccessRules() ?? []
      const ruleIdx = rules.findIndex((r: OathkeeperRule) => r.id === name)
      if (ruleIdx === -1) {
        throw Object.assign(new Error(`Oathkeeper rule not found for service: ${name}`), { statusCode: 404 })
      }

      const existing = rules[ruleIdx]
      const updated: OathkeeperRule = {
        ...existing,
        upstream: {
          url: options.upstreamUrl ?? existing.upstream.url,
          ...(options.stripPath !== undefined
            ? options.stripPath === null
              ? {}  // remove strip_path
              : { strip_path: options.stripPath }
            : existing.upstream.strip_path !== undefined
              ? { strip_path: existing.upstream.strip_path }
              : {}),
          ...(existing.upstream.preserve_host !== undefined ? { preserve_host: existing.upstream.preserve_host } : {}),
        },
        match: {
          url: options.matchUrl ?? existing.match.url,
          methods: (options.matchMethods ?? existing.match.methods) as OathkeeperRule['match']['methods'],
        },
      }

      rules[ruleIdx] = updated
      await redisRbacRepository.setAccessRules(rules)
    })
    await this.invalidateBundle('rbac.service_config_updated', { type: 'service', id: name }, actor)
    return this.result(`Service '${name}' config updated`)
  }

  async updateServiceRoutes(serviceName: string, rules: RouteMap['rules'], actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    if (!(await redisRbacRepository.serviceExists(serviceName))) {
      throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
    }
    await redisRbacRepository.setRouteMap(serviceName, { rules })
    await this.invalidateBundle('rbac.service_routes_updated', { type: 'service', id: serviceName }, actor)
    return this.result(`Route map for '${serviceName}' updated (${rules.length} rules)`)
  }

  async getServiceRoutes(serviceName: string): Promise<{ service: string; rules: RouteMap['rules'] }> {
    if (!(await redisRbacRepository.serviceExists(serviceName))) {
      throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
    }
    const routeMap = await redisRbacRepository.getRouteMap(serviceName)
    return { service: serviceName, rules: routeMap?.rules ?? [] }
  }

  async updateServiceRoles(
    serviceName: string,
    roles: Record<string, string[]>,
    actor?: { email?: string; ip?: string }
  ): Promise<MutationResult> {
    if (!(await redisRbacRepository.serviceExists(serviceName))) {
      throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
    }
    await redisRbacRepository.setRoles(serviceName, roles)
    this.notifyOpalRoles(serviceName).catch(() => {})
    await this.invalidateBundle('roles.updated', { type: 'service', id: serviceName, service: serviceName }, actor)
    return this.result(`Roles updated for ${serviceName}`)
  }

  async getServiceRoles(serviceName: string): Promise<{ service: string; roles: Array<{ name: string; permissions: string[] }> }> {
    const roles = await redisRbacRepository.getRoles(serviceName)
    if (!roles) {
      throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
    }
    return {
      service: serviceName,
      roles: Object.entries(roles).map(([name, permissions]) => ({ name, permissions })),
    }
  }

  // ===========================================================================
  // Access Rules (Oathkeeper)
  // ===========================================================================

  async getAccessRules(): Promise<AccessRulesResponse> {
    const rules = await redisRbacRepository.getAccessRules()
    return { rules }
  }

  async getAccessRule(id: string): Promise<{ rule: OathkeeperRule }> {
    const rule = await redisRbacRepository.getAccessRule(id)
    if (!rule) {
      throw Object.assign(new Error(`Access rule not found: ${id}`), { statusCode: 404 })
    }
    return { rule }
  }

  async createAccessRule(rule: OathkeeperRule, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    try {
      await redisRbacRepository.addAccessRule(rule)
    } catch (err) {
      throw Object.assign(new Error((err as Error).message), { statusCode: 409 })
    }
    await this.invalidateBundle('rbac.access_rule_created', { type: 'access_rule', id: rule.id }, actor)
    return this.result(`Access rule '${rule.id}' created`)
  }

  async updateAccessRule(id: string, rule: OathkeeperRule, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    const updated = await redisRbacRepository.updateAccessRule(id, { ...rule, id })
    if (!updated) {
      throw Object.assign(new Error(`Access rule not found: ${id}`), { statusCode: 404 })
    }
    await this.invalidateBundle('rbac.access_rule_updated', { type: 'access_rule', id }, actor)
    return this.result(`Access rule '${id}' updated`)
  }

  async deleteAccessRule(id: string, actor?: { email?: string; ip?: string }): Promise<MutationResult> {
    const deleted = await redisRbacRepository.deleteAccessRule(id)
    if (!deleted) {
      throw Object.assign(new Error(`Access rule not found: ${id}`), { statusCode: 404 })
    }
    await this.invalidateBundle('rbac.access_rule_deleted', { type: 'access_rule', id }, actor)
    return this.result(`Access rule '${id}' deleted`)
  }

  // ===========================================================================
  // Org → Service Map
  // ===========================================================================

  async getOrgServiceMap(): Promise<Record<string, string>> {
    return redisRbacRepository.getOrgServiceMap()
  }

  async setOrgServiceMapping(organizationId: string, serviceName: string, actor?: { email?: string; ip?: string }): Promise<void> {
    const serviceExists = await redisRbacRepository.serviceExists(serviceName)
    if (!serviceExists) {
      throw Object.assign(new Error(`Service '${serviceName}' does not exist`), { statusCode: 400 })
    }
    await redisRbacRepository.setOrgServiceMapping(organizationId, serviceName)
    await this.invalidateBundle('rbac.org_service_mapping_set', { type: 'org_service_map', id: organizationId, service: serviceName }, actor)
  }

  async deleteOrgServiceMapping(organizationId: string, actor?: { email?: string; ip?: string }): Promise<void> {
    const deleted = await redisRbacRepository.deleteOrgServiceMapping(organizationId)
    if (!deleted) {
      throw Object.assign(new Error(`No mapping found for organization '${organizationId}'`), { statusCode: 404 })
    }
    await this.invalidateBundle('rbac.org_service_mapping_deleted', { type: 'org_service_map', id: organizationId }, actor)
  }

  // ===========================================================================
  // Kratos Bindings
  // ===========================================================================

  async getBindingsFromKratos(): Promise<KratosBindingsResponse> {
    // Single directory scan → groups + org membership + primary org, so OPA's
    // group view and its tenant (org) view come from the same snapshot.
    const bindings = await kratosService.getAllIdentitiesWithBindings()
    const group_membership: Record<string, string[]> = {}
    const user_organizations: Record<string, string[]> = {}
    const user_organization_primary: Record<string, string> = {}
    for (const [email, b] of bindings) {
      group_membership[email] = b.groups
      // user_organizations = ALL orgs the user belongs to = the multi-org
      // membership (metadata_admin.organizations) UNION the primary org (native
      // organization_id). The union is required today: metadata_admin.organizations
      // has no writer yet, so without folding in the primary a rego reading only
      // user_organizations would deny every org-scoped action for every current
      // user. Order-stable (membership first, primary appended if new) + deduped.
      const orgs = [...b.organizations]
      if (b.primaryOrganization && !orgs.includes(b.primaryOrganization)) {
        orgs.push(b.primaryOrganization)
      }
      // Only emit org keys for users with at least one org — keep the payload
      // minimal and don't advertise the full directory as empty entries.
      if (orgs.length > 0) user_organizations[email] = orgs
      if (b.primaryOrganization) user_organization_primary[email] = b.primaryOrganization
    }
    return { emails: {}, group_membership, user_organizations, user_organization_primary }
  }
}

// Singleton export
export const rbacService = new RbacService()
