import { kratosService } from './kratos.service.js'
import { redisRbacRepository, type GroupDefinition, type FlatRolesMap, type RouteMap, type OathkeeperRule } from './redis-rbac.repository.js'
import { withRedisLock } from './redis-lock.js'
import { auditEventService, type AuditActorInput, type AuditChanges } from './audit-event.service.js'
import { accessReviewService } from './access-review.service.js'
import { diffGroupDefinition, diffRoles, diffRouteMap, diffOathkeeperRule } from './audit-diff.js'
import { ASSIGN_MEMBERSHIP, holdsPlatformPermission } from './authorization-model.service.js'
import { realtimeService } from './realtime.service.js'
import { defaultServiceRoles } from './rbac-defaults.js'
import {
  isHandlerEnabled,
  getEnabledHandlerNames,
  type HandlerKind,
} from './oathkeeper-handlers.js'
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

/**
 * SINGLE source of truth for legal service names. Used by BOTH the Fastify
 * route JSON schema and the controller's zod validation — they diverged once
 * (route allowed hyphens, controller didn't → every hyphenated service name
 * 400'd) and must never be able to again.
 */
export const SERVICE_NAME_PATTERN = /^[a-z0-9_-]+$/

/**
 * High-level sign-in methods a service accepts on its main gateway rule.
 * Maps to an ORDERED Oathkeeper authenticator chain (the gateway consults the
 * first authenticator that recognizes the credential format):
 *   cookie → cookie_session, bearer → bearer_token, introspection →
 *   oauth2_introspection. Empty array = public (noop + allow).
 */
export type SignInMethod = 'cookie' | 'bearer' | 'introspection'

/**
 * Maps high-level sign-in methods to an ORDERED Oathkeeper authenticator
 * chain. Fallback order is fixed cookie → bearer → introspection (the gateway
 * consults the first authenticator recognizing the credential format). When
 * bearer AND introspection are both on, both would read `Authorization:
 * Bearer` and the first match would stop the chain — so the Kratos bearer
 * reads the X-Session-Token header instead. Fails closed: throws 400 if a
 * mapped authenticator is not in the gateway's enabled set.
 */
export function buildSignInAuthenticators(signIn: SignInMethod[]): OathkeeperRule['authenticators'] {
  if (signIn.length === 0) return [{ handler: 'noop' }]
  const out: OathkeeperRule['authenticators'] = []
  if (signIn.includes('cookie')) out.push({ handler: 'cookie_session' })
  if (signIn.includes('bearer')) {
    out.push(
      signIn.includes('introspection')
        ? { handler: 'bearer_token', config: { token_from: { header: 'X-Session-Token' } } }
        : { handler: 'bearer_token' }
    )
  }
  if (signIn.includes('introspection')) out.push({ handler: 'oauth2_introspection' })
  for (const a of out) {
    if (!isHandlerEnabled('authenticator', a.handler)) {
      throw Object.assign(
        new Error(
          `Sign-in method requires authenticator '${a.handler}', which is not enabled on this gateway (OATHKEEPER_ENABLED_AUTHENTICATORS).`
        ),
        { statusCode: 400 }
      )
    }
  }
  return out
}

export interface CreateServiceOptions {
  name: string
  displayName?: string
  upstreamUrl?: string
  matchUrl?: string
  matchMethods?: string[]
  stripPath?: string
  /** Accepted sign-in methods. Default ['cookie']. [] = public endpoint. */
  signIn?: SignInMethod[]
}

export interface UpdateServiceOptions {
  upstreamUrl?: string
  matchUrl?: string
  matchMethods?: string[]
  stripPath?: string | null  // null = remove strip_path
  /** Replace the accepted sign-in methods on the service's main rule. */
  signIn?: SignInMethod[]
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

/**
 * Where a generated access rule would send its authorization question, if anything read those rules.
 * `.invalid` can never resolve (RFC 2606), so it reads as intended rather than as a hostname
 * somebody forgot to update.
 */
const RETIRED_AUTHORIZER = 'http://retired.invalid:8080/v1/data/strada/authz/decision'

export class RbacService {
  // ===========================================================================
  // Private Helpers
  // ===========================================================================

  private result(message: string): MutationResult {
    return { success: true, message, timestamp: new Date().toISOString() }
  }

  /**
   * Privilege escalation guard: refuses the mutation unless the actor holds `admin.membership:write`
   * across the platform.
   *
   * A DECLARED PERMISSION, not a shape. What this held before asked whether the actor was in any
   * group granting under `*` — which conflated "operator of one API everywhere" with "administrator
   * of the platform", and was a predicate invented here rather than something the model says. The
   * model says it now, and the coverage rule that admits `admin:write` for it is the same one the
   * engine applies to a route.
   *
   * Keyed on the IMMUTABLE identity rather than an address: this is the gate that says who may hand
   * out rights, so it must not move when somebody changes their email, nor follow a reused one.
   *
   * FAIL-CLOSED on every uncertainty: no identity, or a model that cannot be read, both refuse.
   */
  private async requireSuperAdmin(
    reason: string,
    actor?: { id?: string | null; email?: string | null },
  ): Promise<void> {
    if (!actor?.id) {
      throw Object.assign(
        new Error('Authentication required for this operation'),
        { statusCode: 401 },
      )
    }
    let powerful: boolean
    try {
      powerful = await holdsPlatformPermission(actor.id, ASSIGN_MEMBERSHIP)
    } catch (err) {
      throw Object.assign(
        new Error(`The authorization model could not be read, so nobody may ${reason}: ${(err as Error).message}`),
        { statusCode: 503 },
      )
    }
    if (!powerful) {
      throw Object.assign(
        new Error(`Only ${ASSIGN_MEMBERSHIP} may ${reason}`),
        { statusCode: 403 },
      )
    }
  }

  // `isSuperAdmin` lived here and asked the previous model — Kratos read through a cache — for a
  // `*` permission this model deliberately does not define. So what an administrator could see was
  // decided by metadata nobody enforces, keyed on an address. Its one caller now asks
  // `holdsPlatformPermission` for the permission it actually needs, on the immutable identity.


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
   * Public wrapper exposing the super_admin authority check used internally
   * by mutation guards. Throws 403 if the actor is not a super_admin.
   */
  async assertSuperAdmin(
    reason: string,
    actor?: { id?: string | null; email?: string | null },
  ): Promise<void> {
    return this.requireSuperAdmin(reason, actor)
  }

  // The group predicates that used to live here — admin power, global power, emptiness, and the
  // MFA gate built on them — read this store's group and role definitions. The engine decides
  // against a model carried in the bundle, which this store does not hold, so for every group that
  // model declares they answered "confers nothing". `authorization-model.service` answers them now,
  // from the documents the bundle carries.

  // Public: call after any user-group mutation that bypasses rbacService methods
  async notifyBindingsChanged(reason: string, actor?: AuditActorInput): Promise<void> {
    await this.invalidateBundle(`user.${reason}`, { type: 'user' }, actor)
  }

  // Public: the RBAC bundle importer reuses this exact fan-out so a restore
  // propagates to OPAL/OPA immediately (etag bump + real-time + OPAL push),
  // instead of leaving OPA on stale data until the next mutation/restart.
  //
  // `changes` (A3) carries the redacted before→after envelope; `actor` is the
  // full audit-actor (A4) so name/ua/sessionId/requestId thread through and
  // cascade child-events correlate by requestId.
  async invalidateBundle(eventType?: string, target?: { type?: string; id?: string; service?: string; services?: string[] }, actor?: AuditActorInput, changes?: AuditChanges): Promise<void> {
    await redisRbacRepository.invalidateBundleEtag()

    // Directory counts (total/active/perGroup/perOrg) may have moved — drop the
    // stats cache so the next dashboard read recomputes. Best-effort; covers
    // every mutation flowing through here (groups/services/org-map + all
    // notifyBindingsChanged user mutations).
    redisRbacRepository.invalidateStats().catch(() => {})
    // Access-review resolves the same bindings/group definitions — bust its SWR
    // cache too ([P1-5]) so the next review reflects this mutation.
    accessReviewService.invalidate()
    // Push a real-time signal so connected admin browsers refetch at once.
    realtimeService.publish(eventType ?? 'rbac')

    // Notify OPAL server for real-time WebSocket push to all OPA clients (<100ms)
    // The OPAL push that used to be here is gone: no OPAL runs in this namespace, and the engine
    // pulls a bundle instead of being pushed data. It failed on every mutation, logging a DNS
    // error for a component that never existed here. The etag invalidation and the real-time
    // notification above DO serve, and stay.

    if (eventType) {
      auditEventService.emit({
        type: eventType,
        target,
        actor: { email: actor?.email, ip: actor?.ip, name: actor?.name, ua: actor?.ua, sessionId: actor?.sessionId },
        requestId: actor?.requestId,
        changes,
        source: 'jinbe-api',
      }).catch(() => {})
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
    // Directory membership drives access-review tiers/reach — bust it too ([P1-5]).
    accessReviewService.invalidate()
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

  async createGroup(name: string, services: GroupDefinition, actor?: AuditActorInput): Promise<MutationResult> {
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
    const changes = diffGroupDefinition(name, null, services)
    await this.invalidateBundle('rbac.group_created', { type: 'group', id: name }, actor, changes)
    return this.result(`Group '${name}' created`)
  }

  async updateGroup(name: string, services: GroupDefinition, actor?: AuditActorInput): Promise<MutationResult> {
    if (!(await redisRbacRepository.groupExists(name))) {
      throw Object.assign(new Error(`Group not found: ${name}`), { statusCode: 404 })
    }
    // Privilege escalation guard: editing super_admins (the wildcard group)
    // requires the caller to already be a super_admin themselves.
    if (name === 'super_admins') {
      await this.requireSuperAdmin(`modify the 'super_admins' group`, actor)
    }
    // Capture the pre-image for the before→after diff (A3).
    const before = await redisRbacRepository.getGroup(name)
    // PUT semantics: full replace. Earlier behavior merged the incoming
    // services map with the existing one, which silently dropped the
    // operator's intent when they unchecked every role for a service —
    // the API returned 200 but nothing changed in Redis. Replacing
    // matches the REST PUT contract and what kuma's UI implies.
    await redisRbacRepository.setGroup(name, services)
    const changes = diffGroupDefinition(name, before, services)
    await this.invalidateBundle('rbac.group_updated', { type: 'group', id: name }, actor, changes)
    return this.result(`Group '${name}' updated`)
  }

  async deleteGroup(name: string, actor?: AuditActorInput): Promise<MutationResult> {
    if (!(await redisRbacRepository.groupExists(name))) {
      throw Object.assign(new Error(`Group not found: ${name}`), { statusCode: 404 })
    }
    if (await this.isSystemGroup(name)) {
      // System groups are never deletable — even by super_admins. Removing
      // super_admins leaves the cluster with no path back to global admin.
      // Emit the denied attempt (previously silent) before failing closed.
      auditEventService.emit({
        category: 'rbac', kind: 'change', verb: 'delete', target: `group:${name}`,
        result: 'denied', reason: 'system_resource_immutable', severity: 'warn',
        targetType: 'group', targetId: name,
        actor: { email: actor?.email ?? null, ip: actor?.ip, name: actor?.name, ua: actor?.ua, sessionId: actor?.sessionId },
        requestId: actor?.requestId, source: 'jinbe-api',
      }).catch(() => {})
      throw new SystemResourceImmutable('group', name)
    }
    const before = await redisRbacRepository.getGroup(name)
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

    const changes = diffGroupDefinition(name, before, {})
    await this.invalidateBundle('rbac.group_deleted', { type: 'group', id: name }, actor, changes)
    return this.result(`Group '${name}' deleted`)
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

  async createService(options: CreateServiceOptions, actor?: AuditActorInput): Promise<MutationResult> {
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

    // 1. Create default roles (shared with the bundle-import autofix)
    const defaultRoles: FlatRolesMap = defaultServiceRoles(name)

    // 2. Create default route map with health endpoint
    const defaultRouteMap: RouteMap = {
      rules: [{ method: 'GET', path: `/api/${name}/health` }],
    }

    // 3. Create Oathkeeper rules
    // Per-rule authorizer config overrides the global one — sets app to this service name
    // so OPA evaluates RBAC against this service's roles/routes, not the global config
    // Sign-in methods → ordered authenticator chain. Default: cookie only
    // (previous hardcoded behavior). [] = public: no auth check, allow-all
    // authorizer — OPA has no subject to evaluate for anonymous traffic.
    const signIn = options.signIn ?? ['cookie']
    const isPublic = signIn.length === 0
    const mainRule: OathkeeperRule = {
      id: name,
      upstream: stripPath ? { url: upstreamUrl, strip_path: stripPath } : { url: upstreamUrl },
      match: { url: matchUrl, methods: matchMethods },
      authenticators: buildSignInAuthenticators(signIn),
      authorizer: isPublic
        ? { handler: 'allow' }
        : {
            handler: 'remote_json',
            config: this.buildRemoteJsonConfig(name),
          },
      mutators: [{ handler: isPublic ? 'noop' : 'header' }],
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

    await this.invalidateBundle('rbac.service_created', { type: 'service', id: name, service: name }, actor)
    return this.result(`Service '${name}' created with roles, routes, and oathkeeper rules`)
  }

  async deleteService(name: string, actor?: AuditActorInput): Promise<MutationResult> {
    if (!(await redisRbacRepository.serviceExists(name))) {
      throw Object.assign(new Error(`Service not found: ${name}`), { statusCode: 404 })
    }
    if (await this.isSystemService(name)) {
      auditEventService.emit({
        category: 'service', kind: 'change', verb: 'delete', target: `service:${name}`,
        result: 'denied', reason: 'system_resource_immutable', severity: 'warn',
        service: name, targetType: 'service', targetId: name,
        actor: { email: actor?.email ?? null, ip: actor?.ip, name: actor?.name, ua: actor?.ua, sessionId: actor?.sessionId },
        requestId: actor?.requestId, source: 'jinbe-api',
      }).catch(() => {})
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

    await this.invalidateBundle('rbac.service_deleted', { type: 'service', id: name, service: name }, actor)
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

  async updateServiceConfig(name: string, options: UpdateServiceOptions, actor?: AuditActorInput): Promise<MutationResult> {
    if (!(await redisRbacRepository.serviceExists(name))) {
      throw Object.assign(new Error(`Service not found: ${name}`), { statusCode: 404 })
    }

    // Capture the posture before→after (A3) — structural fields only, computed
    // inside the lock where `existing` is authoritative.
    let changes: AuditChanges | undefined
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
        // Replace the sign-in chain when requested. Switching to public also
        // relaxes authorizer/mutators (OPA can't evaluate anonymous traffic);
        // switching BACK from public restores the OPA-checked posture.
        ...(options.signIn !== undefined
          ? options.signIn.length === 0
            ? {
                authenticators: buildSignInAuthenticators([]),
                authorizer: { handler: 'allow' as const },
                mutators: [{ handler: 'noop' }],
              }
            : {
                authenticators: buildSignInAuthenticators(options.signIn),
                authorizer:
                  existing.authorizer.handler === 'allow'
                    ? { handler: 'remote_json' as const, config: this.buildRemoteJsonConfig(name) }
                    : existing.authorizer,
                mutators: existing.mutators?.some((m) => m.handler === 'header')
                  ? existing.mutators
                  : [{ handler: 'header' }],
              }
          : {}),
      }

      rules[ruleIdx] = updated
      changes = diffOathkeeperRule(name, existing, updated)
      await redisRbacRepository.setAccessRules(rules)
    })
    await this.invalidateBundle('rbac.service_config_updated', { type: 'service', id: name, service: name }, actor, changes)
    return this.result(`Service '${name}' config updated`)
  }

  async updateServiceRoutes(serviceName: string, rules: RouteMap['rules'], actor?: AuditActorInput): Promise<MutationResult> {
    if (!(await redisRbacRepository.serviceExists(serviceName))) {
      throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
    }
    const before = await redisRbacRepository.getRouteMap(serviceName)
    await redisRbacRepository.setRouteMap(serviceName, { rules })
    const changes = diffRouteMap(serviceName, before, { rules })
    await this.invalidateBundle('rbac.service_routes_updated', { type: 'service', id: serviceName, service: serviceName }, actor, changes)
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
    actor?: AuditActorInput
  ): Promise<MutationResult> {
    if (!(await redisRbacRepository.serviceExists(serviceName))) {
      throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
    }
    const before = await redisRbacRepository.getRoles(serviceName)
    await redisRbacRepository.setRoles(serviceName, roles)
    const changes = diffRoles(serviceName, before, roles)
    await this.invalidateBundle('roles.updated', { type: 'service', id: serviceName, service: serviceName }, actor, changes)
    return this.result(`Roles updated for ${serviceName}`)
  }

  async getServiceRoles(serviceName: string): Promise<{ service: string; roles: Array<{ name: string; permissions: string[] }> }> {
    let roles = await redisRbacRepository.getRoles(serviceName)
    // Self-repair: a registered service with no roles (legacy / hand-created
    // without defaults) is seeded the standard default role set on first read —
    // the same defaults createService applies — instead of 404-ing. 404 only if
    // the service isn't registered at all.
    if (!roles || Object.keys(roles).length === 0) {
      const services = await redisRbacRepository.getServices()
      if (!services.includes(serviceName)) {
        throw Object.assign(new Error(`Service not found: ${serviceName}`), { statusCode: 404 })
      }
      roles = defaultServiceRoles(serviceName)
      await redisRbacRepository.setRoles(serviceName, roles)
      await this.invalidateBundle('rbac.roles_selfrepaired', { type: 'service', id: serviceName, service: serviceName }, { email: 'system' })
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

  /**
   * Builds the PER-SERVICE `remote_json` authorizer config: the shared OPA
   * remote endpoint plus a Go-template `payload` that embeds this service's
   * name as `app`, so OPA authorizes the request against THIS service's
   * roles/routes rather than some other service's. Extracted from createService
   * and reused by the create/update backfill net so a rule can never be
   * persisted with a bare or app-less remote_json config that would silently
   * authorize against the wrong service.
   */
  /**
   * The authorizer an access rule generated here would carry.
   *
   * DELIBERATELY UNREACHABLE, like the rules it belongs to. The proxy reads its rules from the
   * ConfigMap a controller owns, rendered from Git — so nothing this generates reaches it, and the
   * address it used to name (an adapter Service, then a chart default naming a component that never
   * existed here) only made a dead rule look live.
   *
   * The generation itself is not removed here: it is reachable from more places than one commit
   * should touch, and `RULES_SOURCE` — the flag that says where rules come from — gates NOTHING
   * today. It is only reported to the console, which greys the screen while the machinery underneath
   * still runs. Making it gate is the next step, and it is what lets all of this go.
   */
  private buildRemoteJsonConfig(service: string): { remote: string; payload: string } {
    const groupsTemplate = `{{ $ma := index .Extra.identity "metadata_admin" }}{{ if $ma }}{{ if index $ma "groups" }}{{ toJson (index $ma "groups") }}{{ else }}[]{{ end }}{{ else }}[]{{ end }}`
    // Go templates need a literal "email" key (unescaped); JSON.stringify handles
    // escaping when the rule is stored.
    const q = '"'
    const payload = `{"input":{"sub":"{{ print .Subject }}","email":"{{ index .Extra.identity.traits ${q}email${q} }}","groups":${groupsTemplate},"object":"{{ .MatchContext.URL.Path }}","action":"{{ .MatchContext.Method }}","app":"${service}"}}`
    return { remote: RETIRED_AUTHORIZER, payload }
  }

  /**
   * Derives the owning service of an access rule from its id. Rule ids are the
   * service name, optionally with a suffix (e.g. `<service>-health`,
   * `<service>-preflight`). Matches the id against the registered service names
   * and returns the LONGEST one the id equals or is prefixed by (at a `-`
   * boundary) — so a hyphenated service like `order-service` wins over a bare
   * `order`, and suffixed sub-rules resolve to their real service. Falls back to
   * the id's first `-`-segment only when no registered service matches (e.g. the
   * rule is created before its service is registered).
   */
  private deriveServiceForRule(id: string, services: string[]): string {
    let best: string | null = null
    for (const svc of services) {
      if (id === svc || id.startsWith(`${svc}-`)) {
        if (best === null || svc.length > best.length) best = svc
      }
    }
    return best ?? id.split('-')[0]
  }

  /**
   * P0 safety net for the gateway editor: `remote_json`'s config is PER-SERVICE
   * (its `payload` embeds `"app":"<service>"`). A rule saved with a bare or
   * app-less remote_json config would authorize against the wrong service —
   * silent mis-authorization. So before persisting, if the authorizer is
   * remote_json and either `remote` or `payload` is missing/empty, backfill the
   * correct per-service config derived from the rule's id. Any already-present
   * value is preserved verbatim — only absent fields are filled — so a complete
   * or custom per-service config is stored unchanged.
   */
  private async backfillRemoteJsonConfig(rule: OathkeeperRule): Promise<void> {
    if (rule.authorizer?.handler !== 'remote_json') return
    const config = rule.authorizer.config as { remote?: unknown; payload?: unknown } | undefined
    const isEmpty = (v: unknown): boolean =>
      v === undefined || v === null || (typeof v === 'string' && v.trim() === '')
    const remoteMissing = isEmpty(config?.remote)
    const payloadMissing = isEmpty(config?.payload)
    if (!remoteMissing && !payloadMissing) return

    const services = await redisRbacRepository.getServices()
    const service = this.deriveServiceForRule(rule.id, services)
    const built = this.buildRemoteJsonConfig(service)
    rule.authorizer.config = {
      ...(config ?? {}),
      ...(remoteMissing ? { remote: built.remote } : {}),
      ...(payloadMissing ? { payload: built.payload } : {}),
    }
  }

  /**
   * Fail-closed guard: reject any access rule that references a handler not
   * enabled in the running gateway. If jinbe stored such a rule, Oathkeeper
   * would reject the ENTIRE ruleset at load → the gateway goes down for every
   * service. So we validate every stage (authenticators, authorizer, mutators,
   * error handlers) before writing and throw a 400 naming the offending handler
   * and the allowed options. Per-service rule generation only ever uses handlers
   * from the enabled defaults, so it is unaffected.
   */
  private assertHandlersEnabled(rule: OathkeeperRule): void {
    const stages: Array<{ kind: HandlerKind; name: string }> = []
    for (const a of rule.authenticators ?? []) stages.push({ kind: 'authenticator', name: a.handler })
    if (rule.authorizer) stages.push({ kind: 'authorizer', name: rule.authorizer.handler })
    for (const m of rule.mutators ?? []) stages.push({ kind: 'mutator', name: m.handler })
    for (const e of rule.errors ?? []) stages.push({ kind: 'error', name: e.handler })

    for (const { kind, name } of stages) {
      if (!isHandlerEnabled(kind, name)) {
        const allowed = getEnabledHandlerNames(kind)
        throw Object.assign(
          new Error(
            `The ${kind} handler '${name}' is not enabled in the gateway and would break the entire ruleset. ` +
              `Enabled ${kind}s: ${allowed.join(', ') || '(none)'}.`,
          ),
          { statusCode: 400 },
        )
      }
    }
  }

  async createAccessRule(rule: OathkeeperRule, actor?: AuditActorInput): Promise<MutationResult> {
    this.assertHandlersEnabled(rule)
    await this.backfillRemoteJsonConfig(rule)
    try {
      await redisRbacRepository.addAccessRule(rule)
    } catch (err) {
      throw Object.assign(new Error((err as Error).message), { statusCode: 409 })
    }
    const changes = diffOathkeeperRule(rule.id, null, rule)
    await this.invalidateBundle('rbac.access_rule_created', { type: 'access_rule', id: rule.id }, actor, changes)
    return this.result(`Access rule '${rule.id}' created`)
  }

  async updateAccessRule(id: string, rule: OathkeeperRule, actor?: AuditActorInput): Promise<MutationResult> {
    this.assertHandlersEnabled(rule)
    // Persist under the path id (authoritative). Backfill derives the service
    // from that same id so a bare/app-less remote_json can't slip through.
    const toPersist: OathkeeperRule = { ...rule, id }
    const before = (await redisRbacRepository.getAccessRules() ?? []).find((r) => r.id === id)
    await this.backfillRemoteJsonConfig(toPersist)
    const updated = await redisRbacRepository.updateAccessRule(id, toPersist)
    if (!updated) {
      throw Object.assign(new Error(`Access rule not found: ${id}`), { statusCode: 404 })
    }
    const changes = diffOathkeeperRule(id, before, toPersist)
    await this.invalidateBundle('rbac.access_rule_updated', { type: 'access_rule', id }, actor, changes)
    return this.result(`Access rule '${id}' updated`)
  }

  async deleteAccessRule(id: string, actor?: AuditActorInput): Promise<MutationResult> {
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

  async getOrgServiceMap(): Promise<Record<string, string[]>> {
    return redisRbacRepository.getOrgServiceMap()
  }

  async setOrgServiceMapping(organizationId: string, services: string[], actor?: AuditActorInput): Promise<void> {
    // Fail-closed: validate EVERY service in the bundle exists before writing.
    // Reject the whole set if any is unknown rather than mapping an org to a
    // phantom service (which would resolve to no route_map / no roles in OPA).
    for (const serviceName of services) {
      const serviceExists = await redisRbacRepository.serviceExists(serviceName)
      if (!serviceExists) {
        throw Object.assign(new Error(`Service '${serviceName}' does not exist`), { statusCode: 400 })
      }
    }
    await redisRbacRepository.setOrgServiceMapping(organizationId, services)
    await this.invalidateBundle('rbac.org_service_mapping_set', { type: 'org_service_map', id: organizationId, services }, actor)
  }

  async deleteOrgServiceMapping(organizationId: string, actor?: AuditActorInput): Promise<void> {
    const deleted = await redisRbacRepository.deleteOrgServiceMapping(organizationId)
    if (!deleted) {
      throw Object.assign(new Error(`No mapping found for organization '${organizationId}'`), { statusCode: 404 })
    }
    await this.invalidateBundle('rbac.org_service_mapping_deleted', { type: 'org_service_map', id: organizationId }, actor)
  }

  async getOrgAdminMap(): Promise<Record<string, string[]>> {
    return redisRbacRepository.getOrgAdminMap()
  }

  // Replace an org's admin roster with exactly `admins`. Membership is NOT
  // re-validated here on purpose: the policy's manageable_orgs requires the admin
  // to also be a MEMBER of the org (data.bindings.user_organizations), so a
  // rostered non-member is inert — they gain nothing until they're a member.
  async setOrgAdmins(organizationId: string, admins: string[], actor?: AuditActorInput): Promise<void> {
    await redisRbacRepository.setOrgAdmins(organizationId, admins)
    await this.invalidateBundle('rbac.org_admins_set', { type: 'org_admin_map', id: organizationId }, actor)
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
