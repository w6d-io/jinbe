import { kratosService } from './kratos.service.js'
import { redisRbacRepository, type FlatRolesMap } from './redis-rbac.repository.js'
import { auditEventService } from './audit-event.service.js'
import { getRedisClient } from './redis-client.service.js'

/**
 * Access Review Service (audit-overhaul Part B / [P1-5])
 *
 * Answers "who can do anything, and how they got it" for the whole directory.
 *
 * Resolver correctness (the whole point of [P1-5]):
 *  - Enumerate identities via kratosService.getAllIdentitiesWithBindings() — the
 *    single light directory walk (NOT getUsers(), whose MFA enrichment is capped
 *    at 250 rows).
 *  - Resolve power across ALL services by walking the group definitions once
 *    (the exact shape of rbacService.wildcardGroupNames / getDirectoryStats),
 *    NOT resolveUserRbac(email, appName) — that is single-app and would miss
 *    power held in other services.
 *  - MFA comes from a dedicated PAGINATED credential pass (every page, with
 *    include_credential) so it is not truncated at 250.
 *
 * Tiers (highest wins):
 *  - T0 = a group grants GLOBAL power (global super_admin role, or a global role
 *         resolving to the "*" permission).
 *  - T1 = a group grants a SERVICE wildcard ("*") but not global power.
 *  - T2 = org-admin, POSITIONAL: rostered in getOrgAdminMap() AND a member of
 *         that org (user_organizations). This is invisible to a perms-walk — the
 *         power comes from the org roster, not from a group→role→perm chain.
 *  - T3 = broad cross-service reach (>= BROAD_REACH_MIN distinct services).
 *
 * SWR-cached exactly like getDirectoryStats: served fresh-or-stale at once,
 * refreshed in the background, single-flight, epoch-guarded so a bust that lands
 * mid-compute is never cached. Busted from rbacService.invalidateBundle /
 * invalidateDirectoryStats (see rbac.service.ts).
 *
 * Fail-closed: an error reading the directory / group definitions THROWS — the
 * caller must see a load error, never a spuriously "clean" empty list.
 */

// ── Tuning constants ─────────────────────────────────────────────────────────
/** Distinct services that count as "broad cross-service" reach (T3 threshold). */
const BROAD_REACH_MIN = 3
/** Distinct services that trigger the "sprawl" flag. */
const SPRAWL_MIN = 5
/** A privileged identity with no recorded activity newer than this is dormant. */
const DORMANT_MS = 30 * 24 * 60 * 60 * 1000
/** Serve cached for this long before a background refresh (mirrors getDirectoryStats). */
const FRESH_MS = 15_000
/** Cap on how many grant paths we surface per identity (strongest first). */
const MAX_PATHS = 24

// ── Output shape (matches kuma AccessReview.tsx + api/types.ts contract) ───────
export interface AccessReviewGrantPath {
  group: string
  service?: string
  role?: string
  summary: string
}

export interface AccessReviewIdentityOut {
  id: string
  email: string
  name?: string
  /** 0 = global super-admin, 1 = service wildcard, 2 = org-admin, 3 = broad reach. */
  tier: number
  tierLabel: string
  /** Distinct service count the identity can reach. */
  reach: number
  services: string[]
  /** Alias of `services` (Part B prose contract). */
  reachServices: string[]
  groups: string[]
  flags: string[]
  mfa: boolean
  active: boolean
  lastActive: string | null
  lastPrivilegedAction: string | null
  grantedBy: string | null
  grantedAt: string | null
  provenance: { grantedBy?: string | null; at?: string | null } | null
  selfGranted: boolean
  powerScore: number
  /** Alias of `powerScore` (Part B prose contract). */
  score: number
  paths: AccessReviewGrantPath[]
  /** Plain "group → role → perm" strings (Part B prose contract). */
  powerPaths: string[]
}

export interface AccessReviewSummary {
  totalPrivileged: number
  /** Alias of `totalPrivileged`. */
  total: number
  /** T0 + T1 — "can do anything". */
  canDoAnything: number
  selfGranted: number
  dormant: number
  noMfa: number
  /** Alias of `noMfa`. */
  withoutMfa: number
  computedAt: string
}

export interface AccessReviewResult {
  summary: AccessReviewSummary
  identities: AccessReviewIdentityOut[]
  limits: { bounded: boolean; note: string }
}

// ── Per-group resolved power (computed once per walk) ──────────────────────────
interface GroupPower {
  globalPower: boolean
  /** Services where one of the group's roles grants the "*" permission. */
  wildcardServices: Set<string>
  /** All (non-global) services the group binds a role on. */
  services: Set<string>
  paths: AccessReviewGrantPath[]
}

class AccessReviewService {
  private cache: { computedAt: number; data: AccessReviewResult } | null = null
  private inflight: Promise<AccessReviewResult> | null = null
  // Monotonic generation — a background refresh that read its inputs BEFORE a
  // bust must decline to cache its (now stale) result. Mirrors statsEpoch.
  private epoch = 0

  /** Drop the cache — called from rbacService.invalidateBundle / invalidateDirectoryStats. */
  invalidate(): void {
    this.epoch++
    this.cache = null
  }

  /** SWR read: fresh-or-stale at once, refresh in the background, single-flight. */
  async getAccessReview(): Promise<AccessReviewResult> {
    const cached = this.cache
    if (cached) {
      if (Date.now() - cached.computedAt >= FRESH_MS) {
        void this.refresh().catch(() => {})
      }
      return cached.data
    }
    // Cold cache: compute once and wait. Errors propagate (fail-closed).
    return this.refresh()
  }

  private refresh(): Promise<AccessReviewResult> {
    if (this.inflight) return this.inflight
    const startEpoch = this.epoch
    const p = (async (): Promise<AccessReviewResult> => {
      const data = await this.compute()
      // Only publish if no bust landed while we computed.
      if (this.epoch === startEpoch) this.cache = { computedAt: Date.now(), data }
      return data
    })()
    this.inflight = p
    // Clear the single-flight slot when the walk settles. The cleanup runs on a
    // SEPARATE promise chain, so its rejection must be swallowed here — the real
    // rejection still propagates to the caller via the returned `p` (fail-closed).
    void p.finally(() => { if (this.inflight === p) this.inflight = null }).catch(() => {})
    return p
  }

  private async compute(): Promise<AccessReviewResult> {
    // Fail-closed core reads: any of these throwing aborts the whole review so
    // the caller sees a load error, never an empty "clean" posture.
    const [bindings, groupDefs, services, orgAdminMap] = await Promise.all([
      kratosService.getAllIdentitiesWithBindings(),
      redisRbacRepository.getGroups(),
      redisRbacRepository.getServices(),
      redisRbacRepository.getOrgAdminMap(),
    ])

    // Resolve every role definition once, across all services + global (the walk
    // shape of wildcardGroupNames): union of registry services + services any
    // group binds, plus 'global'.
    const svcSet = new Set<string>(services)
    for (const def of Object.values(groupDefs)) {
      for (const svc of Object.keys(def)) svcSet.add(svc)
    }
    svcSet.add('global')
    const rolesByService: Record<string, FlatRolesMap> = {}
    await Promise.all(
      [...svcSet].map(async (svc) => {
        rolesByService[svc] = (await redisRbacRepository.getRoles(svc)) ?? {}
      }),
    )

    // Classify each GROUP once → does it grant global power / a service wildcard,
    // which services it reaches, and the group→role→perm grant paths.
    const groupPower = new Map<string, GroupPower>()
    for (const [name, def] of Object.entries(groupDefs)) {
      const gp: GroupPower = { globalPower: false, wildcardServices: new Set(), services: new Set(), paths: [] }
      for (const [svc, roles] of Object.entries(def)) {
        for (const role of roles ?? []) {
          const perms = rolesByService[svc]?.[role] ?? []
          const isWild = perms.includes('*')
          if (svc === 'global') {
            if (role === 'super_admin' || isWild) {
              gp.globalPower = true
              gp.paths.push({ group: name, service: 'global', role, summary: `${name} → global:${role} → *` })
            } else {
              gp.paths.push({ group: name, service: 'global', role, summary: `${name} → global:${role}` })
            }
          } else {
            gp.services.add(svc)
            if (isWild) {
              gp.wildcardServices.add(svc)
              gp.paths.push({ group: name, service: svc, role, summary: `${name} → ${svc}:${role} → *` })
            } else {
              gp.paths.push({ group: name, service: svc, role, summary: `${name} → ${svc}:${role}` })
            }
          }
        }
      }
      groupPower.set(name, gp)
    }

    // Invert the org-admin roster: email(lower) → orgs they are rostered admin of.
    const rosterByEmail = new Map<string, Set<string>>()
    for (const [org, roster] of Object.entries(orgAdminMap)) {
      for (const e of roster) {
        const key = e.toLowerCase()
        if (!rosterByEmail.has(key)) rosterByEmail.set(key, new Set())
        rosterByEmail.get(key)!.add(org)
      }
    }

    // Enrichment indexes (best-effort — never fail the review on these).
    let lastSeen: Record<string, string> = {}
    let lastPriv: Record<string, string> = {}
    try {
      const redis = getRedisClient()
      const [ls, lp] = await Promise.all([
        redis.hgetall('auth:audit:last_seen'),
        redis.hgetall('auth:audit:last_privileged_action'),
      ])
      lastSeen = ls || {}
      lastPriv = lp || {}
    } catch { /* enrichment only */ }

    const { map: mfaByEmail, ok: mfaOk } = await this.mfaMap()

    const now = Date.now()
    const identities: AccessReviewIdentityOut[] = []

    for (const [email, b] of bindings) {
      const grps = b.groups ?? []

      let globalPower = false
      const wildcardServices = new Set<string>()
      const reached = new Set<string>()
      let paths: AccessReviewGrantPath[] = []
      let orphaned = false

      for (const g of grps) {
        const gp = groupPower.get(g)
        if (!gp) {
          // A group in the identity's metadata with no definition in rbac:groups.
          if (g !== 'users') orphaned = true
          continue
        }
        if (gp.globalPower) globalPower = true
        for (const s of gp.wildcardServices) wildcardServices.add(s)
        for (const s of gp.services) reached.add(s)
        for (const p of gp.paths) paths.push(p)
      }

      // Org-admin is POSITIONAL: rostered admin AND member of that org.
      const memberOrgs = new Set<string>([
        ...(b.organizations ?? []),
        ...(b.primaryOrganization ? [b.primaryOrganization] : []),
      ])
      const rostered = rosterByEmail.get(email.toLowerCase())
      const adminOrgs = rostered ? [...rostered].filter((o) => memberOrgs.has(o)) : []
      const isOrgAdmin = adminOrgs.length > 0

      // A global super-admin (T0) can reach EVERY service, not just the ones
      // their groups explicitly bind — report the true blast radius.
      if (globalPower) for (const s of services) reached.add(s)
      const reach = reached.size

      // Tier ladder — highest power wins; below the ladder = not privileged.
      let tier: number | null = null
      if (globalPower) tier = 0
      else if (wildcardServices.size > 0) tier = 1
      else if (isOrgAdmin) tier = 2
      else if (reach >= BROAD_REACH_MIN) tier = 3
      if (tier === null) continue

      // Positional org-admin has no group→role→perm chain — surface a synthetic
      // path so "how they got it" is not blank (drawer + list "how" column).
      if (isOrgAdmin) {
        for (const o of adminOrgs) {
          paths.push({ group: `org:${o}`, summary: `org-admin of ${o} (positional — org roster, not a group role)` })
        }
      }

      // Strongest grant first (frontend uses paths[0] as the "how" summary).
      paths = paths.sort((a, b2) => pathRank(a) - pathRank(b2)).slice(0, MAX_PATHS)

      const lastActive = lastSeen[email] ?? null
      const lastPrivileged = lastPriv[email] ?? null

      // Provenance is best-effort (bounded per-target trail).
      const prov = await this.provenance(email)
      const grantedBy = prov?.grantedBy ?? null
      const grantedAt = prov?.at ?? null
      const selfGranted = !!grantedBy && grantedBy.toLowerCase() === email.toLowerCase()

      const mfaKnown = mfaByEmail.has(email)
      const mfa = mfaByEmail.get(email) ?? false
      // Only assert "no MFA" when the credential pass actually ran; on a Kratos
      // blip we must not flag every power holder as un-enrolled.
      const noMfa = mfaOk && (mfaKnown ? mfa === false : true)

      const flags: string[] = []
      if (globalPower) flags.push('global-super-admin')
      if (wildcardServices.size > 0) flags.push('wildcard')
      if (reach >= SPRAWL_MIN) flags.push('sprawl')
      if (isOrgAdmin && reach >= BROAD_REACH_MIN) flags.push('org-admin-broad-reach')
      if (isDormant(lastActive, now)) flags.push('dormant')
      if (selfGranted) flags.push('self-granted')
      if (noMfa) flags.push('no-mfa')
      if (b.active === false) flags.push('inactive-retaining-power')
      if (orphaned) flags.push('orphaned-group')

      const powerScore = scoreFor(tier, {
        wildcardServiceCount: wildcardServices.size,
        orgCount: adminOrgs.length,
        reach,
      })

      const svcList = [...reached].sort()

      identities.push({
        id: b.id,
        email,
        name: b.name ?? undefined,
        tier,
        tierLabel: `T${tier}`,
        reach,
        services: svcList,
        reachServices: svcList,
        groups: grps,
        flags,
        mfa,
        active: b.active,
        lastActive,
        lastPrivilegedAction: lastPrivileged,
        grantedBy,
        grantedAt,
        provenance: prov ? { grantedBy, at: grantedAt } : null,
        selfGranted,
        powerScore,
        score: powerScore,
        paths,
        powerPaths: paths.map((p) => p.summary),
      })
    }

    // Server-side ranking mirrors the frontend: score desc, tier asc, reach desc.
    identities.sort(
      (a, b) => b.powerScore - a.powerScore || a.tier - b.tier || b.reach - a.reach,
    )

    const canDoAnything = identities.filter((i) => i.tier === 0 || i.tier === 1).length
    const dormant = identities.filter((i) => i.flags.includes('dormant')).length
    const selfGrantedCount = identities.filter((i) => i.selfGranted).length
    const noMfaCount = identities.filter((i) => i.flags.includes('no-mfa')).length

    const summary: AccessReviewSummary = {
      totalPrivileged: identities.length,
      total: identities.length,
      canDoAnything,
      selfGranted: selfGrantedCount,
      dormant,
      noMfa: noMfaCount,
      withoutMfa: noMfaCount,
      computedAt: new Date().toISOString(),
    }

    return {
      summary,
      identities,
      limits: {
        bounded: true,
        note: 'Provenance and "last active" are bounded by the audit stream cap (Redis-only store); this is not tamper-evident.',
      },
    }
  }

  /**
   * MFA for the whole directory via a PAGINATED credential pass — every page,
   * with include_credential, so it is NOT truncated at getUsers()'s 250 rows.
   * Best-effort: on Kratos failure returns ok:false so the caller degrades
   * (no false "no-MFA" alarms) rather than emptying the review.
   */
  private async mfaMap(): Promise<{ map: Map<string, boolean>; ok: boolean }> {
    const map = new Map<string, boolean>()
    try {
      let pageToken: string | undefined
      for (let page = 0; page < 1000; page++) {
        const resp = await kratosService.listIdentities(500, pageToken, undefined, [
          'totp',
          'webauthn',
          'lookup_secret',
        ])
        for (const ident of resp.identities) {
          const email = ident.traits?.email as string | undefined
          if (!email) continue
          map.set(email, kratosService.mfaFromCredentials(ident.credentials))
        }
        const next = resp.nextPageToken
        if (!next || next === pageToken || resp.identities.length === 0) break
        pageToken = next
      }
      return { map, ok: true }
    } catch {
      return { map, ok: false }
    }
  }

  /**
   * Best-effort grant provenance from the per-target audit trail
   * (auth:audit:target:<email>). Returns the most recent access-changing event
   * that targeted this identity — its actor is the grantor. Never throws.
   */
  private async provenance(email: string): Promise<{ grantedBy: string | null; at: string | null } | null> {
    try {
      const events = await auditEventService.query({ target: email, kind: 'change', limit: 25 })
      // newest first
      const grant = events.find(isGrantLike) ?? events[0]
      if (!grant) return null
      const grantedBy = grant.who && grant.who !== 'anon' && grant.who !== 'system' ? grant.who : null
      return { grantedBy, at: grant.ts ?? null }
    } catch {
      return null
    }
  }
}

// ── Pure helpers ───────────────────────────────────────────────────────────
function pathRank(p: AccessReviewGrantPath): number {
  if (p.service === 'global') return 0
  if (p.summary.endsWith('→ *')) return 1
  if (p.group.startsWith('org:')) return 2
  return 3
}

function scoreFor(
  tier: number,
  { wildcardServiceCount, orgCount, reach }: { wildcardServiceCount: number; orgCount: number; reach: number },
): number {
  // Reach bonus applies across tiers ([P1-5]: "… + reach bonus").
  const reachBonus = reach
  switch (tier) {
    case 0: return 100 + reachBonus
    case 1: return 60 * Math.max(1, wildcardServiceCount) + reachBonus
    case 2: return 40 * Math.max(1, orgCount) + reachBonus
    case 3: return 15 + 3 * reach + reachBonus
    default: return 0
  }
}

function isDormant(lastActive: string | null, now: number): boolean {
  if (!lastActive) return true
  const t = new Date(lastActive).getTime()
  if (Number.isNaN(t)) return true
  return now - t > DORMANT_MS
}

/** A "done-to" event that plausibly granted power to the target. */
function isGrantLike(e: { verb?: string; changes?: { added?: string[]; flags?: string[] } }): boolean {
  if ((e.changes?.added?.length ?? 0) > 0) return true
  if (e.changes?.flags?.some((f) => f === 'grants_super_admin' || f === 'wildcard_permission')) return true
  return e.verb === 'assign' || e.verb === 'grant'
}

export const accessReviewService = new AccessReviewService()
