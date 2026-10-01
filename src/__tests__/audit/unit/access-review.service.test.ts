import { describe, it, expect, beforeEach, vi } from 'vitest'

// Hoisted mock fns — referenced by vi.mock (hoisted) AND re-primed per test.
const H = vi.hoisted(() => ({
  getAllIdentitiesWithBindings: vi.fn(),
  listIdentities: vi.fn(),
  mfaFromCredentials: vi.fn((creds: any) => {
    const c = creds || {}
    return !!(
      c.totp?.config?.totp_url ||
      c.webauthn?.config?.credentials?.length ||
      c.lookup_secret?.config?.recovery_codes?.length
    )
  }),
  getGroups: vi.fn(),
  getRoles: vi.fn(),
  getServices: vi.fn(),
  getOrgRoles: vi.fn(),
  getAssignments: vi.fn(),
  query: vi.fn(),
  hgetall: vi.fn(),
}))

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    getAllIdentitiesWithBindings: H.getAllIdentitiesWithBindings,
    listIdentities: H.listIdentities,
    mfaFromCredentials: H.mfaFromCredentials,
  },
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: H.getGroups,
    getRoles: H.getRoles,
    getServices: H.getServices,
    getOrgRoles: H.getOrgRoles,
  },
}))
vi.mock('../../../services/org-roles.repository.js', () => ({
  orgRolesRepository: { getAll: H.getAssignments },
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { query: H.query },
}))
vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({ hgetall: H.hgetall }),
  redisClientService: {
    getClient: () => ({ hgetall: H.hgetall }),
    isHealthy: () => Promise.resolve(true),
    disconnect: () => Promise.resolve(),
    isConnected: true,
  },
}))

import { accessReviewService } from '../../../services/access-review.service.js'
import { roleDefinitions, orgRoleDefinitions } from '../../../policy/roles.js'

// ── Fixtures ─────────────────────────────────────────────────────────────────
const GROUPS: Record<string, Record<string, string[]>> = {
  super_admins:   { jinbe: ['super_admin'] },      // T0 (every platform permission)
  billing_admins: { billing: ['admin'] },          // T1 (every billing permission)
  broad:          { svcA: ['member'], svcB: ['member'], svcC: ['member'] }, // T3 reach 3, no whole service
  viewers:        { reporting: ['viewer'] },        // no power (reach 1)
  users:          {},
}
const ROLES: Record<string, Record<string, string[]>> = {
  jinbe:     roleDefinitions(),
  billing:   { admin: ['billing:read', 'billing:write'], viewer: ['billing:read'] },
  reporting: { viewer: ['reporting:read'], editor: ['reporting:read', 'reporting:write'] },
  svcA:      { member: ['svcA:read'], admin: ['svcA:read', 'svcA:write'] },
  svcB:      { member: ['svcB:read'], admin: ['svcB:read', 'svcB:write'] },
  svcC:      { member: ['svcC:read'], admin: ['svcC:read', 'svcC:write'] },
}
const SERVICES = ['billing', 'reporting', 'svcA', 'svcB', 'svcC']

function binding(id: string, groups: string[], extra: Partial<{ organizations: string[]; primaryOrganization: string | null; active: boolean; name: string }> = {}) {
  return {
    groups,
    organizations: extra.organizations ?? [],
    primaryOrganization: extra.primaryOrganization ?? null,
    active: extra.active ?? true,
    id,
    name: extra.name ?? id,
  }
}

function standardBindings() {
  return new Map<string, ReturnType<typeof binding>>([
    ['t0@ex.com', binding('id-t0', ['super_admins', 'users'], { name: 'Zero' })],
    ['t1@ex.com', binding('id-t1', ['billing_admins', 'users'], { name: 'One' })],
    // T2 holds an org role only — invisible to a group→role walk.
    ['t2@ex.com', binding('id-t2', ['users'], { organizations: ['org-1'], primaryOrganization: 'org-1', name: 'Two' })],
    ['t3@ex.com', binding('id-t3', ['broad', 'users'], { name: 'Three' })],
    ['plain@ex.com', binding('id-p', ['viewers', 'users'], { name: 'Plain' })],
  ])
}

/** Prime the standard directory. Call at the top of each test (mocks are cleared per test). */
function primeStandard() {
  H.getGroups.mockResolvedValue(GROUPS)
  H.getRoles.mockImplementation(async (svc: string) => ROLES[svc] ?? null)
  H.getServices.mockResolvedValue(SERVICES)
  H.getOrgRoles.mockResolvedValue(orgRoleDefinitions())
  H.getAssignments.mockResolvedValue({ 'org-1': { 'id-t2': ['jinbe:owner'] } })
  H.getAllIdentitiesWithBindings.mockResolvedValue(standardBindings())
  H.listIdentities.mockResolvedValue({
    identities: [...standardBindings()].map(([email, b]) => ({ id: b.id, traits: { email }, credentials: {} })),
    nextPageToken: undefined,
  })
  H.query.mockResolvedValue([])
  H.hgetall.mockResolvedValue({})
}

const byEmail = (list: any[], email: string) => list.find((i) => i.email === email)

describe('accessReviewService — tier enumeration ([P1-5])', () => {
  beforeEach(() => accessReviewService.invalidate())

  it('enumerates all four tiers, including the org owner invisible to a group walk', async () => {
    primeStandard()
    const res = await accessReviewService.getAccessReview()

    // Exactly the four privileged identities — the reach-1 viewer is excluded.
    const emails = res.identities.map((i) => i.email).sort()
    expect(emails).toEqual(['t0@ex.com', 't1@ex.com', 't2@ex.com', 't3@ex.com'])
    expect(byEmail(res.identities, 'plain@ex.com')).toBeUndefined()

    expect(byEmail(res.identities, 't0@ex.com').tier).toBe(0)
    expect(byEmail(res.identities, 't1@ex.com').tier).toBe(1)
    expect(byEmail(res.identities, 't3@ex.com').tier).toBe(3)

    // T2: an org role carrying org.members:write ∩ org membership; a group walk alone would drop it.
    const t2 = byEmail(res.identities, 't2@ex.com')
    expect(t2.tier).toBe(2)
    expect(t2.flags).not.toContain('whole-service')
    expect(t2.flags).not.toContain('every-permission')
    expect(t2.paths[0].summary).toContain('manages the members of org-1')

    // Summary rollups.
    expect(res.summary.totalPrivileged).toBe(4)
    expect(res.summary.total).toBe(4)
    expect(res.summary.canDoAnything).toBe(2) // T0 + T1

    // Contract fields the kuma frontend reads.
    const t0 = byEmail(res.identities, 't0@ex.com')
    expect(t0.tierLabel).toBe('T0')
    expect(t0.powerScore).toBeGreaterThan(0)
    expect(t0.score).toBe(t0.powerScore)
    expect(t0.flags).toContain('every-permission')
    const t1 = byEmail(res.identities, 't1@ex.com')
    expect(t1.flags).toContain('whole-service')
    expect(t1.powerPaths.join(' ')).toContain('billing:admin → every permission')
    const t3 = byEmail(res.identities, 't3@ex.com')
    expect(t3.reach).toBe(3)
    expect(t3.reachServices).toEqual(['svcA', 'svcB', 'svcC'])

    expect(res.limits.bounded).toBe(true)
  })

  it('T2 vanishes when the org role is for an org they no longer belong to', async () => {
    primeStandard()
    // t2 holds owner in org-1 but is a member of org-9 only → not an org owner.
    const b = standardBindings()
    b.set('t2@ex.com', binding('id-t2', ['users'], { organizations: ['org-9'], primaryOrganization: 'org-9' }))
    H.getAllIdentitiesWithBindings.mockResolvedValue(b)

    const res = await accessReviewService.getAccessReview()
    expect(byEmail(res.identities, 't2@ex.com')).toBeUndefined()
    expect(res.summary.totalPrivileged).toBe(3)
  })
})

describe('accessReviewService — dormant + self-granted flags', () => {
  beforeEach(() => accessReviewService.invalidate())

  it('flags a dormant power holder and a self-granted one', async () => {
    primeStandard()
    const OLD = new Date(Date.now() - 60 * 24 * 3600 * 1000).toISOString()   // 60d ago
    const RECENT = new Date(Date.now() - 60 * 1000).toISOString()            // 1m ago
    H.hgetall.mockImplementation(async (key: string) =>
      key === 'auth:audit:last_seen' ? { 't0@ex.com': OLD, 't1@ex.com': RECENT } : {},
    )
    // t1 granted itself power (actor == target); nobody else has provenance.
    H.query.mockImplementation(async (opts: { target?: string }) =>
      opts.target === 't1@ex.com'
        ? [{ id: 'e1', ts: RECENT, when: '1m ago', verb: 'assign', who: 't1@ex.com', changes: { resource: 'user', added: ['billing_admins'] } }]
        : [],
    )

    const res = await accessReviewService.getAccessReview()

    const t0 = byEmail(res.identities, 't0@ex.com')
    expect(t0.flags).toContain('dormant') // last-seen 60d ago

    const t1 = byEmail(res.identities, 't1@ex.com')
    expect(t1.flags).not.toContain('dormant') // last-seen 1m ago
    expect(t1.selfGranted).toBe(true)
    expect(t1.flags).toContain('self-granted')
    expect(t1.grantedBy).toBe('t1@ex.com')
    expect(t1.provenance).toEqual({ grantedBy: 't1@ex.com', at: RECENT })

    expect(res.summary.selfGranted).toBe(1)
    expect(res.summary.dormant).toBeGreaterThanOrEqual(1)
  })
})

describe('accessReviewService — fail-closed', () => {
  beforeEach(() => accessReviewService.invalidate())

  it('throws (never returns an empty list) when the directory read fails', async () => {
    primeStandard()
    H.getAllIdentitiesWithBindings.mockRejectedValue(new Error('kratos down'))

    await expect(accessReviewService.getAccessReview()).rejects.toThrow('kratos down')
  })
})
