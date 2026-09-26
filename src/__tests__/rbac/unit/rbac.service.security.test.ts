import { describe, it, expect, beforeEach, vi } from 'vitest'

/**
 * Locks down the security helpers exposed by RbacService:
 *   - isAdminPowerGroup    (src/services/rbac.service.ts:205-207)
 *   - groupGrantsAdminPower (private — exercised via isAdminPowerGroup,
 *                            src/services/rbac.service.ts:217-236)
 *   - assertSuperAdmin     (src/services/rbac.service.ts:213-215, wraps
 *                            requireSuperAdmin at lines 165-176)
 *
 * Both are called by the user-group assignment endpoint and by every
 * RbacService mutation that touches a system resource, so behaviour drift
 * here is a security regression.
 */

const { redisMock, redisModule } = vi.hoisted(() => {
  class InlineRedisMock {
    private store = new Map<string, string>()
    private hashStore = new Map<string, Map<string, string>>()
    private setStore = new Map<string, Set<string>>()
    async get(key: string) { return this.store.get(key) ?? null }
    async set(key: string, value: string) { this.store.set(key, value); return 'OK' as const }
    async del(...keys: string[]) { let c = 0; for (const k of keys) { if (this.store.delete(k)) c++; if (this.hashStore.delete(k)) c++; if (this.setStore.delete(k)) c++ } return c }
    async hget(key: string, field: string) { return this.hashStore.get(key)?.get(field) ?? null }
    async hset(key: string, field: string, value: string) { if (!this.hashStore.has(key)) this.hashStore.set(key, new Map()); const isNew = !this.hashStore.get(key)!.has(field); this.hashStore.get(key)!.set(field, value); return isNew ? 1 : 0 }
    async hdel(key: string, ...fields: string[]) { const h = this.hashStore.get(key); if (!h) return 0; let c = 0; for (const f of fields) { if (h.delete(f)) c++ } return c }
    async hgetall(key: string) { const h = this.hashStore.get(key); if (!h) return {}; return Object.fromEntries(h.entries()) }
    async sadd(key: string, ...members: string[]) { if (!this.setStore.has(key)) this.setStore.set(key, new Set()); let c = 0; for (const m of members) { if (!this.setStore.get(key)!.has(m)) { this.setStore.get(key)!.add(m); c++ } } return c }
    async srem(key: string, ...members: string[]) { const s = this.setStore.get(key); if (!s) return 0; let c = 0; for (const m of members) { if (s.delete(m)) c++ } return c }
    async smembers(key: string) { const s = this.setStore.get(key); return s ? Array.from(s) : [] }
    async sismember(key: string, member: string) { const s = this.setStore.get(key); return s?.has(member) ? 1 : 0 }
    async ping() { return 'PONG' }
    async quit() { return 'OK' as const }
    clear() { this.store.clear(); this.hashStore.clear(); this.setStore.clear() }
  }
  const mock = new InlineRedisMock()
  return {
    redisMock: mock,
    redisModule: {
      redisClientService: { getClient: () => mock, isHealthy: vi.fn().mockResolvedValue(true), disconnect: vi.fn().mockResolvedValue(undefined), isConnected: true },
      getRedisClient: () => mock,
    },
  }
})

vi.mock('../../../services/redis-client.service.js', () => redisModule)

// kratos.service is imported by rbac.service even though these helpers don't
// touch Kratos directly — keep the mock surface minimal. getUserGroups /
// updateUserGroups are exercised by the J1 end-to-end case below, which drives
// the real userGroupsService gate through the real rbacService.
vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    listIdentities: vi.fn().mockResolvedValue({ identities: [] }),
    getAllIdentitiesWithGroups: vi.fn().mockResolvedValue(new Map()),
    removeGroupFromAllUsers: vi.fn().mockResolvedValue(0),
    hasMFA: vi.fn().mockResolvedValue(false),
    getUserGroups: vi.fn().mockResolvedValue([]),
    updateUserGroups: vi.fn().mockResolvedValue(undefined),
  },
}))

// The gate asks OPA whether the actor holds admin.membership:write in jinbe; the J1 case's gates read
// the group catalogue (see the helper for why one catalogue rather than independent predicates).
vi.mock('../../../services/group-catalogue.js', async () =>
  (await import('../../helpers/group-catalogue-mock.js')).groupCatalogueMock())
vi.mock('../../../authz/opa.js', () => ({ holdsInJinbe: vi.fn() }))

// The pre-image of a group change comes from the store that decides, so the J1 case below needs it
// mocked: unmocked, the guard it exercises is never reached — the read fails closed first.
vi.mock('../../../services/organisation-store.js', () => ({
  groupsForSubjects: vi.fn(async () => new Map([['target-1', []]])),
  addToGroup: vi.fn(async () => {}),
  applyGroupChange: vi.fn(async () => {}),
  removeFromGroup: vi.fn(async () => {}),
  allGroupMemberships: vi.fn(async () => new Map()),
  allEntitlements: vi.fn(async () => new Map()),
  organisationStoreConfigured: vi.fn(() => true),
}))

import { RbacService } from '../../../services/rbac.service.js'
import { holdsInJinbe } from '../../../authz/opa.js'
import { kratosService } from '../../../services/kratos.service.js'
import { userGroupsService, type ResolvedIdentity } from '../../../services/user-groups.service.js'

describe('RbacService - security helpers', () => {
  let service: RbacService

  beforeEach(async () => {
    vi.clearAllMocks()
    redisMock.clear()
    service = new RbacService()
  })

  // ===========================================================================
  // assertSuperAdmin / requireSuperAdmin
  // src/services/rbac.service.ts:165-176, 213-215
  // ===========================================================================
  describe('assertSuperAdmin (rbac.service.ts:213-215, 165-176)', () => {
    it('throws 401 when the actor is not identified', async () => {
      await expect(service.assertSuperAdmin('do something dangerous')).rejects.toMatchObject({
        message: 'Authentication required for this operation',
        statusCode: 401,
      })
      expect(holdsInJinbe).not.toHaveBeenCalled()
    })

    it('throws 401 when no address is presented (OPA bindings are keyed on it)', async () => {
      await expect(
        service.assertSuperAdmin('reason', { id: 'subject-root' }),
      ).rejects.toMatchObject({ statusCode: 401 })
      expect(holdsInJinbe).not.toHaveBeenCalled()
    })

    it('resolves when the actor holds the permission to hand out a group', async () => {
      vi.mocked(holdsInJinbe).mockResolvedValueOnce(true)

      await expect(
        service.assertSuperAdmin('do x', { id: 'subject-root', email: 'root@example.com' }),
      ).resolves.toBeUndefined()

      expect(holdsInJinbe).toHaveBeenCalledWith('root@example.com', 'admin.membership:write')
    })

    it('throws 403 when the actor does not hold it', async () => {
      vi.mocked(holdsInJinbe).mockResolvedValueOnce(false)

      await expect(
        service.assertSuperAdmin('elevate role', { id: 'subject-admin', email: 'admin@example.com' }),
      ).rejects.toMatchObject({
        statusCode: 403,
        message: 'Only admin.membership:write may elevate role',
      })
    })

    it('throws 503 when OPA cannot be asked, rather than deciding without it', async () => {
      // "Nobody is powerful" and "I could not tell" are opposite facts. Answering 403 here would
      // read as a missing right; answering 200 would authorize on ignorance.
      vi.mocked(holdsInJinbe).mockRejectedValueOnce(new Error('OPA is unreachable'))

      await expect(
        service.assertSuperAdmin('do y', { id: 'subject-someone', email: 'someone@example.com' }),
      ).rejects.toMatchObject({ statusCode: 503 })
    })
  })

  // ===========================================================================
  // J1 — org-scoped ("*"-in-org) admin CANNOT grant a GLOBAL group.
  // Drives the real userGroupsService gate through the real rbacService so the
  // cross-tenant escalation backstop cannot be mocked away. A regression here
  // means an org admin holding org "*" can mint a global super_admin.
  // ===========================================================================
  describe('J1 — org-scoped admin cannot assign the global super_admins group', () => {
    const TARGET: ResolvedIdentity = {
      id: 'target-1',
      email: 'target@example.com',
      organizationId: 'org-1',
    }
    // The actor is an org admin holding org "*", but is NOT a global super_admin.
    const ORG_ADMIN_ACTOR = { email: 'org-admin@example.com', ip: '10.0.0.1' }

    beforeEach(async () => {
      // super_admins is a GLOBAL group.
      await redisMock.hset(
        'rbac:groups',
        'super_admins',
        JSON.stringify({ global: ['super_admin'] }),
      )
    })

    it('blocks with 422 privilege_escalation_blocked despite the actor holding org "*"', async () => {
      const result = await userGroupsService.applyGroupUpdate({
        identity: TARGET,
        newGroups: ['super_admins'],
        actor: ORG_ADMIN_ACTOR,
        // Org-scoped policy: actor holds "*" for THIS organization only.
        privilegePolicy: { kind: 'wildcard_in_org', orgId: 'org-1' },
        auditEventType: 'organization_user.groups_changed',
      })

      expect(result.ok).toBe(false)
      if (!result.ok) {
        expect(result.status).toBe(422)
        expect(result.body.error).toBe('privilege_escalation_blocked')
        expect(result.body.blockingGroup).toBe('super_admins')
      }
      // The escalation must be refused before Kratos is mutated.
      expect(kratosService.updateUserGroups).not.toHaveBeenCalled()
    })
  })
})
