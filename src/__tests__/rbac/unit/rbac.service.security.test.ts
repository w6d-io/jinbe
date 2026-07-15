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

// Mock OPA — assertSuperAdmin/requireSuperAdmin lookups go through this.
vi.mock('../../../services/opa.service.js', () => ({
  opaService: {
    simulate: vi.fn(),
    getUserInfo: vi.fn(),
  },
}))

import { RbacService } from '../../../services/rbac.service.js'
import { opaService } from '../../../services/opa.service.js'
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
  // groupGrantsAdminPower / isAdminPowerGroup
  // src/services/rbac.service.ts:205-207, 217-236
  // ===========================================================================
  describe('isAdminPowerGroup (rbac.service.ts:205-207, 217-236)', () => {
    it('returns true when the group has global super_admin (rbac.service.ts:222)', async () => {
      await redisMock.hset(
        'rbac:groups',
        'super_admins',
        JSON.stringify({ global: ['super_admin'] }),
      )

      await expect(service.isAdminPowerGroup('super_admins')).resolves.toBe(true)
    })

    it('returns true when a service-scoped role grants the wildcard "*" permission (rbac.service.ts:226-234)', async () => {
      await redisMock.hset(
        'rbac:groups',
        'jinbe_admins',
        JSON.stringify({ jinbe: ['admin'] }),
      )
      // role 'admin' resolves to the wildcard permission
      await redisMock.set(
        'rbac:roles:jinbe',
        JSON.stringify({ admin: ['*'], viewer: ['read'] }),
      )

      await expect(service.isAdminPowerGroup('jinbe_admins')).resolves.toBe(true)
    })

    it('returns false when no service-scoped role contains "*" (rbac.service.ts:230-233)', async () => {
      await redisMock.hset(
        'rbac:groups',
        'jinbe_viewers',
        JSON.stringify({ jinbe: ['viewer'] }),
      )
      await redisMock.set(
        'rbac:roles:jinbe',
        JSON.stringify({ admin: ['*'], viewer: ['read'] }),
      )

      await expect(service.isAdminPowerGroup('jinbe_viewers')).resolves.toBe(false)
    })

    it('returns false when the group does not exist (rbac.service.ts:218-219)', async () => {
      await expect(service.isAdminPowerGroup('does_not_exist')).resolves.toBe(false)
    })
  })

  // ===========================================================================
  // assertSuperAdmin / requireSuperAdmin
  // src/services/rbac.service.ts:165-176, 213-215
  // ===========================================================================
  describe('assertSuperAdmin (rbac.service.ts:213-215, 165-176)', () => {
    it('throws 401 when the actor email is missing (rbac.service.ts:166-168)', async () => {
      await expect(service.assertSuperAdmin('do something dangerous')).rejects.toMatchObject({
        message: 'Authentication required for this operation',
        statusCode: 401,
      })
      // OPA must not be queried without an actor — saves a round-trip and
      // prevents an unauthenticated path from reaching the policy engine.
      expect(opaService.simulate).not.toHaveBeenCalled()
    })

    it('throws 401 when the actor object is present but email is empty (rbac.service.ts:166)', async () => {
      await expect(
        service.assertSuperAdmin('reason', { email: '' }),
      ).rejects.toMatchObject({ statusCode: 401 })
      expect(opaService.simulate).not.toHaveBeenCalled()
    })

    it('resolves silently when OPA reports super_admin: true (rbac.service.ts:169-175)', async () => {
      vi.mocked(opaService.simulate).mockResolvedValueOnce({
        allow: true,
        matching_rules: [],
        groups: ['super_admins'],
        roles: ['super_admin'],
        permissions: ['*'],
        super_admin: true,
      })

      await expect(
        service.assertSuperAdmin('do x', { email: 'root@example.com' }),
      ).resolves.toBeUndefined()

      expect(opaService.simulate).toHaveBeenCalledWith(
        'root@example.com',
        'jinbe',
        'POST',
        '/api/admin/rbac/groups',
      )
    })

    it('throws 403 when OPA reports super_admin: false (rbac.service.ts:170-174)', async () => {
      vi.mocked(opaService.simulate).mockResolvedValueOnce({
        allow: true,
        matching_rules: [],
        groups: ['admins'],
        roles: ['admin'],
        permissions: ['*'],
        super_admin: false,
      })

      await expect(
        service.assertSuperAdmin('elevate role', { email: 'admin@example.com' }),
      ).rejects.toMatchObject({
        statusCode: 403,
        message: 'Only super_admins may elevate role',
      })
    })

    it('throws 403 when OPA returns null (no result) (rbac.service.ts:170)', async () => {
      vi.mocked(opaService.simulate).mockResolvedValueOnce(null)

      await expect(
        service.assertSuperAdmin('do y', { email: 'someone@example.com' }),
      ).rejects.toMatchObject({
        statusCode: 403,
        message: 'Only super_admins may do y',
      })
    })
  })

  // ===========================================================================
  // groupGrantsGlobalPower (rbac.service.ts)
  // Distinct from groupGrantsAdminPower: TRUE only for GLOBAL power
  // (global super_admin, or a global role resolving to "*"), FALSE for a
  // merely service-scoped wildcard role.
  // ===========================================================================
  describe('groupGrantsGlobalPower', () => {
    it('returns true when the group has the global super_admin role', async () => {
      await redisMock.hset(
        'rbac:groups',
        'super_admins',
        JSON.stringify({ global: ['super_admin'] }),
      )
      await expect(service.groupGrantsGlobalPower('super_admins')).resolves.toBe(true)
    })

    it('returns true when a global role resolves to the wildcard "*"', async () => {
      await redisMock.hset(
        'rbac:groups',
        'global_admins',
        JSON.stringify({ global: ['platform_admin'] }),
      )
      await redisMock.set(
        'rbac:roles:global',
        JSON.stringify({ platform_admin: ['*'], auditor: ['read'] }),
      )
      await expect(service.groupGrantsGlobalPower('global_admins')).resolves.toBe(true)
    })

    it('returns FALSE for a service-scoped wildcard role (org-scoped admin, not global)', async () => {
      // jinbe_admins holds "*" for the jinbe SERVICE only — admin power, but
      // NOT global. groupGrantsAdminPower would return true here; the global
      // check must not.
      await redisMock.hset(
        'rbac:groups',
        'jinbe_admins',
        JSON.stringify({ jinbe: ['admin'] }),
      )
      await redisMock.set(
        'rbac:roles:jinbe',
        JSON.stringify({ admin: ['*'], viewer: ['read'] }),
      )
      await expect(service.groupGrantsGlobalPower('jinbe_admins')).resolves.toBe(false)
      // sanity: it IS admin-power, just not global
      await expect(service.isAdminPowerGroup('jinbe_admins')).resolves.toBe(true)
    })

    it('returns false when the group does not exist', async () => {
      await expect(service.groupGrantsGlobalPower('nope')).resolves.toBe(false)
    })

    it('returns FALSE for an empty global array { global: [] }', async () => {
      await redisMock.hset(
        'rbac:groups',
        'empty_global',
        JSON.stringify({ global: [] }),
      )
      await expect(service.groupGrantsGlobalPower('empty_global')).resolves.toBe(false)
    })

    it('returns FALSE for a named global role that resolves to non-wildcard perms', async () => {
      await redisMock.hset(
        'rbac:groups',
        'global_auditors',
        JSON.stringify({ global: ['auditor'] }),
      )
      await redisMock.set(
        'rbac:roles:global',
        JSON.stringify({ auditor: ['read'], platform_admin: ['*'] }),
      )
      await expect(service.groupGrantsGlobalPower('global_auditors')).resolves.toBe(false)
    })

    it('returns FALSE for a non-super_admin global role when getRoles("global") is null', async () => {
      // No rbac:roles:global stored — a named (non-literal) global role cannot
      // be resolved, so we must NOT claim global power. (The literal
      // super_admin still trips earlier, without needing the roles map.)
      await redisMock.hset(
        'rbac:groups',
        'unresolvable_global',
        JSON.stringify({ global: ['platform_admin'] }),
      )
      await expect(service.groupGrantsGlobalPower('unresolvable_global')).resolves.toBe(false)
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
      // OPA reports the org admin is NOT a super_admin (assertSuperAdmin → 403).
      vi.mocked(opaService.simulate).mockResolvedValue({
        allow: true,
        matching_rules: [],
        groups: ['org_admins'],
        roles: ['admin'],
        permissions: ['*'],
        super_admin: false,
      })
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
