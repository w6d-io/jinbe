import { describe, it, expect, beforeEach, vi } from 'vitest'

// The org-admin roster is stored and read LOWERCASED (a roster typed "Alice@X" against the identity
// "alice@x" showed as admin and was refused); the OPAL feed keeps every spelling until the policy
// compares without case, and the bindings feed carries a lowercase key beside each address.

const { redisMock, redisModule } = vi.hoisted(() => {
  class InlineRedisMock {
    private hashStore = new Map<string, Map<string, string>>()
    async hget(key: string, field: string) { return this.hashStore.get(key)?.get(field) ?? null }
    async hset(key: string, field: string, value: string) {
      if (!this.hashStore.has(key)) this.hashStore.set(key, new Map())
      const isNew = !this.hashStore.get(key)!.has(field)
      this.hashStore.get(key)!.set(field, value)
      return isNew ? 1 : 0
    }
    async hdel(key: string, ...fields: string[]) {
      const h = this.hashStore.get(key)
      if (!h) return 0
      let c = 0
      for (const f of fields) if (h.delete(f)) c++
      return c
    }
    async hgetall(key: string) {
      const h = this.hashStore.get(key)
      if (!h) return {}
      return Object.fromEntries(h.entries())
    }
    // Raw seed helper for legacy-shape fixtures (bypasses setOrgServiceMapping).
    seedRaw(key: string, field: string, value: string) {
      if (!this.hashStore.has(key)) this.hashStore.set(key, new Map())
      this.hashStore.get(key)!.set(field, value)
    }
    rawValue(key: string, field: string) { return this.hashStore.get(key)?.get(field) ?? null }
    clear() { this.hashStore.clear() }
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

import { redisRbacRepository } from '../../../services/redis-rbac.repository.js'
import { bindingsWithLowercaseKeys, rosterForPolicy } from '../../../services/email-spellings.js'

const KEY = 'rbac:org_admins'
const ORG = '11111111-1111-1111-1111-111111111111'

beforeEach(() => redisMock.clear())

describe('org-admin roster — lowercased, migration-safe', () => {
  it('writes lowercased, trimmed and deduped', async () => {
    await redisRbacRepository.setOrgAdmins(ORG, ['Alice@X.io', ' alice@x.io ', 'BOB@x.io', ''])
    expect(JSON.parse(redisMock.rawValue(KEY, ORG)!)).toEqual(['alice@x.io', 'bob@x.io'])
  })

  it('reads a legacy mixed-case row lowercased — no migration needed', async () => {
    redisMock.seedRaw(KEY, ORG, JSON.stringify(['Alice@X.io', 'alice@x.io']))
    expect(await redisRbacRepository.getOrgAdmins(ORG)).toEqual(['alice@x.io'])
    expect(await redisRbacRepository.getOrgAdminMap()).toEqual({ [ORG]: ['alice@x.io'] })
    // As stored, for the policy feed only.
    expect(await redisRbacRepository.getOrgAdminMapAsStored()).toEqual({ [ORG]: ['Alice@X.io', 'alice@x.io'] })
  })

  it('the policy feed carries the stored, lowercase and identity spellings', () => {
    const out = rosterForPolicy({ [ORG]: ['alice@x.io', 'Carol@X.io'], empty: [] }, ['Alice@X.io', 'dave@x.io'])
    expect(out).toEqual({ [ORG]: ['Alice@X.io', 'Carol@X.io', 'alice@x.io', 'carol@x.io'] })
  })

  it('bindings gain a lowercase key per address, never replacing a real one', () => {
    const out = bindingsWithLowercaseKeys({
      emails: {},
      group_membership: { 'Alice@X.io': ['ops'], 'bob@x.io': ['users'] },
      user_organizations: { 'Alice@X.io': ['acme'] },
      user_organization_primary: { 'Alice@X.io': 'acme' },
    })
    expect(out.group_membership).toEqual({ 'Alice@X.io': ['ops'], 'alice@x.io': ['ops'], 'bob@x.io': ['users'] })
    expect(out.user_organizations).toEqual({ 'Alice@X.io': ['acme'], 'alice@x.io': ['acme'] })
    expect(out.user_organization_primary).toEqual({ 'Alice@X.io': 'acme', 'alice@x.io': 'acme' })
    const clash = bindingsWithLowercaseKeys({ emails: {}, group_membership: { 'A@x.io': ['x'], 'a@x.io': ['y'] }, user_organizations: {}, user_organization_primary: {} })
    expect(clash.group_membership['a@x.io']).toEqual(['y'])
  })
})
