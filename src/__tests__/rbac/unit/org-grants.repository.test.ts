import { describe, it, expect, beforeEach, vi } from 'vitest'

// org_grants[org][email] = [group] — stored next to the other rbac keys, one hash field per org,
// each write under that org's lock.

const { redisMock, redisModule, lock } = vi.hoisted(() => {
  class InlineRedisMock {
    hashStore = new Map<string, Map<string, string>>()
    failReads = false
    async hget(key: string, field: string) { return this.hashStore.get(key)?.get(field) ?? null }
    async hset(key: string, field: string, value: string) {
      if (!this.hashStore.has(key)) this.hashStore.set(key, new Map())
      this.hashStore.get(key)!.set(field, value)
      return 1
    }
    async hdel(key: string, ...fields: string[]) {
      let c = 0
      for (const f of fields) if (this.hashStore.get(key)?.delete(f)) c++
      return c
    }
    async hgetall(key: string) {
      if (this.failReads) throw new Error('ECONNREFUSED')
      return Object.fromEntries(this.hashStore.get(key)?.entries() ?? [])
    }
  }
  const mock = new InlineRedisMock()
  return {
    redisMock: mock,
    redisModule: { getRedisClient: () => mock },
    lock: vi.fn((_name: string, fn: () => Promise<unknown>) => fn()),
  }
})

vi.mock('../../../services/redis-client.service.js', () => redisModule)
vi.mock('../../../services/redis-lock.js', () => ({ withRedisLock: lock }))

import { orgGrantsRepository } from '../../../services/org-grants.repository.js'

const ACME = '11111111-1111-1111-1111-111111111111'
const GLOBEX = '22222222-2222-2222-2222-222222222222'

describe('orgGrantsRepository', () => {
  beforeEach(() => {
    redisMock.hashStore.clear()
    redisMock.failReads = false
    lock.mockClear()
  })

  it('is empty when nothing was granted', async () => {
    expect(await orgGrantsRepository.getAll()).toEqual({})
  })

  it('stores a member grant under rbac:org_grants, per org, lowercased and deduped', async () => {
    await orgGrantsRepository.setForMember(ACME, 'Bob@Acme.test', ['fleet-viewers', 'fleet-viewers', 'kuma-readers'])
    await orgGrantsRepository.setForMember(GLOBEX, 'bob@acme.test', ['kuma-readers'])

    expect(JSON.parse(redisMock.hashStore.get('rbac:org_grants')!.get(ACME)!)).toEqual({
      'bob@acme.test': ['fleet-viewers', 'kuma-readers'],
    })
    expect(await orgGrantsRepository.getAll()).toEqual({
      [ACME]: { 'bob@acme.test': ['fleet-viewers', 'kuma-readers'] },
      [GLOBEX]: { 'bob@acme.test': ['kuma-readers'] },
    })
    expect(await orgGrantsRepository.getForMember(ACME, 'BOB@acme.test')).toEqual(['fleet-viewers', 'kuma-readers'])
  })

  it('writes under a per-org lock and returns what was there before', async () => {
    await orgGrantsRepository.setForMember(ACME, 'bob@acme.test', ['a'])
    const before = await orgGrantsRepository.setForMember(ACME, 'bob@acme.test', ['b'])
    expect(before).toEqual(['a'])
    expect(lock).toHaveBeenCalledWith(`org_grants:${ACME}`, expect.any(Function))
  })

  it('an empty list drops the member, and an org with nobody left drops its field', async () => {
    await orgGrantsRepository.setForMember(ACME, 'bob@acme.test', ['a'])
    await orgGrantsRepository.setForMember(ACME, 'bob@acme.test', [])
    expect(redisMock.hashStore.get('rbac:org_grants')!.has(ACME)).toBe(false)
    expect(await orgGrantsRepository.getAll()).toEqual({})
  })

  it('ignores malformed stored values rather than publishing them', async () => {
    redisMock.hashStore.set('rbac:org_grants', new Map([
      [ACME, '{"bob@acme.test":["a", 3, ""],"eve@acme.test":"nope"}'],
      [GLOBEX, 'not json'],
    ]))
    expect(await orgGrantsRepository.getAll()).toEqual({ [ACME]: { 'bob@acme.test': ['a'] } })
  })

  it('throws when Redis cannot be read — never an empty map', async () => {
    redisMock.failReads = true
    await expect(orgGrantsRepository.getAll()).rejects.toThrow()
  })
})
