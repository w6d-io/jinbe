import { describe, it, expect, beforeEach, vi } from 'vitest'
import { payrollSite } from './fixtures.js'

// S-1 store: rbac:sites (intent per name), rbac:sites:draft:<name>, rbac:sites:versions:<name>
// (append-only, who/when/note), etag per saved version.

const { redisMock } = vi.hoisted(() => {
  class InlineRedisMock {
    hashes = new Map<string, Map<string, string>>()
    strings = new Map<string, string>()
    lists = new Map<string, string[]>()
    ttl = new Map<string, number>()
    async hget(k: string, f: string) { return this.hashes.get(k)?.get(f) ?? null }
    async hset(k: string, f: string, v: string) {
      if (!this.hashes.has(k)) this.hashes.set(k, new Map())
      this.hashes.get(k)!.set(f, v)
      return 1
    }
    async hdel(k: string, f: string) { return this.hashes.get(k)?.delete(f) ? 1 : 0 }
    async hgetall(k: string) { return Object.fromEntries(this.hashes.get(k)?.entries() ?? []) }
    async get(k: string) { return this.strings.get(k) ?? null }
    async set(k: string, v: string, ...args: unknown[]) {
      this.strings.set(k, v)
      if (args[0] === 'EX') this.ttl.set(k, args[1] as number)
      return 'OK'
    }
    async del(k: string) { return this.strings.delete(k) || this.lists.delete(k) ? 1 : 0 }
    sets = new Map<string, Set<string>>()
    async sadd(k: string, v: string) { if (!this.sets.has(k)) this.sets.set(k, new Set()); this.sets.get(k)!.add(v); return 1 }
    async srem(k: string, v: string) { return this.sets.get(k)?.delete(v) ? 1 : 0 }
    async smembers(k: string) { return [...(this.sets.get(k) ?? [])] }
    async rpush(k: string, v: string) {
      if (!this.lists.has(k)) this.lists.set(k, [])
      this.lists.get(k)!.push(v)
      return this.lists.get(k)!.length
    }
    async lrange(k: string, a: number, b: number) {
      const l = this.lists.get(k) ?? []
      return l.slice(a, b === -1 ? undefined : b + 1)
    }
  }
  return { redisMock: new InlineRedisMock() }
})

vi.mock('../../services/redis-client.service.js', () => ({ getRedisClient: () => redisMock }))
vi.mock('../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => Promise<unknown>) => fn() }))

import { sitesRepository } from '../../sites/repository.js'

describe('sitesRepository', () => {
  beforeEach(() => {
    redisMock.hashes.clear()
    redisMock.strings.clear()
    redisMock.lists.clear()
  })

  it('saves version 1 with an etag and appends a version entry', async () => {
    const rec = await sitesRepository.save(payrollSite(), { by: 'sam@x.test', note: 'first', ifMatch: undefined })
    expect(rec.version).toBe(1)
    expect(rec.etag).toMatch(/^[0-9a-f]{16}$/)
    expect(JSON.parse((await redisMock.hget('rbac:sites', 'payroll'))!).site.name).toBe('payroll')
    const versions = await sitesRepository.versions('payroll')
    expect(versions).toMatchObject([{ v: 1, by: 'sam@x.test', note: 'first', kind: 'save' }])
    expect(typeof versions[0].at).toBe('string')
  })

  it('refuses a stale If-Match and a missing one on an existing site', async () => {
    const first = await sitesRepository.save(payrollSite(), { by: 'a', ifMatch: undefined })
    await expect(sitesRepository.save(payrollSite(), { by: 'a', ifMatch: 'deadbeefdeadbeef' })).rejects.toMatchObject({ statusCode: 412 })
    await expect(sitesRepository.save(payrollSite(), { by: 'a', ifMatch: undefined })).rejects.toMatchObject({ statusCode: 428 })
    const second = await sitesRepository.save(payrollSite({ displayName: 'P2' }), { by: 'b', ifMatch: first.etag })
    expect(second.version).toBe(2)
    expect(second.etag).not.toBe(first.etag)
    expect((await sitesRepository.versions('payroll')).map((v) => v.v)).toEqual([1, 2])
  })

  it('keeps every version readable (append-only)', async () => {
    const a = await sitesRepository.save(payrollSite(), { by: 'a', ifMatch: undefined })
    await sitesRepository.save(payrollSite({ displayName: 'P2' }), { by: 'a', ifMatch: a.etag })
    expect((await sitesRepository.version('payroll', 1))?.site.displayName).toBe('Payroll')
    expect((await sitesRepository.version('payroll', 2))?.site.displayName).toBe('P2')
    expect(await sitesRepository.version('payroll', 3)).toBeNull()
  })

  it('stores, reads and drops a draft', async () => {
    await sitesRepository.putDraft('payroll', { site: payrollSite(), baseVersion: 0, updatedBy: 'a' })
    expect((await sitesRepository.getDraft('payroll'))?.updatedBy).toBe('a')
    expect(redisMock.strings.has('rbac:sites:draft:payroll')).toBe(true)
    await sitesRepository.deleteDraft('payroll')
    expect(await sitesRepository.getDraft('payroll')).toBeNull()
  })

  it('marks an apply and lists records', async () => {
    const a = await sitesRepository.save(payrollSite(), { by: 'a', ifMatch: undefined })
    await sitesRepository.markApplied('payroll', { version: a.version, by: 'sam', rules: [] })
    const list = await sitesRepository.list()
    expect(list).toHaveLength(1)
    expect(list[0].applied).toMatchObject({ version: 1, by: 'sam' })
  })

  it('removes a site and keeps a 30-day snapshot', async () => {
    await sitesRepository.save(payrollSite(), { by: 'a', ifMatch: undefined })
    await sitesRepository.remove('payroll', 'sam')
    expect(await sitesRepository.get('payroll')).toBeNull()
    expect(redisMock.ttl.get('rbac:sites:deleted:payroll')).toBe(30 * 24 * 3600)
  })
})
