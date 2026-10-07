import { describe, it, expect, vi, beforeEach } from 'vitest'

// A group that no longer exists leaves nobody holding it: the names a path deleted, and the staff
// groups retired from code before the cascade existed (once) — never a sweep of unknown names.

const h = vi.hoisted(() => ({ removed: [] as string[], done: new Set<string>(), fail: '' }))

vi.mock('../../../services/kratos.service.js', () => ({
  kratosService: {
    removeGroupFromAllUsers: vi.fn(async (name: string) => {
      if (name === h.fail) throw new Error('kratos down')
      h.removed.push(name)
      return 1
    }),
  },
}))
vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({
    smembers: vi.fn(async () => [...h.done]),
    sadd: vi.fn(async (_k: string, ...names: string[]) => { names.forEach((n) => h.done.add(n)); return names.length }),
  }),
}))
vi.mock('../../../telemetry/logger.js', () => ({ componentLogger: () => ({ info: vi.fn(), error: vi.fn() }) }))

import { forgetGroupMembers, pruneRetiredGroups } from '../../../services/group-cascade.js'

beforeEach(() => { h.removed = []; h.done = new Set(); h.fail = '' })

describe('group cascade', () => {
  it('takes each deleted group off its members once, and survives a Kratos failure on one', async () => {
    h.fail = 'b'
    expect(await forgetGroupMembers(['a', 'b', 'a', 'c'])).toBe(2)
    expect(h.removed).toEqual(['a', 'c'])
  })

  it('prunes the retired staff groups once per environment, never one that is defined again', async () => {
    await pruneRetiredGroups({ 'staff-auditors': { jinbe: ['auditor'] } })
    expect(h.removed).toEqual(['staff-viewers'])
    h.removed = []
    await pruneRetiredGroups({})
    expect(h.removed).toEqual(['staff-auditors'])
    h.removed = []
    await pruneRetiredGroups({})
    expect(h.removed).toEqual([])
  })
})
