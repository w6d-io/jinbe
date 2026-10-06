import { describe, it, expect, beforeEach, vi } from 'vitest'

// Groups added while their member had no second factor: kept, never a membership, applied once the
// person enrols — as the adder, holding rule included. A refusal drops the wait; an outage keeps it.

vi.mock('../../services/redis-client.service.js', async () => {
  const { InlineRedisMock } = await import('../sites/mocks.js')
  const redis = new InlineRedisMock()
  return { getRedisClient: () => redis, __redis: redis }
})
vi.mock('../../services/redis-lock.js', () => ({ withRedisLock: (_n: string, fn: () => unknown) => fn() }))

import { AWAITING_TTL_DAYS, applyAwaitingGroups, awaitingSecondFactor, type ApplyAwaitingDeps } from '../../second-factor/awaiting.js'

const BY = { id: 'admin-1', email: 'admin@x.io' }
const deps = (o: Partial<ApplyAwaitingDeps> = {}): ApplyAwaitingDeps => ({
  hasSecondFactor: vi.fn(async () => true),
  addGroups: vi.fn(async () => ({ ok: true })),
  ...o,
})

beforeEach(async () => {
  ;((await import('../../services/redis-client.service.js')) as unknown as { __redis: { clear: () => void } }).__redis.clear()
})

describe('awaitingSecondFactor', () => {
  it('merges additions for the same person and restarts the clock; an expired wait is gone', async () => {
    await awaitingSecondFactor.add('p', ['devs'], BY, 0)
    const now = Date.now()
    const merged = await awaitingSecondFactor.add('p', ['ops', 'devs'], BY, now)
    expect(merged.groups).toEqual(['devs', 'ops'])
    expect(Date.parse(merged.expiresAt) - now).toBe(AWAITING_TTL_DAYS * 86_400_000)
    expect(await awaitingSecondFactor.get('p', now + (AWAITING_TTL_DAYS + 1) * 86_400_000)).toBeNull()
    expect(await awaitingSecondFactor.get('p', now)).toBeNull()
  })
})

describe('applyAwaitingGroups', () => {
  it('applies once enrolled, as the adder, then forgets the wait', async () => {
    await awaitingSecondFactor.add('p', ['devs'], BY)
    const d = deps()
    expect(await applyAwaitingGroups('p', d)).toBe('applied')
    expect(d.addGroups).toHaveBeenCalledWith('p', ['devs'], BY)
    expect(await awaitingSecondFactor.get('p')).toBeNull()
  })

  it('keeps waiting while not enrolled, or when the update cannot be made (5xx)', async () => {
    await awaitingSecondFactor.add('p', ['devs'], BY)
    expect(await applyAwaitingGroups('p', deps({ hasSecondFactor: vi.fn(async () => false) }))).toBe('waiting')
    expect(await applyAwaitingGroups('p', deps({ addGroups: vi.fn(async () => ({ ok: false, status: 503 })) }))).toBe('waiting')
    expect(await awaitingSecondFactor.get('p')).not.toBeNull()
  })

  it('a refusal (the adder lost the right) drops the wait instead of retrying forever', async () => {
    await awaitingSecondFactor.add('p', ['devs'], BY)
    expect(await applyAwaitingGroups('p', deps({ addGroups: vi.fn(async () => ({ ok: false, status: 403 })) }))).toBe('refused')
    expect(await awaitingSecondFactor.get('p')).toBeNull()
  })

  it('nothing waiting, or no identity: nothing to do, and never throws', async () => {
    expect(await applyAwaitingGroups('p', deps())).toBe('none')
    expect(await applyAwaitingGroups(null, deps())).toBe('none')
    await awaitingSecondFactor.add('p', ['devs'], BY)
    expect(await applyAwaitingGroups('p', deps({ hasSecondFactor: vi.fn(async () => { throw new Error('kratos down') }) }))).toBe('waiting')
  })
})
