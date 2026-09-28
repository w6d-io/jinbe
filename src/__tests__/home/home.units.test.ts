import { describe, it, expect, beforeEach, vi } from 'vitest'

vi.mock('../../home/sources.js', async () => (await import('./world.js')).sourcesMock())
vi.mock('../../services/redis-client.service.js', async () => (await import('./world.js')).redisMock())

import { world, resetWorld } from './world.js'
import { failedFactor } from '../../home/modules/activity.js'
import { ensureLabels, person, resetLabels, UNKNOWN_USER } from '../../home/labels.js'
import { scopeKeyOf, viewFor, type HomeScope } from '../../home/scope.js'

const scope = (over: Partial<HomeScope>): HomeScope => ({
  subject: 's', email: 's@example.com', name: null, aal: 'aal1', stepUpFresh: false, roles: [], permissions: [],
  platform: false, superAdmin: false, canApply: false, people: false, sessions: false, orgs: [], ...over,
})

describe('failedFactor (§10: ≥ 3× the 7-day median of the same hour, and ≥ 20 failures)', () => {
  const week = (sameHour: number, current: number) => {
    const hours = Array.from({ length: 7 * 24 + 1 }, () => 1)
    for (let d = 1; d <= 7; d++) hours[hours.length - 1 - d * 24] = sameHour
    hours[hours.length - 1] = current
    return hours
  }
  it('answers the factor, rounded to one decimal, once both floors are met', () => {
    expect(failedFactor(week(8, 30))).toBe(3.8)
  })
  it('null below 3×, below 20 failures, or without history', () => {
    expect(failedFactor(week(10, 25))).toBeNull()
    expect(failedFactor(week(1, 15))).toBeNull()
    expect(failedFactor([40])).toBeNull()
  })
  it('a zero baseline counts as one, not as an infinite spike', () => {
    expect(failedFactor(week(0, 24))).toBe(24)
  })
})

describe('labels (J10): a display name or "Unknown user", never an address', () => {
  beforeEach(() => { resetWorld(); resetLabels() })
  it('resolves by address and by id', async () => {
    await ensureLabels()
    expect(person('ada@example.com')).toEqual({ id: 'id-ada', label: 'Ada Lovelace' })
    expect(person('ADA@example.com').label).toBe('Ada Lovelace')
    expect(person('id-bob')).toEqual({ id: 'id-bob', label: 'Bob Chen' })
  })
  it('falls back to Unknown user, and drops an address-shaped name', async () => {
    world.identities.set('eve@example.com', { id: 'id-eve', name: 'eve@example.com', active: true })
    await ensureLabels()
    expect(person('stranger@example.com')).toEqual({ id: null, label: UNKNOWN_USER })
    expect(person('eve@example.com')).toEqual({ id: 'id-eve', label: UNKNOWN_USER })
    expect(person(null)).toEqual({ id: null, label: UNKNOWN_USER })
  })
})

describe('viewFor / scopeKeyOf', () => {
  it('platform readers may narrow to any org; org admins only to theirs', () => {
    expect(viewFor(scope({ platform: true }))).toEqual({ kind: 'platform' })
    expect(viewFor(scope({ platform: true }), 'x')).toEqual({ kind: 'orgs', orgs: ['x'] })
    expect(viewFor(scope({ orgs: ['a', 'b'] }))).toEqual({ kind: 'orgs', orgs: ['a', 'b'] })
    expect(viewFor(scope({ orgs: ['a', 'b'] }), 'b')).toEqual({ kind: 'orgs', orgs: ['b'] })
    expect(viewFor(scope({ orgs: ['a'] }), 'b')).toBeNull()
    expect(viewFor(scope({}), 'a')).toBeNull()
    expect(viewFor(scope({}))).toEqual({ kind: 'self' })
  })
  it('hashes org sets so no org id appears in a cache key', () => {
    const key = scopeKeyOf({ kind: 'orgs', orgs: ['11111111-1111-4111-8111-111111111111'] }, 's')
    expect(key).toMatch(/^orgs:[0-9a-f]{16}$/)
    expect(scopeKeyOf({ kind: 'platform' }, 's')).toBe('platform')
    expect(scopeKeyOf({ kind: 'self' }, 's')).not.toContain('s@')
  })
})
