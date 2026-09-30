import { describe, it, expect, beforeEach, vi } from 'vitest'

// The policy looks a role name up in roles.global and roles.<app> alike, so a binding naming a role its
// service does not define reaches whatever carries that name elsewhere: a group { jinbe: ['super_admin'] }
// was the global super_admin (`*`) — a second account put in it was a super admin.

const store = vi.hoisted(() => ({ roles: {} as Record<string, Record<string, string[]>> }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: { getRoles: vi.fn(async (svc: string) => store.roles[svc] ?? null) },
}))

import { assertValidBinding, bindingProblems, InvalidBindingError } from '../../../services/group-bindings.js'

beforeEach(() => {
  store.roles = {
    global: { super_admin: ['*'], admin: ['*'], support: ['users:read'] },
    jinbe: { admin: ['*'], legacy_support: ['users:read'] },
    billing: { viewer: ['invoices:read'], admin: ['*'] },
  }
})

const refusal = async (p: Promise<unknown>) => {
  try { await p; return null } catch (e) { return e }
}

describe('group bindings', () => {
  it('refuses super_admin under any service but global — the second-account path', async () => {
    const err = await refusal(assertValidBinding('mine', { jinbe: ['super_admin'] }))
    expect(err).toBeInstanceOf(InvalidBindingError)
    expect((err as InvalidBindingError).statusCode).toBe(422)
    expect((err as InvalidBindingError).problems[0]).toContain('super_admin is bound only under global')
    // Even when the service happens to define a role of that name.
    store.roles.jinbe.super_admin = ['users:read']
    expect(await refusal(assertValidBinding('mine', { jinbe: ['super_admin'] }))).toBeInstanceOf(InvalidBindingError)
  })

  it('refuses a role the service does not define (it would resolve to the global role of that name)', async () => {
    expect(await refusal(assertValidBinding('desk', { jinbe: ['support'] }))).toBeInstanceOf(InvalidBindingError)
    expect(bindingProblems('x', { billing: ['viewer', 'editor'] }, (s) => store.roles[s])).toEqual(['x: billing defines no role editor'])
    expect(bindingProblems('x', { ghost: ['viewer'] }, (s) => store.roles[s])).toEqual(['x: ghost has no roles'])
  })

  it('allows roles each service defines, global:super_admin included', async () => {
    expect(await refusal(assertValidBinding('super_admins', { global: ['super_admin'] }))).toBeNull()
    expect(await refusal(assertValidBinding('ops', { jinbe: ['admin'], billing: ['viewer'], global: ['support'] }))).toBeNull()
    expect(await refusal(assertValidBinding('users', {}))).toBeNull()
  })
})
