import { describe, it, expect, beforeEach, vi } from 'vitest'

// The holding rule's one copy is the policy (rbac.delegation.*_verdict). What jinbe sends it, how it
// reads the verdict, and that anything unreadable fails closed — OPA mocked at the client boundary.

const s = vi.hoisted(() => ({
  answer: undefined as unknown,
  fail: false,
  calls: [] as Array<{ rule: string; input: Record<string, unknown> }>,
}))

vi.mock('../../services/opa-client.js', () => ({
  queryOpa: vi.fn(async (rule: string, input: Record<string, unknown>) => {
    s.calls.push({ rule, input })
    if (s.fail) throw new Error('connect ECONNREFUSED')
    return typeof s.answer === 'function' ? (s.answer as (r: string, i: Record<string, unknown>) => unknown)(rule, input) : s.answer
  }),
}))
vi.mock('../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getOrgSites: vi.fn(async () => ({})),
    getOrgRoles: vi.fn(async (svc: string) => (svc === 'jinbe' ? { owner: ['org.members:write'], viewer: ['org.members:read'] } : null)),
  },
}))

import { AuthzUnavailableError, grantVerdict } from '../../authz/opa.js'
import { orgRoleRefusals, orgRolesFor } from '../../services/org-role-grants.js'

const ALLOW = { allow: true, reasons: [], missing: {}, missing_every_org: {}, granted_by: [] }

beforeEach(() => {
  s.answer = ALLOW
  s.fail = false
  s.calls = []
})

describe('grantVerdict', () => {
  it('sends each grant to its verdict rule with the agreed input', async () => {
    await grantVerdict({ kind: 'assign', actor: 'a@example.com', grantee: 'b@example.com', org: 'acme', role: 'jinbe:viewer' })
    await grantVerdict({ kind: 'unassign', actor: 'a@example.com', org: 'acme' })
    await grantVerdict({ kind: 'add_to_group', actor: 'a@example.com', group: 'staff-support' })
    await grantVerdict({ kind: 'remove_from_group', actor: 'a@example.com' })
    await grantVerdict({ kind: 'define_group', actor: 'a@example.com', definition: { jinbe: ['viewer'] } })
    await grantVerdict({ kind: 'define_roles', actor: 'a@example.com', roles: { billing: { viewer: ['invoices:read'] } } })
    await grantVerdict({ kind: 'define_group', actor: 'a@example.com', definition: { billing: ['viewer'] }, roles: { billing: { viewer: ['invoices:read'] } } })
    await grantVerdict({ kind: 'grant_direct', actor: 'a@example.com', grantee: 'b@example.com', scope: 'platform', app: 'payroll', grantKind: 'role', name: 'editor' })
    await grantVerdict({ kind: 'grant_direct', actor: 'a@example.com', grantee: 'b@example.com', scope: 'acme', app: 'jinbe', grantKind: 'permission', name: 'org.keys:read' })
    await grantVerdict({ kind: 'revoke_direct', actor: 'a@example.com', scope: 'platform' })
    await grantVerdict({ kind: 'revoke_direct', actor: 'a@example.com', scope: 'acme' })
    expect(s.calls).toEqual([
      { rule: 'rbac/delegation/assign_verdict', input: { actor: { email: 'a@example.com' }, grantee: { email: 'b@example.com' }, org: 'acme', role: 'jinbe:viewer' } },
      { rule: 'rbac/delegation/unassign_verdict', input: { actor: { email: 'a@example.com' }, org: 'acme' } },
      { rule: 'rbac/delegation/add_to_group_verdict', input: { actor: { email: 'a@example.com' }, group: 'staff-support' } },
      { rule: 'rbac/delegation/remove_from_group_verdict', input: { actor: { email: 'a@example.com' } } },
      { rule: 'rbac/delegation/define_group_verdict', input: { actor: { email: 'a@example.com' }, definition: { jinbe: ['viewer'] } } },
      { rule: 'rbac/delegation/define_roles_verdict', input: { actor: { email: 'a@example.com' }, roles: { billing: { viewer: ['invoices:read'] } } } },
      { rule: 'rbac/delegation/define_group_verdict', input: { actor: { email: 'a@example.com' }, definition: { billing: ['viewer'] }, roles: { billing: { viewer: ['invoices:read'] } } } },
      // A platform direct grant names no org; an org one names it.
      { rule: 'rbac/delegation/grant_direct_verdict', input: { actor: { email: 'a@example.com' }, grantee: { email: 'b@example.com' }, app: 'payroll', kind: 'role', name: 'editor' } },
      { rule: 'rbac/delegation/grant_direct_verdict', input: { actor: { email: 'a@example.com' }, grantee: { email: 'b@example.com' }, app: 'jinbe', kind: 'permission', name: 'org.keys:read', org: 'acme' } },
      { rule: 'rbac/delegation/revoke_direct_verdict', input: { actor: { email: 'a@example.com' } } },
      { rule: 'rbac/delegation/revoke_direct_verdict', input: { actor: { email: 'a@example.com' }, org: 'acme' } },
    ])
  })

  it('reads a refusal: reasons, missing per app, the every-org part, who covers it', async () => {
    s.answer = {
      allow: false, reasons: ['missing_permissions', 'missing_every_org_permissions'],
      missing: { jinbe: ['users:disable', 'groups.members:write'] }, missing_every_org: { jinbe: ['org.members:write'] },
      granted_by: ['staff-support', 'super_admins'],
    }
    expect(await grantVerdict({ kind: 'add_to_group', actor: 'a@example.com', group: 'staff-support' })).toEqual({
      allow: false, reasons: ['missing_every_org_permissions', 'missing_permissions'],
      missing: { jinbe: ['groups.members:write', 'users:disable'] }, missingEveryOrg: { jinbe: ['org.members:write'] },
      grantedBy: ['staff-support', 'super_admins'],
    })
  })

  it('never caches: the same grant asked twice is asked twice', async () => {
    await grantVerdict({ kind: 'remove_from_group', actor: 'a@example.com' })
    await grantVerdict({ kind: 'remove_from_group', actor: 'a@example.com' })
    expect(s.calls).toHaveLength(2)
  })

  it.each([
    ['OPA unreachable', () => { s.fail = true }],
    ['no policy loaded (no answer)', () => { s.answer = undefined }],
    ['an answer without allow', () => { s.answer = { reasons: [] } }],
    ['a malformed missing map', () => { s.answer = { ...ALLOW, allow: false, missing: ['x'] } }],
  ])('fails closed: %s', async (_label, set) => {
    set()
    await expect(grantVerdict({ kind: 'remove_from_group', actor: 'a@example.com' })).rejects.toBeInstanceOf(AuthzUnavailableError)
  })
})

describe('org roles through the policy', () => {
  it('marks as assignable exactly what assignable_roles answers', async () => {
    s.answer = (rule: string) => (rule === 'rbac/delegation/assignable_roles' ? ['jinbe:viewer'] : ALLOW)
    expect(await orgRolesFor('a@example.com', 'acme')).toEqual([
      { role: 'jinbe:owner', permissions: ['org.members:write'], assignable: false },
      { role: 'jinbe:viewer', permissions: ['org.members:read'], assignable: true },
    ])
  })

  it('a person created into the org by this request is not refused for not being a member yet — nothing else is forgiven', async () => {
    s.answer = { allow: false, reasons: ['grantee_not_member'], missing: {}, missing_every_org: {}, granted_by: [] }
    expect(await orgRoleRefusals('a@example.com', 'acme', ['jinbe:viewer'], { email: 'new@example.com', joining: true })).toEqual([])
    expect(await orgRoleRefusals('a@example.com', 'acme', ['jinbe:viewer'], { email: 'new@example.com' })).toEqual([
      { role: 'jinbe:viewer', reason: 'grantee_not_member', reasons: ['grantee_not_member'] },
    ])
    s.answer = { allow: false, reasons: ['grantee_not_member', 'missing_permissions'], missing: { jinbe: ['org.members:read'] }, missing_every_org: {}, granted_by: ['jinbe:owner'] }
    expect(await orgRoleRefusals('a@example.com', 'acme', ['jinbe:viewer'], { email: 'new@example.com', joining: true })).toEqual([
      { role: 'jinbe:viewer', reason: 'grant_exceeds_own', reasons: ['missing_permissions'], missing: ['org.members:read'], grantedBy: ['jinbe:owner'] },
    ])
  })
})
