import { describe, it, expect, beforeEach, vi } from 'vitest'

// What a group grants, app by app, and who grants a missing permission (the 403 hint) — read off the
// staff roles as code defines them. The grant decision itself is the policy's (rbac-escalation-guard).

const store = vi.hoisted(() => ({
  groups: {} as Record<string, Record<string, string[]>>,
  roles: {} as Record<string, Record<string, string[]>>,
}))

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => 'id') } }))
vi.mock('../../../services/redis-client.service.js', () => ({ redisClientService: { isConnected: true } }))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: vi.fn(async () => store.groups),
    getRoles: vi.fn(async (service: string) => store.roles[service] ?? null),
  },
}))

import { exceeding, groupGrants, heldIn } from '../../../services/grant-subset.js'
import { grantedBy, hintFor } from '../../../services/permission-refusal.js'
import { roleDefinitions, staffGroups } from '../../../policy/roles.js'
import { resetOpaWorld } from '../../helpers/opa-authz-mock.js'

beforeEach(() => {
  vi.clearAllMocks()
  resetOpaWorld()
  // As the bootstrap writes them: the staff roles under jinbe, one group each.
  store.roles = { jinbe: roleDefinitions(), billing: { reader: ['invoices:read'] } }
  store.groups = staffGroups()
})

describe('resolution, app by app (as rbac.rego)', () => {
  it('reads each role name in its own app only', () => {
    expect(groupGrants({ billing: ['reader'] }, store.roles)).toEqual({ billing: ['invoices:read'] })
    expect(groupGrants({ billing: ['security'] }, store.roles)).toEqual({})
    expect(groupGrants({ jinbe: ['security'] }, store.roles).jinbe).toContain('users:reset_second_factor')
  })

  it('what somebody holds in one app says nothing about another', () => {
    const held = heldIn([{ jinbe: ['viewer'] }, { billing: ['reader'] }], store.roles, ['jinbe', 'billing'])
    expect(held.jinbe).not.toContain('invoices:read')
    expect(held.billing).toEqual(['invoices:read'])
  })

  it('exceeding is an exact difference: no wildcard, no alias', () => {
    expect(exceeding({ jinbe: ['zones:write', 'sites:read'] }, { jinbe: ['sites:read'] })).toEqual({ jinbe: ['zones:write'] })
    expect(exceeding({ jinbe: ['users:read'] }, { jinbe: ['*'] })).toEqual({ jinbe: ['users:read'] })
  })
})

describe('grantedBy', () => {
  it('lists the groups whose roles hold the permission, the narrowest first', async () => {
    expect(await grantedBy(['users:reset_second_factor'])).toEqual(['staff-security', 'staff-support', 'super_admins'])
    expect(await grantedBy(['sites:read'])).toEqual(['staff-ops', 'staff-developers', 'super_admins'])
  })

  it('answers an empty list, never an error, when the model cannot be read', async () => {
    const { redisRbacRepository } = await import('../../../services/redis-rbac.repository.js')
    vi.mocked(redisRbacRepository.getGroups).mockRejectedValueOnce(new Error('down'))
    expect(await grantedBy(['users:read'])).toEqual([])
    expect(hintFor(null, ['users:read'])).toBe('Ask an administrator for users:read.')
    expect(hintFor([])).toMatch(/super admin/)
  })
})
