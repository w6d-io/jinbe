import { describe, it, expect, vi } from 'vitest'

// Mirror of opal-policies org.rego `org_permissions`: org_grants[org][email] → groups → SERVICE roles
// → permissions. A group's global roles never flow through an org grant; another org's grants never
// count here.

const ACME = '11111111-1111-1111-1111-111111111111'

vi.mock('../../../services/org-grants.repository.js', () => ({
  orgGrantsRepository: {
    getForMember: vi.fn(async (org: string, email: string) =>
      org === ACME && email === 'bob@acme.test' ? ['keys', 'sneaky', 'ghost'] : []),
  },
}))
vi.mock('../../../services/redis-rbac.repository.js', () => ({
  redisRbacRepository: {
    getGroups: vi.fn(async () => ({
      keys: { kuma: ['key_manager'] },
      sneaky: { global: ['super_admin'] },
    })),
    getRoles: vi.fn(async (svc: string) => ({
      kuma: { key_manager: ['org:manage_api_keys', 'kuma:read'] },
      global: { super_admin: ['*'] },
    } as Record<string, Record<string, string[]>>)[svc] ?? null),
  },
}))

import { orgGrantPermissions } from '../../../services/org-grants.service.js'

describe('orgGrantPermissions', () => {
  it('resolves service roles of the groups granted in THAT org, never global ones', async () => {
    expect(await orgGrantPermissions('Bob@acme.test', ACME)).toEqual(['kuma:read', 'org:manage_api_keys'])
  })

  it('is empty in another org', async () => {
    expect(await orgGrantPermissions('bob@acme.test', 'globex')).toEqual([])
  })
})
