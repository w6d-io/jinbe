import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { policyContract, renderPolicyContract } from '../../authz-v2/contract.js'

describe('policy-contract.json (for opal-policies CI)', () => {
  it('is what the code generates — run `npm run build` (or `npm run contract` after tsc)', () => {
    expect(readFileSync(new URL('../../../policy-contract.json', import.meta.url), 'utf8')).toBe(renderPolicyContract())
  })

  it('names who reaches each row, and nobody reaches through a wildcard', () => {
    const c = policyContract()
    expect(JSON.stringify(c)).not.toContain('"*"')
    const rows = c.route_map.jinbe.rules
    const del = rows.find((r) => r.method === 'DELETE' && r.path === '/api/admin/users/:id')!
    expect(del.reach).toEqual({ kind: 'platform', roles: ['super_admin'], groups: ['super_admins'] })
    const invite = rows.find((r) => r.method === 'POST' && r.path === '/api/organizations/:organizationId/users')!
    expect(invite.reach).toEqual({ kind: 'org', orgRoles: ['member_manager', 'owner'], everyOrg: ['super_admin', 'support'] })
    expect(rows.find((r) => r.path === '/api/whoami')!.reach).toEqual({ kind: 'public' })
    expect(rows.find((r) => r.path === '/api/audit/events')!.reach).toEqual({ kind: 'signed-in' })
  })
})
