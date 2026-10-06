import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { policyContract, renderPolicyContract } from '../../policy/contract.js'

describe('policy-contract.json (for opal-policies CI)', () => {
  it('is what the code generates — run `npm run build` (or `npm run contract` after tsc)', () => {
    expect(readFileSync(new URL('../../../policy-contract.json', import.meta.url), 'utf8')).toBe(renderPolicyContract())
  })

  it('carries worked direct-grant examples for the policy to replay', () => {
    const ex = Object.fromEntries(policyContract().direct_grants.examples.map((e) => [e.name, e.expect]))
    expect(ex['a platform permission, alone']).toEqual({ platform: ['users:read'], orgs: {} })
    expect(ex['a platform role'].platform).toEqual(expect.arrayContaining(['sites:read', 'sites:write']))
    expect(ex['an org role, for a member'].orgs['org-example']).toEqual(expect.arrayContaining(['org.members:read']))
    expect(ex['an org permission, for a member']).toEqual({ platform: [], orgs: { 'org-example': ['org.keys:read'] } })
    expect(ex['an org grant without membership counts for nothing']).toEqual({ platform: [], orgs: {} })
    expect(ex['an expired grant counts for nothing (the policy checks expires_at too)']).toEqual({ platform: [], orgs: {} })
    expect(ex['a direct role carries its every-org reach'].orgs['org-example']).toEqual(['org.audit:read', 'org.keys:read', 'org.members:read'])
  })

  it('names who reaches each row, and nobody reaches through a wildcard', () => {
    const c = policyContract()
    expect(JSON.stringify(c)).not.toContain('"*"')
    const rows = c.route_map.jinbe.rules
    const del = rows.find((r) => r.method === 'DELETE' && r.path === '/api/admin/users/:id')!
    expect(del.reach).toEqual({ kind: 'platform', roles: ['super_admin'], groups: ['super_admins'] })
    const invite = rows.find((r) => r.method === 'POST' && r.path === '/api/organizations/:organizationId/invitations')!
    expect(invite.reach).toEqual({ kind: 'org', orgRoles: ['member_manager', 'owner'], everyOrg: ['super_admin'] })
    expect(rows.find((r) => r.path === '/api/whoami')!.reach).toEqual({ kind: 'public' })
    const audit = rows.filter((r) => r.method === 'GET' && r.path === '/api/audit/events')
    expect(audit.map((r) => r.reach.kind)).toEqual(['platform', 'any_org'])
    expect(audit[1].reach).toEqual({ kind: 'any_org', orgRoles: ['auditor', 'owner'], everyOrg: ['security', 'super_admin'] })
  })
})
