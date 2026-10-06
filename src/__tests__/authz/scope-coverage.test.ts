import { describe, it, expect } from 'vitest'
import { clientGranted, isGrantableScope } from '../../services/authorization-resolution.js'

describe('isGrantableScope — a token carries exact names only', () => {
  it('a wildcard is never a grantable scope', () => {
    expect(isGrantableScope('payroll.runs:read')).toBe(true)
    expect(isGrantableScope('*')).toBe(false)
    expect(isGrantableScope('payroll:*')).toBe(false)
  })
})

describe('clientGranted — the org-key clause (rbac.rego §8b)', () => {
  const acme = { org: 'acme', scopes: ['payroll:read', 'payroll:write'] }
  const sites = (org: string) => (org === 'acme' ? ['jinbe', 'payroll'] : ['jinbe', 'crm'])

  it("needs the permission in the key's expanded scopes, exactly", () => {
    expect(clientGranted(acme, { permission: 'payroll:read', org: 'acme', app: 'payroll' }, sites)).toBe(true)
    // Exact for a machine: an ancestor scope does not reach a sibling route.
    expect(clientGranted(acme, { permission: 'payroll.runs:read', org: 'acme', app: 'payroll' }, sites)).toBe(false)
    expect(clientGranted(acme, { permission: 'payroll:delete', org: 'acme', app: 'payroll' }, sites)).toBe(false)
  })

  it("the route's org must be the key's; the site must serve the key's org", () => {
    expect(clientGranted(acme, { permission: 'payroll:read', org: 'globex', app: 'payroll' }, sites)).toBe(false)
    expect(clientGranted(acme, { permission: 'payroll:read', app: 'payroll' }, sites)).toBe(true)
    expect(clientGranted(acme, { permission: 'payroll:read', app: 'crm' }, sites)).toBe(false)
  })

  it("never on the platform's own apps, even serving the org", () => {
    expect(clientGranted({ org: 'acme', scopes: ['users:read'] }, { permission: 'users:read', app: 'jinbe' }, sites)).toBe(false)
  })

  it('refuses an unknown client, a permission-less route, and an expired key', () => {
    expect(clientGranted(undefined, { permission: 'payroll:read', app: 'payroll' }, sites)).toBe(false)
    expect(clientGranted(acme, { app: 'payroll' }, sites)).toBe(false)
    const expired = { ...acme, expires_at: '2020-01-01T00:00:00Z' }
    expect(clientGranted(expired, { permission: 'payroll:read', app: 'payroll' }, sites)).toBe(false)
  })
})
