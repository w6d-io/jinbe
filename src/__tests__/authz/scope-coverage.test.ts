import { describe, it, expect } from 'vitest'
import { clientGranted, isGrantableScope } from '../../services/authorization-resolution.js'

describe('isGrantableScope — a token carries exact names only', () => {
  it('a wildcard is never a grantable scope', () => {
    expect(isGrantableScope('payroll.runs:read')).toBe(true)
    expect(isGrantableScope('*')).toBe(false)
    expect(isGrantableScope('payroll:*')).toBe(false)
  })
})

describe('clientGranted — the machine-client clause', () => {
  const acme = { org: 'acme', scopes: ['payroll:read', 'payroll:write'] }
  const sites = (org: string) => (org === 'acme' ? ['payroll'] : ['crm'])

  it('needs a scope the token carries AND the client was registered with', () => {
    expect(clientGranted(acme, ['payroll:read'], { permission: 'payroll:read', org: 'acme', app: 'payroll' }, sites)).toBe(true)
    // Exact for a machine: an ancestor scope does not reach a sibling route.
    expect(clientGranted(acme, ['payroll:read'], { permission: 'payroll.runs:read', org: 'acme', app: 'payroll' }, sites)).toBe(false)
    expect(clientGranted(acme, ['payroll:read'], { permission: 'payroll:write', org: 'acme', app: 'payroll' }, sites)).toBe(false)
    // Token claims a scope the client was never registered with.
    expect(clientGranted(acme, ['payroll:delete'], { permission: 'payroll:delete', org: 'acme', app: 'payroll' }, sites)).toBe(false)
  })

  it("the route's org must be the client's; without an org param, a site the org runs", () => {
    expect(clientGranted(acme, ['payroll:read'], { permission: 'payroll:read', org: 'globex', app: 'payroll' }, sites)).toBe(false)
    expect(clientGranted(acme, ['payroll:read'], { permission: 'payroll:read', app: 'payroll' }, sites)).toBe(true)
    expect(clientGranted(acme, ['payroll:read'], { permission: 'payroll:read', app: 'crm' }, sites)).toBe(false)
  })

  it('refuses an unknown client, a permission-less route, and an expired key', () => {
    expect(clientGranted(undefined, ['payroll:read'], { permission: 'payroll:read', app: 'payroll' }, sites)).toBe(false)
    expect(clientGranted(acme, ['payroll:read'], { app: 'payroll' }, sites)).toBe(false)
    const expired = { ...acme, expires_at: '2020-01-01T00:00:00Z' }
    expect(clientGranted(expired, ['payroll:read'], { permission: 'payroll:read', app: 'payroll' }, sites)).toBe(false)
  })
})
