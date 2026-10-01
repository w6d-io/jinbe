import { describe, it, expect, afterEach } from 'vitest'
import { CATALOG_V2, ORG_PERMISSIONS_V2, PLATFORM_PERMISSIONS_V2, PLATFORM_RENAMES, v2Name, V2NameError } from '../../authz-v2/catalogue.js'
import { EVERY_ORG, ORG_ROLES, PLATFORM_ROLES, modelProblems, staffGroupsV2 } from '../../authz-v2/roles.js'
import { activeModel, onlyInModel, refreshActiveModel, setActiveModel, v2Grants } from '../../authz-v2/model.js'
import { PERMISSIONS, grants } from '../../policy/catalog.js'
import { STAFF_ROLES } from '../../policy/roles.js'

afterEach(() => setActiveModel('v1'))

describe('the v2 catalogue', () => {
  it('scopes every permission platform or org, and the org namespace is exactly the design table', () => {
    for (const spec of Object.values(CATALOG_V2)) expect(['platform', 'org']).toContain(spec.scope)
    expect([...ORG_PERMISSIONS_V2].sort()).toEqual(
      ['org.audit:read', 'org.keys:read', 'org.keys:revoke', 'org.keys:write', 'org.members:read', 'org.members:write'].sort(),
    )
  })

  it('renames the platform permissions about orgs to orgs:*, so the namespaces cannot be confused', () => {
    expect(PLATFORM_RENAMES).toMatchObject({
      'org:read': 'orgs:read', 'org:write': 'orgs:write', 'org:delete': 'orgs:delete', 'org.admins:write': 'orgs.owners:write',
    })
    for (const name of PLATFORM_PERMISSIONS_V2) expect(name.startsWith('org.') || name.startsWith('org:'), name).toBe(false)
    for (const name of ['org:read', 'org:write', 'org:delete', 'org.admins:write']) expect(CATALOG_V2[name]).toBeUndefined()
  })

  it('keeps every v1 leaf under a v2 name, with its step-up and delegability', () => {
    for (const v1 of PERMISSIONS) {
      const names = Object.entries(CATALOG_V2).filter(([, s]) => s.from === v1)
      expect(names.length, v1).toBeGreaterThan(0)
      for (const [, spec] of names) expect(spec.delegable).toBe(CATALOG_V2[names[0][0]].delegable)
    }
    expect(CATALOG_V2['orgs.owners:write']).toMatchObject({ stepUp: true, fourEyes: 'prod', delegable: 'never' })
    expect(CATALOG_V2['org.keys:write']).toMatchObject({ stepUp: true, delegable: 'never', scope: 'org' })
  })

  it('has no wildcard anywhere', () => {
    expect(Object.keys(CATALOG_V2).filter((n) => n.includes('*'))).toEqual([])
  })

  it('reads a route permission by the route shape: org scope only on an org parameter, platform elsewhere', () => {
    expect(v2Name('org.members:read', true)).toBe('org.members:read')
    expect(v2Name('org.members:write', false)).toBe('orgs.members:write')
    expect(v2Name('org:read', false)).toBe('orgs:read')
    expect(() => v2Name('org.keys:read', false)).toThrow(V2NameError)
    expect(() => v2Name('users:read', true)).toThrow(V2NameError)
  })
})

describe('the v2 roles', () => {
  it('are sound: platform roles platform-only, org roles and every-org org-only, all catalogue leaves', () => {
    expect(modelProblems()).toEqual([])
  })

  it('generate super_admin as exactly every platform permission, plus every org permission in every org', () => {
    expect([...PLATFORM_ROLES.super_admin].sort()).toEqual([...PLATFORM_PERMISSIONS_V2].sort())
    expect([...(EVERY_ORG.super_admin ?? [])].sort()).toEqual([...ORG_PERMISSIONS_V2].sort())
    expect([...ORG_ROLES.owner.permissions].sort()).toEqual([...ORG_PERMISSIONS_V2].sort())
  })

  it('every-org is the D1 table: support members r/w, auditor and security read, nobody else', () => {
    expect(EVERY_ORG.support).toEqual(['org.members:read', 'org.members:write'])
    expect([...(EVERY_ORG.auditor ?? [])].sort()).toEqual(['org.audit:read', 'org.keys:read', 'org.members:read'])
    expect(EVERY_ORG.security).toEqual(EVERY_ORG.auditor)
    for (const r of ['viewer', 'ops', 'developer'] as const) expect(EVERY_ORG[r]).toBeUndefined()
  })

  it('binds the staff groups under jinbe, never global', () => {
    const groups = staffGroupsV2()
    for (const role of STAFF_ROLES) expect(Object.values(groups)).toContainEqual({ jinbe: [role] })
    for (const def of Object.values(groups)) expect(Object.keys(def)).toEqual(['jinbe'])
  })
})

describe('the model adapter', () => {
  it('starts on v1 and keeps v1 grants (aliases and * included) until the switch', () => {
    expect(activeModel()).toBe('v1')
    expect(grants(['*'], 'users:read')).toBe(true)
    expect(grants(['admin:read'], 'users:read')).toBe(true)
  })

  it('under v2, grants is the exact platform name: no *, no alias, renamed names', () => {
    setActiveModel('v2')
    expect(grants(['*'], 'users:read')).toBe(false)
    expect(grants(['admin:read'], 'users:read')).toBe(false)
    expect(grants(['orgs:read'], 'org:read')).toBe(true)
    expect(grants(['org:read'], 'org:read')).toBe(false)
    expect(grants(['users:read'], 'users:read')).toBe(true)
  })

  it('under v2, an org permission is never held on a platform reading', () => {
    expect(v2Grants(['org.members:read'], 'org.members:read')).toBe(false)
    expect(v2Grants(['org.keys:write'], 'org.keys:write')).toBe(false)
  })

  it('keeps the current model when the switch is absent, unknown or unreadable', async () => {
    expect(await refreshActiveModel(async () => null)).toBe('v1')
    expect(await refreshActiveModel(async () => 'v3')).toBe('v1')
    expect(await refreshActiveModel(async () => 'v2')).toBe('v2')
    expect(await refreshActiveModel(async () => { throw new Error('redis down') })).toBe('v2')
  })

  it('answers 404 on a route of the other model', async () => {
    const sent: { status?: number; body?: unknown } = {}
    const reply = { status(code: number) { sent.status = code; return this }, send(body: unknown) { sent.body = body; return this } }
    await onlyInModel('v2')({} as never, reply as never)
    expect(sent).toMatchObject({ status: 404, body: { code: 'route_not_active' } })
    setActiveModel('v2')
    const passed: { status?: number } = {}
    await onlyInModel('v2')({} as never, { status(c: number) { passed.status = c; return this }, send() { return this } } as never)
    expect(passed.status).toBeUndefined()
  })
})
