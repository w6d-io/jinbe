import { describe, it, expect } from 'vitest'
import type { Redis } from 'ioredis'
import { convergeOwned, jinbeOwnedKeys, readV2Keys, ownedKey, APPS_KEY } from '../../authz-v2/store.js'
import { buildDataV2 } from '../../authz-v2/dataset.js'
import { DOCS_ROW } from '../../authz-v2/route-rows.js'
import { fakeRedis } from './fixtures.js'

const asRedis = (r: ReturnType<typeof fakeRedis>) => r as unknown as Redis

describe('rbac2 keys: converge, never merge', () => {
  it('writes jinbe’s keys beside v1 on first run, then leaves them alone', async () => {
    const r = fakeRedis()
    r.data.set('rbac:roles:global', '{"super_admin":["*"]}')
    const first = await convergeOwned(asRedis(r), 'jinbe', jinbeOwnedKeys({ docs: false }))
    expect(first.created.sort()).toEqual(Object.keys(jinbeOwnedKeys({ docs: false })).sort())
    expect(r.data.get('rbac:roles:global')).toBe('{"super_admin":["*"]}')
    expect(JSON.parse(r.data.get(APPS_KEY)!)).toEqual(['jinbe'])
    const again = await convergeOwned(asRedis(r), 'jinbe', jinbeOwnedKeys({ docs: false }))
    expect(again).toEqual({ created: [], updated: [], drifted: [] })
  })

  it('a code change is an update, a hand edit is drift — both converge back', async () => {
    const r = fakeRedis()
    await convergeOwned(asRedis(r), 'jinbe', jinbeOwnedKeys({ docs: false }))
    const upgraded = await convergeOwned(asRedis(r), 'jinbe', jinbeOwnedKeys({ docs: true }))
    expect(upgraded).toEqual({ created: [], updated: ['rbac2:route_map:jinbe'], drifted: [] })

    r.data.set('rbac2:roles:jinbe', '{"viewer":["*"]}')
    const drift = await convergeOwned(asRedis(r), 'jinbe', jinbeOwnedKeys({ docs: true }))
    expect(drift).toEqual({ created: [], updated: [], drifted: ['rbac2:roles:jinbe'] })
    expect(r.data.get('rbac2:roles:jinbe')).toBe(jinbeOwnedKeys({ docs: true })['rbac2:roles:jinbe'])
    expect(r.data.get(ownedKey('jinbe'))).toBeDefined()
  })

  it('jinbe’s keys hold no wildcard and the docs row only with swagger', () => {
    const keys = jinbeOwnedKeys({ docs: false })
    for (const [k, v] of Object.entries(keys)) expect(v.includes('"*"'), k).toBe(false)
    expect(keys['rbac2:route_map:jinbe']).not.toContain(DOCS_ROW.path)
    expect(jinbeOwnedKeys({ docs: true })['rbac2:route_map:jinbe']).toContain(DOCS_ROW.path)
  })
})

describe('data.v2', () => {
  it('reads back what was converged and keeps people, dropping orphans from the policy only', async () => {
    const r = fakeRedis()
    await convergeOwned(asRedis(r), 'jinbe', jinbeOwnedKeys({ docs: false }))
    const keys = await readV2Keys(asRedis(r))
    const d = buildDataV2(keys, new Map([
      ['Root@X.io', { groups: ['super_admins', 'platform-admins', 'users'], organizations: [], organizationRoles: {} }],
      ['o@acme.io', { groups: ['users'], organizations: ['acme'], organizationRoles: { acme: ['jinbe:owner', 'admin'], globex: ['jinbe:owner'] } }],
    ]), ['globex'])
    expect(d.group_membership['Root@X.io']).toEqual(['super_admins'])
    expect(d.group_membership['root@x.io']).toEqual(['super_admins'])
    expect(d.org_assignments['o@acme.io']).toEqual({ acme: ['jinbe:owner'] })
    expect(d.org_sites).toEqual({ acme: ['jinbe'], globex: ['jinbe'] })
    expect(d.roles.jinbe.super_admin.length).toBeGreaterThan(40)
    expect(Object.keys(d.catalogue)).toContain('orgs.owners:write')
  })
})
