import { describe, it, expect } from 'vitest'
import type { Redis } from 'ioredis'
import { convergeOwned, jinbeOwned, OWNED_KEY } from '../../bootstrap/owned-keys.js'
import { DOCS_ROW } from '../../policy/route-map.js'
import { fakeRedis } from '../helpers/policy-data.js'

const asRedis = (r: ReturnType<typeof fakeRedis>) => r as unknown as Redis

describe('what jinbe owns: converged every run, replaced never merged', () => {
  it('writes its slots on the first run, then leaves them alone', async () => {
    const r = fakeRedis()
    const first = await convergeOwned(asRedis(r), 'jinbe', jinbeOwned({ docs: false }), 'jinbe')
    expect(first.created.sort()).toEqual(jinbeOwned({ docs: false }).map(({ slot }) => (slot.field ? `${slot.key}#${slot.field}` : slot.key)).sort())
    expect(r.sets.get('rbac:services')?.has('jinbe')).toBe(true)
    expect(JSON.parse(r.hashes.get('rbac:groups')!.get('super_admins')!)).toEqual({ jinbe: ['super_admin'] })
    expect(await convergeOwned(asRedis(r), 'jinbe', jinbeOwned({ docs: false }), 'jinbe')).toEqual({ created: [], updated: [], drifted: [] })
  })

  it('a code change is an update, a hand edit is drift — both converge back', async () => {
    const r = fakeRedis()
    await convergeOwned(asRedis(r), 'jinbe', jinbeOwned({ docs: false }), 'jinbe')
    expect(await convergeOwned(asRedis(r), 'jinbe', jinbeOwned({ docs: true }), 'jinbe')).toEqual({ created: [], updated: ['rbac:route_map:jinbe'], drifted: [] })

    r.strings.set('rbac:roles:jinbe', '{"viewer":["*"]}')
    r.hashes.get('rbac:groups')!.set('staff-viewers', '{"jinbe":["super_admin"]}')
    const drift = await convergeOwned(asRedis(r), 'jinbe', jinbeOwned({ docs: true }), 'jinbe')
    expect(drift.drifted.sort()).toEqual(['rbac:groups#staff-viewers', 'rbac:roles:jinbe'])
    expect(r.strings.get('rbac:roles:jinbe')).not.toContain('*')
    expect(r.strings.get(OWNED_KEY('jinbe'))).toBeDefined()
  })

  it('holds no wildcard; the docs row only with swagger', () => {
    for (const { slot, value } of jinbeOwned({ docs: false })) expect(value.includes('"*"'), slot.key).toBe(false)
    const routes = (docs: boolean) => jinbeOwned({ docs }).find((o) => o.slot.key === 'rbac:route_map:jinbe')!.value
    expect(routes(false)).not.toContain(DOCS_ROW.path)
    expect(routes(true)).toContain(DOCS_ROW.path)
  })
})
