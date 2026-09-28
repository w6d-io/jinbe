import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { parseSpecSync } from '../../../sites/openapi/parse.js'
import { plan, type BaseSite, type Decision } from '../../../sites/openapi/plan.js'
import type { ImportOptions } from '../../../sites/openapi/map.js'
import type { Route } from '../../../sites/schemas.js'

// W2: spec → site routes. The spec is untrusted: what lowers protection is only ever a suggestion,
// no security means a permission or deny (never public), re-import keys on `op`, pinned routes are
// kept, removed operations are denied, not deleted.

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8')
const spec = (src: string) => parseSpecSync(src)
const yaml = (paths: string, extra = '') => spec(`openapi: 3.0.0\ninfo: { title: t, version: '1' }\n${extra}paths:\n${paths}`)

const OPTIONS: ImportOptions = { basePathMode: 'prepend', resourceFrom: 'tag', listAsRead: false }
const base = (over: Partial<BaseSite> = {}): BaseSite => ({
  gates: [{ id: 'web', anonymous: false }, { id: 'public', anonymous: true }],
  catchAllGate: 'web',
  items: [],
  roles: { admin: ['*'], viewer: ['pets:read', 'pets:list'] },
  hasLogin: false,
  ...over,
})
const run = (s: ReturnType<typeof spec>, b = base(), decisions: Decision[] = [], options: Partial<ImportOptions> = {}, opts = {}) => plan(s, b, { ...OPTIONS, ...options }, decisions, opts)
const row = (p: ReturnType<typeof plan>, op: string) => p.rows.find((r) => r.op === op)!

describe('mapping', () => {
  it('one route per operation on the catch-all gate, {p} → :p, base path prepended, host ignored', () => {
    const p = run(spec(fixture('petstore-2.0.json')))
    expect(p.items).toEqual([
      { id: 'list-pets', methods: ['GET'], path: '/v1/pets', gate: 'web', access: { kind: 'permission', permission: 'pets:list' }, source: 'openapi', op: 'listPets' },
      { id: 'create-pets', methods: ['POST'], path: '/v1/pets', gate: 'web', access: { kind: 'permission', permission: 'pets:create' }, source: 'openapi', op: 'createPets' },
      { id: 'show-pet-by-id', methods: ['GET'], path: '/v1/pets/:petId', gate: 'web', access: { kind: 'permission', permission: 'pets:read' }, source: 'openapi', op: 'showPetById' },
    ])
    expect(JSON.stringify(p)).not.toContain('10.0.0.1')
  })

  it('no security anywhere: a derived permission, else deny — never public, never signed-in', () => {
    const p = run(yaml('  /x/{a}/{b}:\n    get: {}\n  /things:\n    post: { tags: [things] }\n'))
    expect(row(p, 'POST /things').route!.access).toEqual({ kind: 'permission', permission: 'things:create' })
    expect(row(p, 'GET /x/{a}/{b}').route!.access).toEqual({ kind: 'permission', permission: 'x:read' })
    // Nothing to derive a resource from (param-only path, no tag, no operationId): denied, and it blocks until decided.
    const none = run(yaml('  /{a}:\n    get: {}\n'))
    expect(row(none, 'GET /{a}').route!.access).toEqual({ kind: 'deny' })
    expect(none.blocking.map((b) => b.code)).toEqual(['unmapped'])
    expect(run(yaml('  /{a}:\n    get: {}\n'), base(), [], {}, { acceptDenied: true }).blocking).toEqual([])
    expect(p.items.concat(none.items).some((r) => ['public', 'signed-in'].includes((r as Route).access.kind))).toBe(false)
  })

  it('security: [] only suggests public; applying it needs the decision AND confirm', () => {
    const s = spec(fixture('petstore-3.0.yaml'))
    const health = row(run(s), 'health')
    expect(health.route!.access.kind).toBe('permission')
    expect(health.suggestion).toMatchObject({ access: { kind: 'public' }, from: 'security: []', needsConfirm: true })

    const unconfirmed = run(s, base(), [{ op: 'health', access: { kind: 'public' } }])
    expect(unconfirmed.blocking.map((b) => b.code)).toContain('confirmation_required')

    const confirmed = run(s, base(), [{ op: 'health', access: { kind: 'public' }, confirm: true }])
    expect(confirmed.blocking).toEqual([])
    expect(row(confirmed, 'health').route).toMatchObject({ access: { kind: 'public' }, gate: 'public', pinned: true })
    expect(row(confirmed, 'health').risk.map((f) => f.code)).toContain('spec_lowers_protection')
  })

  it('x-w6d-access public on DELETE /admin/users/{id}: a suggestion rated high (public write, admin path)', () => {
    const r = row(run(spec(fixture('public-delete-admin.yaml'))), 'deleteUser')
    expect(r.route!.access).toEqual({ kind: 'permission', permission: 'users:delete' })
    expect(r.suggestion!.risk.filter((f) => f.level === 'high').map((f) => f.code).sort()).toEqual(['public_sensitive_path', 'public_write', 'spec_lowers_protection'])
    const applied = run(spec(fixture('public-delete-admin.yaml')), base(), [{ op: 'deleteUser', access: { kind: 'public' }, confirm: true }])
    expect(applied.risk.level).toBe('high')
  })

  it('root x-w6d.defaultAccess: public is refused (never makes anything public)', () => {
    const p = run(spec(fixture('root-default-public.yaml')))
    expect(row(p, 'listThings').route!.access).toEqual({ kind: 'permission', permission: 'things:list' })
  })

  it('x-w6d vocabulary: permission, deny, org param, route id, skip, 2FA; x-rbac-* aliases', () => {
    const p = run(yaml([
      '  /a/{tenant_id}/b:',
      '    get: { operationId: a, x-w6d-permission: "billing:read", x-w6d-route-id: bill-read, x-w6d-2fa: true }',
      '  /c:',
      '    get: { operationId: c, x-rbac-permission: "c:see" }',
      '    post: { operationId: c2, x-w6d-access: deny }',
      '    put: { operationId: c3, x-w6d-skip: true }',
      '    patch: { operationId: c4, x-rbac-public: true, tags: [c] }',
      '    delete: { operationId: c5, x-w6d-permission: "NOT A PERMISSION", tags: [c] }',
    ].join('\n') + '\n'), base({ hasLogin: true }))
    expect(row(p, 'a').route).toMatchObject({ id: 'bill-read', access: { kind: 'permission', permission: 'billing:read' }, orgParam: 'tenant_id' })
    expect(p.twoFactorRoutes).toEqual(['bill-read'])
    expect(row(p, 'c').route!.access).toEqual({ kind: 'permission', permission: 'c:see' })
    expect(row(p, 'c2').route!.access).toEqual({ kind: 'deny' })
    expect(row(p, 'c3').status).toBe('skipped')
    expect(row(p, 'c4')).toMatchObject({ route: { access: { kind: 'permission', permission: 'c:update' } }, suggestion: { access: { kind: 'public' }, from: 'x-rbac-public' } })
    expect(row(p, 'c5').route!.access).toEqual({ kind: 'permission', permission: 'c:delete' })
  })

  it('suggests the organization parameter only when exactly one looks like one', () => {
    const p = run(spec(fixture('petstore-3.1.yaml')))
    expect(row(p, 'listOrgPets').route).toMatchObject({ path: '/api/orgs/:orgId/pets', orgParam: 'orgId' })
    expect(row(run(yaml('  /o/{orgId}/t/{tenantId}:\n    get: { tags: [t] }\n')), 'GET /o/{orgId}/t/{tenantId}').route!.orgParam).toBeUndefined()
  })

  it('a deprecated operation is proposed denied', () => {
    expect(row(run(spec(fixture('petstore-3.1.yaml'))), 'deleteOrgPets')).toMatchObject({ route: { access: { kind: 'deny' } }, source: 'deprecated' })
  })

  it('hostile paths are skipped as unsupported, partial templates flagged broadened', () => {
    const p = run(spec(fixture('paths-hostile.yaml')))
    expect(Object.fromEntries(p.rows.map((r) => [r.op, r.status]))).toMatchObject({ redos: 'unsupported', dotdot: 'unsupported', star: 'unsupported', traversal: 'unsupported', twoVars: 'added', report: 'added', fine: 'added' })
    expect(row(p, 'report').risk.map((f) => f.code)).toContain('broadened')
  })

  it('operationIds that slug alike get distinct route ids', () => {
    const ids = run(spec(fixture('opid-collision.yaml'))).items.map((r) => (r as Route).id)
    expect(ids[0]).toBe('get-thing')
    expect(new Set(ids).size).toBe(3)
    for (const id of ids) expect(id).toMatch(/^[a-z][a-z0-9-]{0,31}$/)
  })

  it('two operations on one shape with different access need a decision', () => {
    const p = run(spec(fixture('shape-conflict.yaml')))
    expect(p.blocking.map((b) => b.code)).toContain('shape_conflict')
    expect(run(spec(fixture('shape-conflict.yaml')), base(), [{ op: 'getItemByName', skip: true }]).blocking).toEqual([])
  })

  it('a route outside the site prefix is not imported; the base path option places it', () => {
    const s = spec(fixture('petstore-3.0.yaml'))
    expect(run(s, base({ prefix: '/shop' })).rows.every((r) => r.status === 'unsupported')).toBe(true)
    expect(row(run(s, base({ prefix: '/shop' }), [], { basePath: '/shop/v1' }), 'listPets').route!.path).toBe('/shop/v1/pets')
  })

  it('flags a permission no role grants', () => {
    const r = row(run(spec(fixture('petstore-2.0.json'))), 'createPets')
    expect(r.risk.map((f) => f.code)).toContain('permission_not_granted')
  })

  it('refuses decisions it cannot honour', () => {
    const s = spec(fixture('petstore-2.0.json'))
    const codes = (d: Decision[]) => run(s, base(), d).blocking.map((b) => b.code)
    expect(codes([{ op: 'nope', skip: true }])).toEqual(['unknown_op'])
    expect(codes([{ op: 'listPets', gate: 'ghost' }])).toEqual(['unknown_gate'])
    expect(codes([{ op: 'showPetById', orgParam: 'orgId' }])).toEqual(['invalid_org_param'])
    expect(run(s, base({ gates: [{ id: 'web', anonymous: false }] }), [{ op: 'listPets', access: { kind: 'public' }, confirm: true }]).blocking.map((b) => b.code)).toEqual(['no_public_gate'])
  })
})

describe('re-import', () => {
  const s = spec(fixture('petstore-2.0.json'))

  it('is idempotent: the same spec again changes nothing', () => {
    const first = run(s)
    const again = run(s, base({ items: first.items }))
    expect(again.changed).toBe(false)
    expect(again.counts).toMatchObject({ added: 0, changed: 0, removed: 0, unchanged: 3 })
    expect(again.items).toEqual(first.items)
  })

  it('never touches a pinned route', () => {
    const first = run(s).items as Route[]
    const edited = first.map((r) => (r.op === 'listPets' ? { ...r, access: { kind: 'signed-in' as const }, pinned: true } : r))
    const again = run(s, base({ items: edited }))
    expect(row(again, 'listPets')).toMatchObject({ status: 'pinned', reasons: ['kept your change'] })
    expect((again.items as Route[]).find((r) => r.op === 'listPets')!.access).toEqual({ kind: 'signed-in' })
  })

  it('denies an operation gone from the spec instead of deleting it; removes it only when asked', () => {
    const first = run(s).items
    const doc = JSON.parse(fixture('petstore-2.0.json'))
    delete doc.paths['/pets'].post
    const shorter = spec(JSON.stringify(doc))
    const again = run(shorter, base({ items: first }))
    expect(row(again, 'createPets')).toMatchObject({ status: 'removed', route: { access: { kind: 'deny' } } })
    expect(again.items).toHaveLength(3)
    const removed = run(shorter, base({ items: first }), [{ op: 'createPets', remove: true }])
    expect(removed.items).toHaveLength(2)
  })

  it('a confirm-only decision leaves a pinned route alone', () => {
    const first = run(s).items as Route[]
    const edited = first.map((r) => (r.op === 'listPets' ? { ...r, access: { kind: 'signed-in' as const }, pinned: true } : r))
    expect(row(run(s, base({ items: edited }), [{ op: 'listPets', confirm: true }]), 'listPets').status).toBe('pinned')
  })

  it('never replaces a route written by hand', () => {
    const manual: Route = { id: 'mine', methods: ['GET'], path: '/v1/pets', gate: 'web', access: { kind: 'signed-in' }, source: 'manual' }
    const p = run(s, base({ items: [manual] }))
    expect(row(p, 'listPets').status).toBe('manual')
    expect(p.items[0]).toEqual(manual)
  })

  it('a changed permission is a change; permission → signed-in is high', () => {
    const first = run(s).items as Route[]
    const changed = spec(fixture('petstore-2.0.json').replace('"operationId": "listPets", "tags": ["pets"]', '"operationId": "listPets", "tags": ["animals"]'))
    expect(row(run(changed, base({ items: first })), 'listPets')).toMatchObject({ status: 'changed', route: { access: { permission: 'animals:list' } } })
    const lowered = run(s, base({ items: first }), [{ op: 'listPets', access: { kind: 'signed-in' }, confirm: true }])
    expect(row(lowered, 'listPets').risk.map((f) => f.code)).toContain('permission_removed')
  })

  it('more than 20 routes opened at once is bulk_public', () => {
    const paths = Array.from({ length: 21 }, (_, i) => `  /p${i}:\n    get: { operationId: p${i}, security: [] }\n`).join('')
    const s21 = yaml(paths)
    const p = run(s21, base(), s21.operations.map((o) => ({ op: o.operationId!, access: { kind: 'public' as const }, confirm: true })))
    expect(p.risk.flags.map((f) => f.code)).toContain('bulk_public')
  })
})

describe('scale', () => {
  it('plans 2 000 operations (a GitHub-sized spec) quickly, on the catch-all gate', () => {
    const paths: Record<string, unknown> = {}
    for (let i = 0; i < 1000; i++) {
      paths[`/repos/{owner}/{repo}/r${i}`] = { get: { operationId: `get-r${i}`, tags: [`r${i % 40}`] }, post: { operationId: `post-r${i}`, tags: [`r${i % 40}`] } }
    }
    const big = spec(JSON.stringify({ openapi: '3.0.3', info: { title: 'big', version: '1' }, paths, components: { schemas: { A: { properties: { b: { $ref: '#/components/schemas/B' } } }, B: { properties: { a: { $ref: '#/components/schemas/A' } } } } } }))
    const t = Date.now()
    const p = run(big)
    expect(Date.now() - t).toBeLessThan(2000)
    expect(p.items).toHaveLength(2000)
    expect((p.items as Route[]).every((r) => r.gate === 'web')).toBe(true)
  })
})
