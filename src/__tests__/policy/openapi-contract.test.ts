import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { readFileSync } from 'fs'
import { parse } from 'yaml'
import type { FastifyInstance } from 'fastify'
import { declaredRoutes, resetDeclaredRoutes, type DeclaredRoute } from '../../policy/declared-routes.js'
import { isCatalogPermission } from '../../policy/catalog.js'
import { isV2Permission, v2Name } from '../../authz-v2/catalogue.js'

/**
 * openapi.yaml ↔ declarations ↔ catalogue (authz-v2-design §3.5, routing-remap §4.3 CI 1). Every
 * operation in the committed spec carries the declaration of its route (x-permission or x-access, and
 * x-org-param, x-step-up …), and every declared operation is in the spec. Regenerate with `npm run build`.
 */

type Op = Record<string, unknown>

/** Declared routes the spec leaves out on purpose (`schema.hide`), each with why. */
const HIDDEN: Record<string, string> = {
  'POST /api/public/sign-in-protection/gate/self-service/:flow': "the gateway's proxy in front of Kratos, not an API",
}
const METHODS = ['get', 'post', 'put', 'patch', 'delete']
const spec = parse(readFileSync(new URL('../../../openapi.yaml', import.meta.url), 'utf8')) as { paths: Record<string, Record<string, Op>> }

/** `/api/x/{id}/` → `/api/x/:id` (the policy strips trailing slashes; swagger writes some). */
const toRoute = (p: string) => (p.length > 1 ? p.replace(/\/$/, '') : p).replace(/\{([^}]+)\}/g, ':$1')

const operations = Object.entries(spec.paths).flatMap(([path, item]) =>
  METHODS.filter((m) => item[m]).map((m) => ({ key: `${m.toUpperCase()} ${toRoute(path)}`, op: item[m] })))

let app: FastifyInstance
let declared: Map<string, DeclaredRoute>

beforeAll(async () => {
  process.env.NODE_ENV = 'development'
  process.env.DEV_BYPASS_AUTH = 'true'
  process.env.ENCRYPTION_KEY = 'x'.repeat(32)
  process.env.DEV_USER_EMAIL = 'dev@localhost.io'
  resetDeclaredRoutes()
  const { buildServer } = await import('../../server.js')
  app = await buildServer()
  await app.ready()
  declared = new Map(
    declaredRoutes()
      .filter((r) => r.method !== 'HEAD' && !r.path.startsWith('/docs'))
      .map((r) => [`${r.method} ${r.path.length > 1 ? r.path.replace(/\/$/, '') : r.path}`, r]),
  )
}, 30_000)
afterAll(async () => { await app?.close() })

describe('openapi.yaml is the declared contract', () => {
  it('every spec operation is a declared route, and every declared route is in the spec', () => {
    const inSpec = new Set(operations.map((o) => o.key))
    expect(operations.map((o) => o.key).filter((k) => !declared.has(k))).toEqual([])
    expect([...declared.keys()].filter((k) => !inSpec.has(k))).toEqual(Object.keys(HIDDEN))
  })

  it('every operation carries x-permission or x-access, never both, equal to its declaration', () => {
    const wrong: string[] = []
    for (const { key, op } of operations) {
      const r = declared.get(key)!
      const permission = op['x-permission']
      const access = op['x-access']
      if ((permission === undefined) === (access === undefined)) wrong.push(`${key}: x-permission=${permission} x-access=${access}`)
      if (r.permission && permission !== r.permission) wrong.push(`${key}: x-permission ${permission} ≠ ${r.permission}`)
      if (r.access && access !== r.access) wrong.push(`${key}: x-access ${access} ≠ ${r.access}`)
      if ((op['x-org-param'] ?? null) !== (r.org ?? null)) wrong.push(`${key}: x-org-param`)
      if ((op['x-step-up'] ?? false) !== (r.stepUp ?? false)) wrong.push(`${key}: x-step-up`)
      if ((op['x-model'] ?? null) !== (r.model ?? null)) wrong.push(`${key}: x-model`)
      if (r.access === 'machine' && op['x-edge'] !== (r.edge === true)) wrong.push(`${key}: x-edge`)
    }
    expect(wrong).toEqual([])
  })

  it('every x-permission is a catalogue permission, and its x-permission-v2 a v2 one matching the route shape', () => {
    const wrong: string[] = []
    for (const { key, op } of operations) {
      const p = op['x-permission'] as string | undefined
      if (!p) continue
      if (!isCatalogPermission(p)) wrong.push(`${key}: ${p} not in the catalogue`)
      if (op['x-model'] === 'v1') continue
      const v2 = op['x-permission-v2'] as string | undefined
      if (!v2 || !isV2Permission(v2) || v2 !== v2Name(p, !!op['x-org-param'])) wrong.push(`${key}: x-permission-v2 ${v2}`)
    }
    expect(wrong).toEqual([])
  })

  it('the committed spec is what the running server publishes', () => {
    const live = app.swagger() as { paths: Record<string, Record<string, Op>> }
    const strip = (paths: Record<string, Record<string, Op>>) => Object.fromEntries(Object.entries(paths)
      .map(([p, item]) => [p, Object.fromEntries(METHODS.filter((m) => item[m]).map((m) => [m, Object.fromEntries(Object.entries(item[m]).filter(([k]) => k.startsWith('x-')))]))]))
    expect(strip(spec.paths)).toEqual(strip(live.paths))
  })
})
