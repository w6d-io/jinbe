import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { PERMISSIONS } from '../../../policy/catalog.js'
import { installRouteAccess } from '../../../policy/route-access.js'
import Fastify, { type FastifyInstance } from 'fastify'

// Replacing the whole access model (bundle import, S3 restore, history rollback) and changing how
// everybody signs in: super_admin AND a second factor proven within 15 minutes. Without the second,
// a stolen session could do any of them.

vi.mock('../../../authz/opa.js', async () => (await import('../../helpers/opa-authz-mock.js')).opaAuthzMock())
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn(async () => 'id') } }))
vi.mock('../../../services/rbac-bundle.service.js', () => ({
  ALL_BUNDLE_SECTIONS: [],
  bundleProblem: () => 'Invalid bundle format — missing version or rbac fields.',
  rbacBundleService: {
    import: vi.fn(async () => ({})),
    rollback: vi.fn(async () => ({ entry: { takenAt: 'now', reason: 'pre-import' }, result: {} })),
  },
}))
vi.mock('../../../services/backup-store.service.js', () => ({ backupStore: { enabled: () => false } }))
vi.mock('../../../services/kratos-config.service.js', () => ({
  KNOWN_METHODS: ['password', 'totp'],
  KratosConfigError: class extends Error {},
  kratosConfigService: { enabled: () => false },
}))

import { rbacBundleRoutes } from '../../../routes/rbac-bundle.routes.js'
import { authConfigRoutes } from '../../../routes/auth-config.routes.js'
import { opaWorld, resetOpaWorld } from '../../helpers/opa-authz-mock.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  installRouteAccess(app)
  app.addHook('onRequest', async (request) => {
    const who = request.headers['x-test-user'] as string
    const fresh = request.headers['x-test-fresh'] === '1'
    request.userContext = {
      id: `id-${who}`, email: `${who}@example.com`, name: who, sessionId: `sess-${who}`,
      aal: fresh ? 'aal2' : 'aal1', secondFactorAt: fresh ? new Date(Date.now() - 60_000) : null, authVia: 'session',
    } as never
  })
  await app.register(rbacBundleRoutes, { prefix: '/api/admin/rbac' })
  await app.register(authConfigRoutes, { prefix: '/api/admin/auth' })
  await app.ready()
})
afterAll(async () => { await app.close() })

beforeEach(() => {
  resetOpaWorld()
  opaWorld.permissions['reader@example.com'] = ['policy.bundle:read', 'settings:read']
  opaWorld.permissions['root@example.com'] = [...PERMISSIONS]
})

const WRITES: Array<[string, string, unknown]> = [
  ['POST', '/api/admin/rbac/bundle/import', { version: 1 }],
  ['POST', '/api/admin/rbac/bundle/backups/restore', { key: 'snap.json' }],
  ['POST', '/api/admin/rbac/bundle/history/h1/rollback', undefined],
  ['PUT', '/api/admin/auth/methods', { password: { enabled: true } }],
]

const call = (method: string, url: string, who: string, fresh: boolean, body: unknown) =>
  app.inject({
    method: method as never, url,
    headers: { 'x-test-user': who, ...(fresh ? { 'x-test-fresh': '1' } : {}) },
    ...(body !== undefined ? { payload: body as never } : {}),
  })

describe('sensitive writes need a fresh second factor', () => {
  it.each(WRITES)('%s %s refuses a super admin without one (422 reauth_required)', async (method, url, body) => {
    const res = await call(method, url, 'root', false, body)
    expect(res.statusCode).toBe(422)
    expect(res.json().error).toBe('reauth_required')
  })

  it.each(WRITES)('%s %s passes the gates with one', async (method, url, body) => {
    expect([401, 403, 422]).not.toContain((await call(method, url, 'root', true, body)).statusCode)
  })

  it.each(WRITES)('%s %s still refuses a read-only administrator', async (method, url, body) => {
    expect((await call(method, url, 'reader', true, body)).statusCode).toBe(403)
  })
})
