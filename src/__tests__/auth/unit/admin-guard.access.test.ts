import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

// The admin plugin's gate: anonymous → 401 (never 503), signed in without admin:read → 403 — on the
// organisation list and on the new access view alike.

vi.mock('../../../services/authorization-model.service.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../services/authorization-model.service.js')>()
  return {
    ...real,
    platformRightsOf: vi.fn(async () => ({ groups: [], roles: [], permissions: [] })),
    holdsPlatformPermission: vi.fn(async () => false),
  }
})
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue(undefined) },
}))

import { extractIdentity } from '../../../middleware/identity-extractor.js'
import { requireAuth } from '../../../middleware/require-auth.js'
import { adminRoutes } from '../../../routes/admin.routes.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', extractIdentity)
  app.addHook('onRequest', async (request) => {
    if (request.headers['x-test-user']) request.userContext = { id: 'subject-nina', email: 'nina@example.com', name: 'Nina' } as never
  })
  app.addHook('onRequest', requireAuth)
  await app.register(async (api) => { await api.register(adminRoutes, { prefix: '/admin' }) }, { prefix: '/api' })
  await app.ready()
})
afterAll(() => app.close())

describe('admin plugin gate', () => {
  for (const url of ['/api/admin/organizations', '/api/admin/users/id-bob/access']) {
    it(`GET ${url} anonymous → 401`, async () => {
      expect((await app.inject({ url })).statusCode).toBe(401)
    })

    it(`GET ${url} without admin:read → 403`, async () => {
      expect((await app.inject({ url, headers: { 'x-test-user': '1' } })).statusCode).toBe(403)
    })
  }
})
