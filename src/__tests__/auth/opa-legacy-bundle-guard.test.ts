import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

// GET /api/opa/bundle carries data.json (every email → its groups): only an allowed in-cluster
// ServiceAccount gets it, never a session, a delegated token or an anonymous caller.

const s = vi.hoisted(() => ({ env: { INTERNAL_API_ALLOWED_SUBJECTS: ['auth:opa'] as string[] } }))
vi.mock('../../config/index.js', () => ({ env: s.env }))
vi.mock('../../services/opa-bundle.service.js', () => ({
  opaBundleService: { getBundle: vi.fn(async () => ({ etag: '"e1"', buffer: Buffer.from('tgz') })) },
}))

import { opaBundleRoutes } from '../../routes/opa-bundle.routes.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const who = request.headers['x-who'] as string | undefined
    if (who === 'session') request.userContext = { email: 'ann@acme.io', id: 'u1', name: 'Ann', authVia: 'session' }
    if (who?.startsWith('sa:')) {
      const [, namespace, serviceAccount] = who.split(':')
      request.machine = { kind: 'k8s-service-account', username: `system:serviceaccount:${namespace}:${serviceAccount}`, namespace, serviceAccount, uid: null, groups: [], email: 'x@sa' }
      request.userContext = { email: 'x@sa', id: 'k8s:x', name: 'sa', authVia: 'machine' }
    }
  })
  await app.register(opaBundleRoutes, { prefix: '/api/opa' })
  await app.ready()
})
afterAll(() => app.close())

const get = (who?: string) => app.inject({ url: '/api/opa/bundle', headers: who ? { 'x-who': who } : {} })

describe('/api/opa/bundle guard', () => {
  it('refuses anonymous and session callers (401) and unlisted ServiceAccounts (403)', async () => {
    expect((await get()).statusCode).toBe(401)
    expect((await get('session')).statusCode).toBe(401)
    expect((await get('sa:default:random')).statusCode).toBe(403)
  })

  it('serves an allowed ServiceAccount', async () => {
    const res = await get('sa:auth:opa')
    expect(res.statusCode).toBe(200)
    expect(res.headers.etag).toBe('"e1"')
  })
})
