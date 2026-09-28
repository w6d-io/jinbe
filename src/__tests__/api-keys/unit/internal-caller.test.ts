import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

// /api/internal takes an allowed in-cluster ServiceAccount and nothing else: not a session, not a
// user token, not a delegated token, not an unlisted ServiceAccount.

const s = vi.hoisted(() => ({ env: { INTERNAL_API_ALLOWED_SUBJECTS: ['auth:oathkeeper'] as string[] } }))
vi.mock('../../../config/index.js', () => ({ env: s.env }))
vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn().mockResolvedValue(undefined) } }))
vi.mock('../../../services/api-key.service.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../services/api-key.service.js')>()
  return { ...real, apiKeyService: { resolveOrganization: vi.fn(async () => ({ organization_id: 'acme', scopes: ['payroll:read'] })) } }
})
vi.mock('../../../audit/record.js', () => ({ recordApiKeyUse: vi.fn() }))

import { apiKeyInternalRoutes } from '../../../routes/api-key.routes.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const who = request.headers['x-who'] as string | undefined
    if (who === 'session') request.userContext = { email: 'ann@acme.io', id: 'u1', name: 'Ann', authVia: 'session' }
    if (who === 'delegated') request.userContext = { email: 'ann@acme.io', id: 'u1', name: 'Ann', authVia: 'delegated' }
    if (who?.startsWith('sa:')) {
      const [, namespace, serviceAccount] = who.split(':')
      request.machine = { kind: 'k8s-service-account', username: `system:serviceaccount:${namespace}:${serviceAccount}`, namespace, serviceAccount, uid: null, groups: [], email: 'x@sa' }
      request.userContext = { email: 'x@sa', id: 'k8s:x', name: 'sa', authVia: 'machine' }
    }
  })
  await app.register(apiKeyInternalRoutes, { prefix: '/api/internal' })
  await app.ready()
})
afterAll(() => app.close())
beforeEach(() => { s.env.INTERNAL_API_ALLOWED_SUBJECTS = ['auth:oathkeeper'] })

const resolve = (who?: string) =>
  app.inject({ url: '/api/internal/oauth-clients/c1/organization', headers: who ? { 'x-who': who } : {} })

describe('/api/internal guard', () => {
  it('answers an allowed ServiceAccount', async () => {
    const res = await resolve('sa:auth:oathkeeper')
    expect(res.statusCode).toBe(200)
    expect(res.json()).toEqual({ organization_id: 'acme', scopes: ['payroll:read'] })
  })

  it('refuses nobody (401), a session or delegated user (401), an unlisted ServiceAccount (403)', async () => {
    expect((await resolve()).statusCode).toBe(401)
    expect((await resolve('session')).statusCode).toBe(401)
    expect((await resolve('delegated')).statusCode).toBe(401)
    expect((await resolve('sa:default:random')).statusCode).toBe(403)
  })

  it('an empty allow-list refuses everyone', async () => {
    s.env.INTERNAL_API_ALLOWED_SUBJECTS = []
    expect((await resolve('sa:auth:oathkeeper')).statusCode).toBe(403)
  })

  it('namespace:* allows that namespace only', async () => {
    s.env.INTERNAL_API_ALLOWED_SUBJECTS = ['auth:*']
    expect((await resolve('sa:auth:anything')).statusCode).toBe(200)
    expect((await resolve('sa:other:anything')).statusCode).toBe(403)
  })
})
