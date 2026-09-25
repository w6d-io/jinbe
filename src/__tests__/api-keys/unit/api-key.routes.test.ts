import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'

// J-3: API-key routes need THAT org (requireOrgPermission('org:manage_api_keys')), and a refused
// scope keeps its explanation on the wire.

const ORG = '11111111-1111-1111-1111-111111111111'

const s = vi.hoisted(() => ({ guardPermission: '' as string, guardParam: '' as string }))

vi.mock('../../../middleware/require-org-permission.js', () => ({
  requireOrgPermission: vi.fn((permission: string, param = 'organizationId') => {
    s.guardPermission = permission
    s.guardParam = param
    return async (request: FastifyRequest, reply: FastifyReply) => {
      if (request.headers['x-test-refuse']) return reply.status(403).send({ error: 'Forbidden', message: 'other org' })
    }
  }),
}))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue(undefined) },
}))
vi.mock('../../../services/api-key.service.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../services/api-key.service.js')>()
  return {
    ...real,
    apiKeyService: {
      create: vi.fn(async () => {
        throw new real.ApiKeyError(400, 'One or more requested scopes are not allowed', {
          invalid_scopes: ['root'],
          allowed_scopes: ['read', 'write'],
        })
      }),
      list: vi.fn(async () => []),
    },
  }
})

import { apiKeyRoutes } from '../../../routes/api-key.routes.js'

let app: FastifyInstance
beforeAll(async () => {
  app = Fastify()
  await app.register(apiKeyRoutes, { prefix: '/api/organizations/:organizationId' })
  await app.ready()
})
afterAll(() => app.close())

describe('API-key routes', () => {
  it('are guarded by org:manage_api_keys on :organizationId', () => {
    expect(s.guardPermission).toBe('org:manage_api_keys')
    expect(s.guardParam).toBe('organizationId')
  })

  it('refuse when the guard refuses (e.g. a service admin of another org)', async () => {
    const res = await app.inject({ url: `/api/organizations/${ORG}/api-keys`, headers: { 'x-test-refuse': '1' } })
    expect(res.statusCode).toBe(403)
  })

  it('a refused scope keeps details.allowed_scopes in the 400 body', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/organizations/${ORG}/api-keys`,
      payload: { label: 'ci', scopes: ['root'] },
    })
    expect(res.statusCode).toBe(400)
    expect(res.json()).toEqual({
      error: 'Bad Request',
      message: 'One or more requested scopes are not allowed',
      details: { invalid_scopes: ['root'], allowed_scopes: ['read', 'write'] },
    })
  })
})
