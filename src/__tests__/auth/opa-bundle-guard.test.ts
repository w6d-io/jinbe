import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'

vi.mock('../../services/scim-token.service.js', () => ({
  scimTokenService: { verify: vi.fn(async (t: string) => (t === 'machine-token' ? { id: 'opa' } : null)) },
}))
vi.mock('../../services/organisation-store.js', () => ({ organisationStoreConfigured: () => true }))
vi.mock('../../services/policy-bundle.service.js', () => ({
  PolicyBundleUnavailableError: class extends Error {},
  policyBundle: async () => ({ revision: 'r1', body: Buffer.from('every rule and everybody') }),
}))

import { opaPolicyBundleRoutes } from '../../routes/opa-bundle-policy.routes.js'

let app: FastifyInstance

beforeAll(async () => {
  app = Fastify()
  // Stands in for the identity extractor: a signed-in operator carries a user context.
  app.addHook('onRequest', async (request) => {
    if (request.headers['x-test-operator']) {
      request.userContext = { id: 'op-1', email: 'op@example.com', name: 'Operator' } as never
    }
  })
  await app.register(opaPolicyBundleRoutes, { prefix: '/api/opa' })
  await app.ready()
})

afterAll(() => app.close())

const machine = { authorization: 'Bearer machine-token' }

describe('OPA bundle routes — who may call them', () => {
  it('refuses the bundle to an anonymous caller', async () => {
    expect((await app.inject({ url: '/api/opa/policy' })).statusCode).toBe(401)
  })

  it('refuses the bundle when the query string names the propagation route', async () => {
    const res = await app.inject({ url: '/api/opa/policy?x=/propagation' })
    expect(res.statusCode).toBe(401)
    expect(res.body).not.toContain('everybody')
  })

  it('refuses a forged engine status report that names the propagation route', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/opa/status?x=/propagation',
      payload: { labels: { id: 'fake' }, bundles: { policy: { active_revision: 'r1' } } },
    })
    expect(res.statusCode).toBe(401)
  })

  it('serves the bundle to the machine credential', async () => {
    expect((await app.inject({ url: '/api/opa/policy', headers: machine })).statusCode).toBe(200)
  })

  it('lets a signed-in operator read the propagation', async () => {
    const res = await app.inject({ url: '/api/opa/propagation', headers: { 'x-test-operator': '1' } })
    expect(res.statusCode).toBe(200)
  })

  it('refuses the propagation to an anonymous caller', async () => {
    expect((await app.inject({ url: '/api/opa/propagation' })).statusCode).toBe(401)
  })

  it('does not let an operator session reach the bundle', async () => {
    const res = await app.inject({ url: '/api/opa/policy', headers: { 'x-test-operator': '1' } })
    expect(res.statusCode).toBe(401)
  })
})
