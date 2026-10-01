import Fastify from 'fastify'
import { describe, expect, it } from 'vitest'
import { z } from 'zod'
import { errorHandler } from '../../../middleware/error-handler.js'
import { SERVICE_NAME_PATTERN } from '../../../services/rbac.service.js'
import { SITE_NAME_PATTERN } from '../../../sites/schemas.js'

// Every 400 for an invalid request has one shape: `details[]` with field + message, and a message a
// client can show as it is (kuma's toast showed a bare "Validation failed" for an org-sites save).

async function app() {
  const a = Fastify()
  a.setErrorHandler(errorHandler)
  a.put('/zod', async (request) => z.object({ services: z.array(z.string().regex(/^[a-z]+$/, 'lowercase only')) }).parse(request.body))
  a.put('/schema', {
    schema: { body: { type: 'object', required: ['organizationId'], properties: { organizationId: { type: 'string' }, services: { type: 'array', items: { type: 'string', pattern: '^[a-z]+$' } } } } },
  }, async () => ({ ok: true }))
  return a
}

describe('error handler: validation errors', () => {
  it('a zod error answers details[] with field + message (path kept) and a joined message', async () => {
    const res = await (await app()).inject({ method: 'PUT', url: '/zod', payload: { services: ['ok', 'Not OK'] } })
    expect(res.statusCode).toBe(400)
    expect(res.json()).toEqual({
      error: 'Validation failed',
      message: 'services.1: lowercase only',
      details: [{ field: 'services.1', path: 'services.1', message: 'lowercase only' }],
    })
  })

  it('a route JSON schema error answers the same shape, the field taken from the instance path', async () => {
    const res = await (await app()).inject({ method: 'PUT', url: '/schema', payload: { organizationId: 'o', services: ['ok', 'BAD'] } })
    expect(res.statusCode).toBe(400)
    const body = res.json()
    expect(body.error).toBe('Validation failed')
    expect(body.details).toEqual([expect.objectContaining({ field: 'services.1', message: expect.stringContaining('pattern') })])
    expect(body.message).toMatch(/^services\.1: /)
  })

  it('a missing required property names that property', async () => {
    const res = await (await app()).inject({ method: 'PUT', url: '/schema', payload: { services: [] } })
    expect(res.json().details).toEqual([expect.objectContaining({ field: 'organizationId' })])
  })
})

describe('site and service names', () => {
  it('every legal site name is a legal service name (site publish writes it into org_service_map)', () => {
    for (const name of ['echo', 'echo-mfa', 'wallets-api', 'wallets-treasury', 'simulation-api', 'a1', `a${'-'.repeat(38)}b`]) {
      expect(SITE_NAME_PATTERN.test(name)).toBe(true)
      expect(SERVICE_NAME_PATTERN.test(name)).toBe(true)
    }
  })
})
