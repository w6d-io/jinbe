import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'

const TOKEN = 'a'.repeat(64)
const env = vi.hoisted(() => ({ OPAL_CLIENT_TOKEN: undefined as string | undefined }))
vi.mock('../../../config/env.js', () => ({ env }))

import { requireOpalClient, redactQueryToken } from '../../../middleware/require-opal-client.js'

function request(url: string, opts: { auth?: string; query?: Record<string, string> } = {}) {
  return {
    url,
    headers: opts.auth ? { authorization: opts.auth } : {},
    query: opts.query ?? {},
  } as unknown as FastifyRequest
}

function reply() {
  const r = { code: 200, status: vi.fn(), send: vi.fn() }
  r.status.mockImplementation((code: number) => ((r.code = code), r))
  r.send.mockImplementation(() => r)
  return r
}

async function run(req: FastifyRequest) {
  const r = reply()
  await requireOpalClient(req, r as unknown as FastifyReply)
  return r
}

describe('requireOpalClient', () => {
  beforeEach(() => {
    env.OPAL_CLIENT_TOKEN = TOKEN
  })

  it('lets the OPAL client through with its bearer token', async () => {
    const r = await run(request('/api/admin/rbac/bindings', { auth: `Bearer ${TOKEN}` }))
    expect(r.status).not.toHaveBeenCalled()
  })

  it('refuses a request without a token', async () => {
    expect((await run(request('/api/admin/rbac/bindings'))).code).toBe(401)
  })

  it('refuses a wrong token of the same length', async () => {
    const r = await run(request('/api/admin/rbac/bindings', { auth: `Bearer ${'b'.repeat(64)}` }))
    expect(r.code).toBe(401)
  })

  it('refuses a prefix of the token', async () => {
    const r = await run(request('/api/admin/rbac/bindings', { auth: `Bearer ${TOKEN.slice(0, 32)}` }))
    expect(r.code).toBe(401)
  })

  it('accepts ?token= on the manifest, where OPAL redirects with it', async () => {
    const r = await run(request(`/api/admin/rbac/opal-datasource?token=${TOKEN}`, { query: { token: TOKEN } }))
    expect(r.status).not.toHaveBeenCalled()
  })

  it('does not accept ?token= on a data route', async () => {
    const r = await run(request(`/api/admin/rbac/bindings?token=${TOKEN}`, { query: { token: TOKEN } }))
    expect(r.code).toBe(401)
  })

  it('refuses everyone when no token is configured', async () => {
    env.OPAL_CLIENT_TOKEN = undefined
    const r = await run(request('/api/admin/rbac/bindings', { auth: 'Bearer undefined' }))
    expect(r.code).toBe(401)
  })
})

describe('redactQueryToken', () => {
  it('hides the token and keeps the rest of the query', () => {
    expect(redactQueryToken('/api/admin/rbac/opal-datasource?token=secret&x=1')).toBe(
      '/api/admin/rbac/opal-datasource?token=[redacted]&x=1',
    )
  })

  it('leaves urls without a token alone', () => {
    expect(redactQueryToken('/api/health?verbose=1')).toBe('/api/health?verbose=1')
  })

  it('passes non-strings through', () => {
    expect(redactQueryToken(undefined)).toBeUndefined()
  })
})
