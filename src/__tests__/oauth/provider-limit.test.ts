import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import Fastify, { type FastifyInstance } from 'fastify'
import rateLimit from '@fastify/rate-limit'

// Every provider call reaches jinbe from login-ui's pods: the per-caller limit must key on the
// visitor (forwarded address, else their session), never on the pod — or one abuser throttles every
// sign-in. A per-replica ceiling stays behind it.

const h = vi.hoisted(() => ({
  env: { MCP_OAUTH_PROVIDER_CEILING: 3000, TRUST_ENVOY_EXTERNAL_ADDRESS: false, TRUSTED_PROXY_HOPS: 1 } as Record<string, unknown>,
}))

vi.mock('../../config/index.js', async (orig) => {
  const real = (await orig()) as { env: object }
  Object.setPrototypeOf(h.env, real.env)
  return { ...real, env: h.env }
})
vi.mock('../../oauth/login.js', () => ({ loginStep: vi.fn(async () => ({ action: 'redirect', to: 'https://hydra.example.com/next' })) }))

import { installRouteAccess } from '../../policy/route-access.js'
import { oauthProviderRoutes } from '../../oauth/routes.js'
import { PER_CALLER_PER_MINUTE, providerRateKey, resetProviderCeiling } from '../../oauth/provider-limit.js'
import { trustProxySetting } from '../../utils/client-ip.js'

let app: FastifyInstance
beforeEach(async () => {
  h.env.MCP_OAUTH_PROVIDER_CEILING = 3000
  resetProviderCeiling()
  app = Fastify({ trustProxy: trustProxySetting(1) })
  installRouteAccess(app)
  await app.register(rateLimit, { max: 100_000, timeWindow: 60_000 })
  await app.register(oauthProviderRoutes, { prefix: '/api/public/oauth2' })
  await app.ready()
})
afterEach(() => app.close())

const login = (headers: Record<string, string>) => app.inject({ method: 'GET', url: '/api/public/oauth2/login?login_challenge=L', headers })

describe('provider rate limit', () => {
  it('keys each forwarded visitor on their own address: one abuser does not throttle another', async () => {
    for (let i = 0; i < PER_CALLER_PER_MINUTE; i++) expect((await login({ 'x-forwarded-for': '203.0.113.9' })).statusCode).toBe(200)
    expect((await login({ 'x-forwarded-for': '203.0.113.9' })).statusCode).toBe(429)
    expect((await login({ 'x-forwarded-for': '198.51.100.4' })).statusCode).toBe(200)
  })

  it('without a forwarded address, keys on the session cookie (not the pod)', async () => {
    for (let i = 0; i < PER_CALLER_PER_MINUTE; i++) await login({ cookie: 'ory_kratos_session=abuser' })
    expect((await login({ cookie: 'ory_kratos_session=abuser' })).statusCode).toBe(429)
    expect((await login({ cookie: 'ory_kratos_session=someone-else' })).statusCode).toBe(200)
  })

  it('providerRateKey: forwarded address, then an HMAC of the session cookie, then the socket', async () => {
    const req = (headers: Record<string, string>, ip: string, peer = '10.0.0.5') => ({ headers, ip, socket: { remoteAddress: peer } }) as never
    expect(providerRateKey(req({ 'x-forwarded-for': '203.0.113.9' }, '203.0.113.9'))).toBe('ip:203.0.113.9')
    const k = providerRateKey(req({ cookie: 'ory_kratos_session=secret' }, '10.0.0.5'))
    expect(k).toMatch(/^sess:/)
    expect(k).not.toContain('secret')
    expect(providerRateKey(req({}, '10.0.0.5'))).toBe('peer:10.0.0.5')
  })

  it('a per-replica ceiling over all visitors stays as the backstop (made-up cookies escape the per-caller key)', async () => {
    h.env.MCP_OAUTH_PROVIDER_CEILING = 5
    for (let i = 0; i < 5; i++) expect((await login({ cookie: `ory_kratos_session=fake${i}` })).statusCode).toBe(200)
    const res = await login({ cookie: 'ory_kratos_session=fake-next' })
    expect(res.statusCode).toBe(429)
    expect(res.json().error).toBe('rate_limited')
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0)
  })
})
