import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

// Owner decision 2026-09-29 ("Ok a b c d"): (c) a personal key stands on the second factor proven when
// it was created — 30 days at most, only for publish / email change / group grants, never when the key
// opted out; (d) a key may revoke keys; and (2026-09-30) removing people from groups is a deletion.

vi.mock('../../../services/audit-event.service.js', () => ({ auditEventService: { emit: vi.fn().mockResolvedValue(undefined) } }))
// The write budget's counter: always under budget here.
vi.mock('../../../services/redis-client.service.js', () => ({
  getRedisClient: () => ({ incr: async () => 1, expire: async () => 1, ttl: async () => 60 }),
}))

import { delegationGate } from '../../../middleware/delegation-gate.js'
import { requireRecentMfa } from '../../../middleware/require-admin.js'
import { keyStepUpVerdict, KEY_STEP_UP_MAX_AGE_MS } from '../../../middleware/delegated-step-up.js'
import { enforcing, recordRoute, resetDeclaredRoutes } from '../../../policy/declared-routes.js'

const guard = (permission: string) => enforcing(async () => {}, permission)
const ok = async () => ({ ok: true })
const DAY = 24 * 3600 * 1000

type Who = { kind?: 'personal' | 'oauth'; at?: string | null; actions?: boolean; scopes?: string; session?: boolean; until?: string }

let app: FastifyInstance
beforeAll(async () => {
  resetDeclaredRoutes()
  app = Fastify()
  app.addHook('onRoute', (route) => recordRoute(route.method, route.url, [route.preHandler], () => false))
  app.addHook('onRequest', async (request: FastifyRequest) => {
    const who = JSON.parse((request.headers['x-who'] as string | undefined) ?? '{}') as Who
    if (who.session) {
      request.userContext = { email: 'ann@acme.io', id: 'user-1', name: 'Ann', authVia: 'session', aal: 'aal1' } as never
      return
    }
    request.userContext = {
      email: 'ann@acme.io', id: 'user-1', name: 'Ann', authVia: 'delegated',
      delegation: {
        clientId: 'key-1', scopes: (who.scopes ?? '').split(' ').filter(Boolean), kind: who.kind ?? 'personal', via: 'auth-mcp',
        ...(who.kind === 'oauth'
          ? { ...(who.at ? { stepUpAt: who.at } : {}), ...(who.actions !== undefined ? { stepUpActions: who.actions } : {}), ...(who.until ? { stepUpUntil: who.until } : {}) }
          : { ...(who.at ? { keyStepUpAt: who.at } : {}), ...(who.actions !== undefined ? { keyStepUpActions: who.actions } : {}) }),
      },
    } as never
  })
  app.addHook('preHandler', delegationGate)
  app.post('/api/admin/sites/:name/apply', { preHandler: [guard('sites:apply'), requireRecentMfa] }, ok)
  app.put('/api/admin/settings/second-factor', { preHandler: [guard('settings.signin:write'), requireRecentMfa] }, ok)
  app.delete('/api/me/api-keys/:clientId', ok)
  app.delete('/api/me/mcp/connections/:clientId', ok)
  app.get('/api/me/mcp/connections', ok)
  app.delete('/api/me/mcp/connections', ok)
  app.delete('/api/organizations/:organizationId/api-keys/:clientId', { preHandler: guard('org.keys:revoke') }, ok)
  app.delete('/api/admin/rbac/groups/:name/members/:email', { preHandler: guard('groups.members:revoke') }, ok)
  app.delete('/api/admin/sites/:name', { preHandler: guard('sites:delete') }, ok)
  await app.ready()
})
afterAll(() => app.close())

const call = (method: 'POST' | 'PUT' | 'DELETE', url: string, who: Who) =>
  app.inject({ method, url, headers: { 'x-who': JSON.stringify(who) } })

const fresh = () => new Date(Date.now() - DAY).toISOString()

describe('(c) a personal key stands on its creation-time second factor', () => {
  it('lets a personal key with a recent proof publish (sites:apply)', async () => {
    const res = await call('POST', '/api/admin/sites/x/apply', { at: fresh(), scopes: 'sites:apply' })
    expect(res.statusCode).toBe(200)
  })

  it('refuses when the proof is older than 30 days, absent, opted out, or the token is not a personal key', async () => {
    const old = new Date(Date.now() - KEY_STEP_UP_MAX_AGE_MS - DAY).toISOString()
    for (const who of [
      { at: old, scopes: 'sites:apply' },
      { at: null, scopes: 'sites:apply' },
      { at: fresh(), actions: false, scopes: 'sites:apply' },
      { kind: 'oauth' as const, at: fresh(), actions: true, scopes: 'sites:apply' },
    ]) {
      const res = await call('POST', '/api/admin/sites/x/apply', who)
      expect(res.statusCode).toBe(422)
      expect(res.json().error).toBe('step_up_unavailable')
    }
  })

  it('never covers a permission outside the three (sign-in settings stay with a person)', async () => {
    const res = await call('PUT', '/api/admin/settings/second-factor', { at: fresh(), scopes: 'settings.signin:write' })
    expect(res.statusCode).toBe(403)
  })

  it('a browser session still needs its own fresh second factor', async () => {
    const res = await call('POST', '/api/admin/sites/x/apply', { session: true })
    expect(res.statusCode).toBe(422)
    expect(res.json().error).toBe('reauth_required')
  })

  it('names why it refuses', () => {
    const req = { method: 'PUT', url: '/x', routeOptions: { url: '/x' }, userContext: { authVia: 'session' } } as never
    expect(keyStepUpVerdict(req)).toEqual({ ok: false, reason: 'not_delegated' })
  })
})

describe('D1 (2026-09-30): a browser sign-in stands on its consent-time second factor, within its window', () => {
  const hourAgo = () => new Date(Date.now() - 3600_000).toISOString()
  const later = () => new Date(Date.now() + 11 * 3600_000).toISOString()

  it('publishes when protected actions were allowed at consent and the window is still open', async () => {
    const res = await call('POST', '/api/admin/sites/x/apply', { kind: 'oauth', at: hourAgo(), actions: true, until: later(), scopes: 'sites:apply' })
    expect(res.statusCode).toBe(200)
  })

  it('refuses past the window, without the consent tick, without a proof, or outside the four permissions', async () => {
    for (const who of [
      { kind: 'oauth' as const, at: hourAgo(), actions: true, until: new Date(Date.now() - 1000).toISOString(), scopes: 'sites:apply' },
      { kind: 'oauth' as const, at: hourAgo(), actions: false, until: later(), scopes: 'sites:apply' },
      { kind: 'oauth' as const, at: null, actions: true, until: later(), scopes: 'sites:apply' },
      { kind: 'oauth' as const, at: hourAgo(), actions: true, scopes: 'sites:apply' },
    ]) {
      const res = await call('POST', '/api/admin/sites/x/apply', who)
      expect(res.statusCode).toBe(422)
    }
    const settings = await call('PUT', '/api/admin/settings/second-factor', { kind: 'oauth', at: hourAgo(), actions: true, until: later(), scopes: 'settings.signin:write' })
    expect(settings.statusCode).toBe(403)
  })

  it('names the proof it stood on', () => {
    const at = new Date(Date.now() - 3600_000).toISOString()
    const req = {
      method: 'POST', url: '/api/admin/sites/x/apply', routeOptions: { url: '/api/admin/sites/:name/apply' },
      userContext: { authVia: 'delegated', delegation: { kind: 'oauth', clientId: 'c', scopes: ['sites:apply'], via: 'auth-mcp', stepUpAt: at, stepUpActions: true, stepUpUntil: new Date(Date.now() + 3600_000).toISOString() } },
    } as never
    expect(keyStepUpVerdict(req, 'sites:apply')).toEqual({ ok: true, via: 'oauth_consent', provenAt: at })
  })
})

describe('signed-in apps through a token', () => {
  it('may disconnect a sign-in (protective) but never list them', async () => {
    expect((await call('DELETE', '/api/me/mcp/connections/c1', { kind: 'oauth' })).statusCode).toBe(200)
    const list = await app.inject({ method: 'GET', url: '/api/me/mcp/connections', headers: { 'x-who': JSON.stringify({ kind: 'oauth' }) } })
    expect(list.statusCode).toBe(403)
    expect(list.json().reason).toBe('delegation_ineligible:api_keys')
    // Disconnecting ALL of them is a person's call, not a token's.
    expect((await call('DELETE', '/api/me/mcp/connections', { kind: 'oauth' })).statusCode).toBe(403)
  })
})

describe('(d) revoking a key is the one DELETE a key may make', () => {
  it('revokes a personal key and an org key', async () => {
    expect((await call('DELETE', '/api/me/api-keys/k2', {})).statusCode).toBe(200)
    expect((await call('DELETE', '/api/organizations/11111111-1111-1111-1111-111111111111/api-keys/k2', { scopes: 'org.keys:revoke' })).statusCode).toBe(200)
  })
})

describe('deletions stay by hand', () => {
  it('refuses removing people from a group and deleting a site, whatever the scopes', async () => {
    const member = await call('DELETE', '/api/admin/rbac/groups/ops/members/bob@acme.io', { at: fresh(), scopes: 'groups.members:revoke' })
    expect(member.statusCode).toBe(403)
    expect(member.json().reason).toBe('delegation_ineligible:groups.members:revoke')
    const site = await call('DELETE', '/api/admin/sites/x', { at: fresh(), scopes: 'sites:delete' })
    expect(site.statusCode).toBe(403)
    expect(site.json().reason).toBe('delegation_ineligible:sites:delete')
  })
})
