import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { KratosSessionService, clearSessionCache, forgetSession, forgetSessionsOf } from '../../services/kratos-session.service.js'
import { extractIdentity } from '../../middleware/identity-extractor.js'
import { KratosService } from '../../services/kratos.service.js'
import { invalidateCachedIdentity } from '../../controllers/webhook.controller.js'
import { configureCache } from '../../cache/swr.js'
import { MemoryCacheStore } from '../../cache/store.js'

/**
 * The short session-validation cache: reads reuse a validation for a few seconds, writes never do,
 * failures are never kept, the raw cookie is never a key, and every revocation jinbe makes (or learns
 * of) drops it on every replica.
 */

const COOKIE = 'ory_kratos_session=super-secret-session-value'
let state: { active: boolean; aal: string; sessionId: string; identityId: string }
const whoami = vi.fn()

function kratosReply() {
  if (!state.active) return { ok: false, status: 401, statusText: 'Unauthorized', json: async () => ({}) }
  return {
    ok: true,
    status: 200,
    json: async () => ({
      id: state.sessionId,
      active: true,
      expires_at: new Date(Date.now() + 3_600_000).toISOString(),
      authenticated_at: new Date().toISOString(),
      authenticator_assurance_level: state.aal,
      authentication_methods: state.aal === 'aal2' ? [{ method: 'password' }, { method: 'totp', aal: 'aal2', completed_at: new Date().toISOString() }] : [{ method: 'password' }],
      identity: { id: state.identityId, traits: { email: 'ana@x.test', name: 'Ana' } },
    }),
  }
}

const req = (method: string) =>
  ({ method, url: '/api/admin/users', headers: { cookie: COOKIE }, log: { debug: vi.fn(), warn: vi.fn() } }) as unknown as FastifyRequest

let store: MemoryCacheStore
beforeEach(() => {
  clearSessionCache()
  store = new MemoryCacheStore()
  configureCache({ enabled: true, disabled: [], store })
  state = { active: true, aal: 'aal1', sessionId: 's-1', identityId: 'id-ana' }
  whoami.mockImplementation(async (url: string) => (String(url).endsWith('/sessions/whoami') ? kratosReply() : { ok: true, status: 204, json: async () => ({}) }))
  global.fetch = whoami as unknown as typeof fetch
})
afterEach(() => {
  vi.useRealTimers()
  configureCache({ enabled: true, disabled: [] })
})

const kratosCalls = () => whoami.mock.calls.filter((c) => String(c[0]).endsWith('/sessions/whoami')).length

describe('reads reuse a validation, writes never do', () => {
  it('a burst of reads with one cookie asks Kratos once', async () => {
    for (let i = 0; i < 20; i++) {
      const r = req('GET')
      await extractIdentity(r, {} as FastifyReply)
      expect(r.userContext?.email).toBe('ana@x.test')
    }
    expect(kratosCalls()).toBe(1)
  })

  it('reads arriving together share ONE validation', async () => {
    await Promise.all(Array.from({ length: 49 }, () => extractIdentity(req('GET'), {} as FastifyReply)))
    expect(kratosCalls()).toBe(1)
  })

  it('every write asks Kratos', async () => {
    await extractIdentity(req('GET'), {} as FastifyReply)
    await extractIdentity(req('POST'), {} as FastifyReply)
    await extractIdentity(req('DELETE'), {} as FastifyReply)
    expect(kratosCalls()).toBe(3)
  })

  it('a revoked session can never write, even inside the TTL', async () => {
    await extractIdentity(req('GET'), {} as FastifyReply)
    state.active = false // revoked in Kratos, behind jinbe's back
    const write = req('PUT')
    await extractIdentity(write, {} as FastifyReply)
    expect(write.userContext).toBeUndefined()
    // … and that write's answer also stops the reads.
    const read = req('GET')
    await extractIdentity(read, {} as FastifyReply)
    expect(read.userContext).toBeUndefined()
  })

  it('a second factor just proven is seen by the write that needs it', async () => {
    await extractIdentity(req('GET'), {} as FastifyReply)
    state.aal = 'aal2'
    const write = req('POST')
    await extractIdentity(write, {} as FastifyReply)
    expect(write.userContext?.aal).toBe('aal2')
  })
})

describe('what is kept, and for how long', () => {
  it('expires after the TTL', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    const svc = new KratosSessionService()
    await svc.validateSession(COOKIE, { allowCached: true })
    vi.setSystemTime(Date.now() + 5_001)
    await svc.validateSession(COOKIE, { allowCached: true })
    expect(kratosCalls()).toBe(2)
  })

  it('never keeps a failure: a fresh login works at once', async () => {
    const svc = new KratosSessionService()
    state.active = false
    expect((await svc.validateSession(COOKIE, { allowCached: true })).session).toBeNull()
    state.active = true
    expect((await svc.validateSession(COOKIE, { allowCached: true })).session?.email).toBe('ana@x.test')
  })

  it('different cookies never share an entry', async () => {
    const svc = new KratosSessionService()
    await svc.validateSession(COOKIE, { allowCached: true })
    state.identityId = 'id-bo'
    const other = await svc.validateSession('ory_kratos_session=another-value', { allowCached: true })
    expect(other.session?.identityId).toBe('id-bo')
    expect(kratosCalls()).toBe(2)
  })

  it('kill switch: SESSION namespace disabled → every read asks Kratos', async () => {
    configureCache({ disabled: ['kratos.session'] })
    const svc = new KratosSessionService()
    await svc.validateSession(COOKIE, { allowCached: true })
    await svc.validateSession(COOKIE, { allowCached: true })
    expect(kratosCalls()).toBe(2)
  })
})

describe('revocations jinbe makes or hears of drop it', () => {
  const primed = async () => {
    const svc = new KratosSessionService()
    await svc.validateSession(COOKIE, { allowCached: true })
    state.active = false
    return svc
  }

  it('revoking the session', async () => {
    const svc = await primed()
    await new KratosService().revokeSession('s-1')
    expect((await svc.validateSession(COOKIE, { allowCached: true })).session).toBeNull()
  })

  it("revoking all the identity's sessions (the second-factor reset does this)", async () => {
    const svc = await primed()
    await new KratosService().revokeAllIdentitySessions('id-ana')
    expect((await svc.validateSession(COOKIE, { allowCached: true })).session).toBeNull()
  })

  it('a Kratos login webhook for the identity (a step-up)', async () => {
    const svc = new KratosSessionService()
    await svc.validateSession(COOKIE, { allowCached: true })
    state.aal = 'aal2'
    invalidateCachedIdentity('login', 'totp', 'id-ana')
    expect((await svc.validateSession(COOKIE, { allowCached: true })).session?.aal).toBe('aal2')
  })

  it('another replica revoking it, over the invalidation channel', async () => {
    const svc = await primed()
    await store.publish('jinbe:cache:invalidate', JSON.stringify({ ns: 'kratos.session', key: 'sid:s-1', origin: 'another-replica' }))
    expect((await svc.validateSession(COOKIE, { allowCached: true })).session).toBeNull()
  })

  it('a validation that was in flight when the session was revoked is not kept', async () => {
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    whoami.mockImplementationOnce(async () => { const answer = kratosReply(); await gate; return answer })
    const svc = new KratosSessionService()
    const slow = svc.validateSession(COOKIE, { allowCached: true })
    await new Promise((r) => setTimeout(r, 5))
    forgetSession('s-1')
    state.active = false
    release()
    expect((await slow).session?.sessionId).toBe('s-1') // it asked before the revocation
    expect((await svc.validateSession(COOKIE, { allowCached: true })).session).toBeNull()
  })

  it('only the named session or identity is dropped', async () => {
    const svc = new KratosSessionService()
    await svc.validateSession(COOKIE, { allowCached: true })
    forgetSession('s-other')
    forgetSessionsOf('id-other')
    await svc.validateSession(COOKIE, { allowCached: true })
    expect(kratosCalls()).toBe(1)
  })
})
