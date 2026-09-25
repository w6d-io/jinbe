import { describe, it, expect, beforeEach, vi } from 'vitest'

// Controlled env so the webhook secret is deterministic. Mutable so a test can
// simulate an unconfigured secret. Hoisted so the vi.mock factory can see it.
const mockState = vi.hoisted(() => ({
  env: {
    KRATOS_WEBHOOK_SECRET: 'top-secret-value' as string | undefined,
    LOG_LEVEL: 'error',
    REDIS_AUDIT_STREAM: 'auth:audit:events',
    REDIS_AUDIT_MAXLEN: 100000,
  },
}))
vi.mock('../../../config/env.js', () => ({ env: mockState.env }))

// Spy on the audit emit so we can assert it is NEVER called on a rejected call.
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn().mockResolvedValue('1-0') },
}))

import { webhookController, verifyKratosWebhookAuth } from '../../../controllers/webhook.controller.js'
import { auditEventService, type AuditEvent } from '../../../services/audit-event.service.js'
import { legacyToV1 } from '../../../audit/v1/legacy-map.js'

function mockRequest(overrides: Record<string, unknown> = {}) {
  return {
    headers: {},
    ip: '10.0.0.1',
    body: {},
    log: { warn: vi.fn(), info: vi.fn(), error: vi.fn(), debug: vi.fn() },
    ...overrides,
  } as never
}

function mockReply() {
  const reply = {
    _status: 200,
    _body: undefined as unknown,
    status: vi.fn(function (this: typeof reply, c: number) { this._status = c; return this }),
    send: vi.fn(function (this: typeof reply, b: unknown) { this._body = b; return this }),
  }
  return reply
}

describe('Kratos webhook — self-authentication (P0-1)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockState.env.KRATOS_WEBHOOK_SECRET = 'top-secret-value'
  })

  it('rejects a call with the WRONG secret and emits nothing', async () => {
    const req = mockRequest({ headers: { 'x-kratos-webhook-secret': 'wrong' }, body: { flow: 'login', identity: { traits: { email: 'a@b.co' } } } })
    const reply = mockReply()
    await webhookController.kratos(req, reply as never)
    expect(reply._status).toBe(401)
    expect(auditEventService.emit).not.toHaveBeenCalled()
  })

  it('rejects a call with NO secret header and emits nothing', async () => {
    const req = mockRequest({ body: { flow: 'login', identity: { traits: { email: 'a@b.co' } } } })
    const reply = mockReply()
    await webhookController.kratos(req, reply as never)
    expect(reply._status).toBe(401)
    expect(auditEventService.emit).not.toHaveBeenCalled()
  })

  it('rejects EVERY call when the secret is not configured (fail-closed)', async () => {
    mockState.env.KRATOS_WEBHOOK_SECRET = undefined
    const req = mockRequest({ headers: { 'x-kratos-webhook-secret': 'anything' }, body: { flow: 'login' } })
    const reply = mockReply()
    await webhookController.kratos(req, reply as never)
    expect(reply._status).toBe(401)
    expect(auditEventService.emit).not.toHaveBeenCalled()
  })

  it('accepts a correct secret and emits an allow-listed auth event', async () => {
    const req = mockRequest({
      headers: { 'x-kratos-webhook-secret': 'top-secret-value' },
      body: { flow: 'login', method: 'password', aal: 'aal1', outcome: 'success', identity: { id: 'uuid-1', traits: { email: 'user@example.com' }, credentials: { password: { config: { hashed_password: 'SECRET' } } } } },
    })
    const reply = mockReply()
    await webhookController.kratos(req, reply as never)

    expect(reply._status).toBe(200)
    expect(auditEventService.emit).toHaveBeenCalledTimes(1)
    const emitted = vi.mocked(auditEventService.emit).mock.calls[0][0] as Record<string, unknown>
    expect(emitted.category).toBe('auth')
    expect(emitted.source).toBe('kratos-webhook')
    // Only the allow-listed detail keys — no raw Kratos payload (no hashed_password).
    expect(Object.keys(emitted.details as object).sort()).toEqual(
      ['aal', 'actorEmail', 'flowType', 'method', 'outcome', 'sessionId'].sort(),
    )
    expect(JSON.stringify(emitted)).not.toContain('hashed_password')
  })

  it('verifyKratosWebhookAuth is constant-time-safe on length mismatch', () => {
    mockState.env.KRATOS_WEBHOOK_SECRET = 'top-secret-value'
    expect(verifyKratosWebhookAuth(mockRequest({ headers: { 'x-kratos-webhook-secret': 'short' } }))).toBe(false)
    expect(verifyKratosWebhookAuth(mockRequest({ headers: { 'x-kratos-webhook-secret': 'top-secret-value' } }))).toBe(true)
    expect(verifyKratosWebhookAuth(mockRequest({ headers: { authorization: 'Bearer top-secret-value' } }))).toBe(true)
  })
})

describe('Kratos webhook — the chart body carries the actor (AUD-0b)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockState.env.KRATOS_WEBHOOK_SECRET = 'top-secret-value'
  })

  // The chart's Jsonnet body: {flow, method, identity_id, identity_email, ip, ua} (+ session_id, aal).
  async function hook(body: Record<string, unknown>) {
    const req = mockRequest({ headers: { 'x-kratos-webhook-secret': 'top-secret-value' }, body })
    const reply = mockReply()
    await webhookController.kratos(req, reply as never)
    expect(reply._status).toBe(200)
    return vi.mocked(auditEventService.emit).mock.calls[0][0] as unknown as AuditEvent
  }
  const chart = { identity_id: 'kratos-uuid-7', identity_email: 'user@example.com', ip: '203.0.113.9', ua: 'Mozilla/5.0 Firefox/130' }

  it('reads identity_id / identity_email, the session id and aal', async () => {
    const e = await hook({ flow: 'login', method: null, ...chart, session_id: 'sess-77', aal: 'aal2' })
    expect(e.actor).toMatchObject({ id: 'kratos-uuid-7', email: 'user@example.com', sessionId: 'sess-77' })
    expect(e.targetId).toBe('kratos-uuid-7')
    expect(e.target).toBe('user:user@example.com')
    expect(e.v1Event).toBe('auth.login.succeeded')

    const v1 = legacyToV1(e)
    expect(v1).toMatchObject({ event: 'auth.login.succeeded', source: 'kratos', actor: { id: 'kratos-uuid-7', sessionId: 'sess-77', aal: 'aal2' } })
    expect(v1.target).toMatchObject({ type: 'user', id: 'kratos-uuid-7' })
  })

  it('accepts the session nested the way Kratos ctx carries it', async () => {
    const e = await hook({ flow: 'login', ...chart, session: { id: 'sess-9', authenticator_assurance_level: 'aal1' } })
    expect(e.actor.sessionId).toBe('sess-9')
    expect(legacyToV1(e).actor.aal).toBe('aal1')
  })

  it.each([
    [{ flow: 'settings', method: 'password' }, 'auth.password.changed'],
    [{ flow: 'settings', method: 'profile' }, 'auth.profile.updated'],
    [{ flow: 'settings', method: 'totp' }, 'auth.mfa.enrolled'],
    [{ flow: 'registration', method: 'password' }, 'auth.registration.succeeded'],
    [{ flow: 'recovery', method: 'code' }, 'auth.recovery.used'],
    [{ flow: 'verification', method: 'code' }, 'auth.verification.succeeded'],
  ])('%o → %s', async (flow, event) => {
    const e = await hook({ ...flow, ...chart })
    expect(e.v1Event).toBe(event)
    expect(e.actor.id).toBe('kratos-uuid-7')
  })
})
