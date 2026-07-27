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
import { auditEventService } from '../../../services/audit-event.service.js'

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
