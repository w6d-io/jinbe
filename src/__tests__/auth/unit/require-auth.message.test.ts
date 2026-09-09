import { describe, it, expect, vi } from 'vitest'
import type { FastifyRequest, FastifyReply } from 'fastify'

// A 401 that lists the accepted credentials and omits one sends the reader looking for a method
// that was never going to work. The list is derived from the deployment, so it cannot drift.

const { envState } = vi.hoisted(() => ({
  envState: { env: { AUTH_COOKIE_ENABLED: true, AUTH_BEARER_ENABLED: false } as Record<string, unknown> },
}))

vi.mock('../../../config/index.js', () => ({ env: envState.env }))
vi.mock('../../../services/audit-event.service.js', () => ({
  auditEventService: { emit: vi.fn(async () => {}) },
}))

const { requireAuth } = await import('../../../middleware/require-auth.js')

async function denialMessage(): Promise<string> {
  let body: { message?: string } = {}
  const reply = {
    status: () => reply,
    send: (payload: { message?: string }) => {
      body = payload
      return reply
    },
  } as unknown as FastifyReply
  const request = {
    method: 'GET',
    url: '/api/me/organizations',
    routerPath: '/api/me/organizations',
    headers: {},
    ip: '10.0.0.1',
  } as unknown as FastifyRequest

  await requireAuth(request, reply)
  return body.message ?? ''
}

describe('the 401 lists what this deployment actually accepts', () => {
  it('names the bearer credential once bearer authentication is on', async () => {
    envState.env.AUTH_BEARER_ENABLED = true
    envState.env.AUTH_COOKIE_ENABLED = true

    const message = await denialMessage()
    expect(message).toContain('ory_kratos_session cookie')
    expect(message).toContain('OIDC access token')
    expect(message).toContain('ServiceAccount token')
  })

  it('does not offer a bearer credential that would be refused', async () => {
    envState.env.AUTH_BEARER_ENABLED = false

    const message = await denialMessage()
    expect(message).not.toContain('OIDC access token')
    expect(message).toContain('ory_kratos_session cookie')
  })

  it('does not offer the cookie once it is turned off', async () => {
    envState.env.AUTH_COOKIE_ENABLED = false
    envState.env.AUTH_BEARER_ENABLED = true

    const message = await denialMessage()
    expect(message).not.toContain('ory_kratos_session')
    expect(message).toContain('OIDC access token')
  })
})
