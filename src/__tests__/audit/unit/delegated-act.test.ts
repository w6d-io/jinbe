import { describe, it, expect, vi } from 'vitest'

// A delegated call is recorded as the USER acting, with the client in actor.act and
// auth.method 'delegated'; a delegated caller can never pass a step-up; the site authorizer payload
// carries the client id and its token's scopes.

const mockEnv = vi.hoisted(() => ({
  env: { LOG_LEVEL: 'error', NODE_ENV: 'test', AUDIT_HMAC_KEY: 'k'.repeat(40), K8S_SA_EMAIL_DOMAIN: 'serviceaccount.cluster.local' },
}))
vi.mock('../../../config/env.js', () => mockEnv)
vi.mock('../../../config/index.js', () => mockEnv)
vi.mock('../../../services/redis-client.service.js', () => ({ getRedisClient: () => ({}) }))

import { buildEvent } from '../../../audit/v1/emitter.js'
import { auditEventV1Schema } from '../../../audit/v1/schema.js'
import { auditActor } from '../../../utils/audit-actor.js'
import { canProveSecondFactor, stepUpFailure } from '../../../services/step-up.js'
import { platformPayload } from '../../../sites/render.js'
import type { FastifyRequest } from 'fastify'

describe('audit/v1 actor.act', () => {
  it('is filled from a delegated request and validates', () => {
    const request = {
      headers: {},
      ip: '10.0.0.1',
      userContext: {
        email: 'ann@acme.io', id: 'user-1', name: 'Ann', authVia: 'delegated',
        delegation: { clientId: 'claude-code', scopes: ['sites:read'], org: 'acme', kind: 'oauth', via: 'auth-mcp' },
      },
    } as unknown as FastifyRequest
    const actor = auditActor(request)
    expect(actor.act).toEqual({ client_id: 'claude-code', via: 'auth-mcp', kind: 'oauth' })

    const event = buildEvent({ event: 'access.denied', result: 'denied', actor })
    expect(event.actor).toMatchObject({ type: 'user', id: 'user-1', act: { client_id: 'claude-code', via: 'auth-mcp', kind: 'oauth' }, auth: { method: 'delegated' } })
    expect(auditEventV1Schema.safeParse(event).success).toBe(true)
  })

  it('is absent for a session', () => {
    const request = { headers: {}, userContext: { email: 'a@x.io', id: 'u', name: 'A', authVia: 'session' } } as unknown as FastifyRequest
    expect(auditActor(request).act).toBeUndefined()
    expect(buildEvent({ event: 'access.denied', actor: auditActor(request) }).actor.act).toBeUndefined()
  })
})

describe('step-up with a delegated token', () => {
  it('is unprovable — never satisfied, never "re-verify"', () => {
    const fresh = { aal: 'aal2', secondFactorAt: new Date(), authVia: 'delegated' as const }
    expect(canProveSecondFactor(fresh)).toBe(false)
    expect(stepUpFailure(fresh)).toBe('unprovable')
  })
})

describe('site authorizer payload', () => {
  it('passes the client id and token scope only for an OAuth2 client', () => {
    const payload = platformPayload('payroll')
    expect(payload).toContain('"client_id": "{{ if .Extra }}{{ if .Extra.client_id }}{{ print .Extra.client_id }}{{ end }}{{ end }}"')
    expect(payload).toContain('{{ if .Extra.client_id }}{{ if .Extra.scope }}{{ print .Extra.scope }}{{ end }}{{ end }}')
    // Rendered with every template emptied, it is still JSON.
    expect(() => JSON.parse(payload.replace(/\{\{[^}]*\}\}/g, '').replace(/"client": [a-z]+,/, '"client": false,'))).not.toThrow()
  })
})
