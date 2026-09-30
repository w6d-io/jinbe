import { describe, it, expect } from 'vitest'
import { mergePatch, resolveGates, resolveHandler } from '../../sites/resolved-gates.js'
import type { GatewaySpec } from '../../gateway/kube-gateway.js'

// A gate handler runs with the rule's config merged over the platform's global config (Oathkeeper
// PipelineConfig: RFC 7386 merge patch); each field says whether the rule set it or the platform did.

const spec: GatewaySpec = {
  authenticators: {
    cookie_session: { enabled: true, config: { check_session_url: 'http://kratos/sessions/whoami', preserve_path: true, only: ['ory_kratos_session'] } },
  },
  authorizers: { remote_json: { enabled: true, config: { remote: 'http://opa/decision', forward_response_headers_to_upstream: ['X-User-Groups'], retry: { max_delay: '300ms', give_up_after: '2s' } } } },
  mutators: { header: { enabled: true, config: { headers: { 'X-User': '{{ print .Subject }}' } } } },
  errors: { redirect: { enabled: false } },
  errorFallback: ['json'],
}

describe('mergePatch (RFC 7386)', () => {
  it('merges objects, replaces anything else, and a null removes', () => {
    expect(mergePatch({ a: 1, b: { c: 1, d: [1] } }, { b: { d: [2], e: 3 }, a: null })).toEqual({ b: { c: 1, d: [2], e: 3 } })
    expect(mergePatch({ a: 1 }, 'x')).toBe('x')
  })
})

describe('resolveHandler', () => {
  it('fills the platform defaults and marks every leaf explicit|default', () => {
    const r = resolveHandler('authenticator', { handler: 'cookie_session', config: { preserve_path: false } }, spec)
    expect(r).toEqual({
      kind: 'authenticator',
      handler: 'cookie_session',
      enabled: true,
      config: { check_session_url: 'http://kratos/sessions/whoami', preserve_path: false, only: ['ory_kratos_session'] },
      fields: { check_session_url: 'default', preserve_path: 'explicit', only: 'default' },
    })
  })

  it('nested keys are dotted; an overridden nested key is explicit, its siblings default', () => {
    const r = resolveHandler('authorizer', { handler: 'remote_json', config: { retry: { give_up_after: '5s' }, payload: '{}' } }, spec)
    expect(r.config.retry).toEqual({ max_delay: '300ms', give_up_after: '5s' })
    expect(r.fields).toEqual({
      remote: 'default',
      forward_response_headers_to_upstream: 'default',
      'retry.max_delay': 'default',
      'retry.give_up_after': 'explicit',
      payload: 'explicit',
    })
  })

  it('a handler the platform does not declare: enabled null, everything explicit', () => {
    const r = resolveHandler('mutator', { handler: 'id_token', config: { claims: '{}' } }, spec)
    expect(r).toMatchObject({ enabled: null, config: { claims: '{}' }, fields: { claims: 'explicit' } })
    expect(resolveHandler('error', { handler: 'redirect' }, spec)).toMatchObject({ enabled: false, config: {}, fields: {} })
  })
})

describe('resolveGates', () => {
  it('every handler of every gate, in rule order', () => {
    const gates = resolveGates([{
      name: 'web',
      match: { methods: ['GET'], url: 'https://x/<**>' },
      authenticators: [{ handler: 'cookie_session' }],
      authorizer: { handler: 'remote_json' },
      mutators: [{ handler: 'header', config: { headers: { 'X-Org': '{{ .Extra.org }}' } } }],
      errors: [{ handler: 'redirect' }],
    }], spec)
    expect(gates[0].gate).toBe('web')
    expect(gates[0].handlers.map((h) => `${h.kind}:${h.handler}`)).toEqual(['authenticator:cookie_session', 'authorizer:remote_json', 'mutator:header', 'error:redirect'])
    expect(gates[0].handlers[2]).toMatchObject({
      config: { headers: { 'X-User': '{{ print .Subject }}', 'X-Org': '{{ .Extra.org }}' } },
      fields: { 'headers.X-User': 'default', 'headers.X-Org': 'explicit' },
    })
  })
})
