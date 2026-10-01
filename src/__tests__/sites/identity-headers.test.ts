import { describe, expect, it } from 'vitest'
import type { GatewaySpec } from '../../gateway/kube-gateway.js'
import { PLATFORM_IDENTITY_HEADERS, gatewayIdentity } from '../../sites/identity-headers.js'
import { render } from '../../sites/render.js'
import type { Site } from '../../sites/schemas.js'
import { payrollSite, platform } from './fixtures.js'

const blanks = (names: readonly string[]) => Object.fromEntries(names.map((n) => [n, '']))
const gate = (r: ReturnType<typeof render>, name: string) => r.siteCr.spec.gates.find((g) => g.name === name)!

describe('identity headers on gates that set none', () => {
  it('a public gate overwrites every platform identity header with an empty value', () => {
    const r = render(payrollSite(), platform)
    expect(gate(r, 'public').mutators).toEqual([{ handler: 'header', config: { headers: blanks(PLATFORM_IDENTITY_HEADERS) } }])
    // The same in what gatekit is asked about.
    expect(r.rules.find((x) => x.id.startsWith('site-payroll-public-'))!.mutators).toEqual(gate(r, 'public').mutators)
    expect(PLATFORM_IDENTITY_HEADERS).toEqual(expect.arrayContaining(['x-user-id', 'x-user-email', 'x-email', 'x-id', 'x-tenant-id', 'x-type', 'x-person-uuid', 'x-applicant-uuid', 'x-client-id', 'x-token-scope']))
  })

  it('also blanks what the site\'s own header mutators inject', () => {
    const site = payrollSite()
    site.gates[0] = { ...site.gates[0], mutators: [{ handler: 'header', config: { headers: { 'X-Payroll-Role': '{{ print .Subject }}' } } }] }
    const headers = (gate(render(site, platform), 'public').mutators[0].config as { headers: Record<string, string> }).headers
    expect(headers['X-Payroll-Role']).toBe('')
    expect(headers['x-user-email']).toBe('')
  })

  it('keeps the gateway config\'s spellings, so the rule key replaces each global key', () => {
    const r = render(payrollSite(), { ...platform, identityHeaders: ['x-User-Email', 'x-user-email'] })
    expect(gate(r, 'public').mutators).toEqual([{ handler: 'header', config: { headers: { 'x-User-Email': '', 'x-user-email': '' } } }])
  })

  it('leaves the headers the gate\'s authorizer forwards from its decision', () => {
    const site = payrollSite()
    site.gates[1] = { ...site.gates[1], authenticators: [{ handler: 'cookie_session' }, { handler: 'anonymous' }], authorizer: 'policy' }
    const r = render(site, { ...platform, authorizerHeaders: { remote_json: ['X-User-Groups'] } })
    const headers = (gate(r, 'public').mutators[0].config as { headers: Record<string, string> }).headers
    expect(headers).not.toHaveProperty('x-user-groups')
    expect(headers['x-user-id']).toBe('')
  })

  it('X-User-Roles and X-User-Permissions are blanked on a gate that sets none, role headers on or off', () => {
    for (const p of [platform, { ...platform, roleHeaders: true }]) {
      const headers = (gate(render(payrollSite(), p), 'public').mutators[0].config as { headers: Record<string, string> }).headers
      expect(headers['x-user-roles']).toBe('')
      expect(headers['x-user-permissions']).toBe('')
    }
  })

  it('with role headers on, a policy gate forwards groups, roles and permissions of this site\'s app from the decision, and does not blank them', () => {
    const site = payrollSite()
    site.gates[1] = { ...site.gates[1], authenticators: [{ handler: 'cookie_session' }, { handler: 'anonymous' }], authorizer: 'policy' }
    const r = render(site, { ...platform, roleHeaders: true })
    const authorizer = gate(r, 'public').authorizer as { handler: string; config: { forward_response_headers_to_upstream: string[]; payload: string } }
    expect(authorizer.config.forward_response_headers_to_upstream).toEqual(['X-User-Groups', 'X-User-Roles', 'X-User-Permissions'])
    expect(authorizer.config.payload).toContain('"app": "payroll"')
    const headers = (gate(r, 'public').mutators[0].config as { headers: Record<string, string> }).headers
    expect(headers).not.toHaveProperty('x-user-roles')
    expect(headers).not.toHaveProperty('x-user-permissions')
    expect(headers['x-user-id']).toBe('')
    // Off: no forward list of its own, and the role headers stay blanked.
    const off = render(site, platform)
    expect((gate(off, 'public').authorizer as { config: Record<string, unknown> }).config).not.toHaveProperty('forward_response_headers_to_upstream')
    expect((gate(off, 'public').mutators[0].config as { headers: Record<string, string> }).headers['x-user-roles']).toBe('')
  })

  it('the pre-flight rule blanks them too; the deny rule never reaches the upstream', () => {
    const site: Site = payrollSite()
    site.routes.items.push({ id: 'internal', methods: ['GET'], path: '/internal', gate: 'web', access: { kind: 'deny' }, source: 'manual' })
    const r = render(site, platform)
    expect(gate(r, 'web-preflight').mutators).toEqual([{ handler: 'header', config: { headers: blanks(PLATFORM_IDENTITY_HEADERS) } }])
    expect(gate(r, 'deny').mutators).toEqual([{ handler: 'noop' }])
  })

  it('other mutators stay, after the blanking', () => {
    const site = payrollSite()
    site.gates[1] = { ...site.gates[1], mutators: [{ handler: 'noop' }, { handler: 'id_token' }] }
    expect(gate(render(site, platform), 'public').mutators.map((m) => m.handler)).toEqual(['header', 'id_token'])
  })

  it('needs the header mutator enabled on the gateway', () => {
    const r = render(payrollSite(), { ...platform, enabled: { ...platform.enabled, mutators: ['noop'] } })
    expect(r.checks).toContainEqual(expect.objectContaining({ level: 'error', code: 'handler_disabled', path: 'gates.1' }))
  })
})

describe('gates with their own header mutator', () => {
  it('are rendered as written: each header they name is set, overwriting the client\'s', () => {
    const r = render(payrollSite(), platform)
    expect(gate(r, 'web').mutators).toEqual([{ handler: 'header' }])
  })
})

describe('gatewayIdentity', () => {
  const spec = (headers: Record<string, string>, forward?: string[]): GatewaySpec => ({
    authenticators: {},
    authorizers: { remote_json: { enabled: true, config: forward ? { forward_response_headers_to_upstream: forward } : {} }, allow: { enabled: true } },
    mutators: { header: { enabled: true, config: { headers } } },
    errors: {},
    errorFallback: ['json'],
  })

  it('takes the templated headers as spelled, not the static ones, and the forwarded decision headers', () => {
    const gw = gatewayIdentity(spec({
      'x-User-Email': '{{ if .Extra.identity }}{{ index .Extra.identity.traits "email" }}{{ end }}',
      'x-user-email': '{{ if .Extra.identity }}{{ index .Extra.identity.traits "email" }}{{ end }}',
      'x-accel-buffering': 'no',
    }, ['X-User-Groups']))
    expect(gw).toEqual({ headers: ['x-User-Email', 'x-user-email'], forwarded: { remote_json: ['X-User-Groups'] } })
  })

  it('copes with a gateway without header mutator config', () => {
    expect(gatewayIdentity({ authenticators: {}, authorizers: {}, mutators: {}, errors: {}, errorFallback: [] })).toEqual({ headers: [], forwarded: {} })
  })
})
