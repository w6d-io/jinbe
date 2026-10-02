import { describe, expect, it } from 'vitest'
import type { GatewaySpec } from '../../gateway/kube-gateway.js'
import { PLATFORM_IDENTITY_HEADERS, ROLE_HEADERS, SESSION_HEADERS, STRIPPED_COOKIE_HEADER, gatewayIdentity } from '../../sites/identity-headers.js'
import { render } from '../../sites/render.js'
import type { Site } from '../../sites/schemas.js'
import { payrollSite, platform } from './fixtures.js'

const blanks = (names: readonly string[]) => ({ ...Object.fromEntries([...names, 'x-user-aal', 'x-user-2fa-at'].map((n) => [n, ''])), ...STRIPPED_COOKIE_HEADER })
const gate = (r: ReturnType<typeof render>, name: string) => r.siteCr.spec.gates.find((g) => g.name === name)!
const ROLE_BLANKS = { 'x-user-groups': '', 'x-user-roles': '', 'x-user-permissions': '' }

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
    expect(gate(r, 'public').mutators).toEqual([{ handler: 'header', config: { headers: { 'x-User-Email': '', 'x-user-email': '', ...ROLE_BLANKS, 'x-user-aal': '', 'x-user-2fa-at': '', ...STRIPPED_COOKIE_HEADER } } }])
  })

  it('leaves the headers a non-policy authorizer forwards (the gateway\'s list for its handler)', () => {
    const site = payrollSite()
    site.gates[1] = { ...site.gates[1], authorizer: { handler: 'remote' } }
    const r = render(site, { ...platform, enabled: { ...platform.enabled, authorizers: [...platform.enabled.authorizers, 'remote'] }, authorizerHeaders: { remote: ['X-User-Groups'] } })
    const headers = (gate(r, 'public').mutators[0].config as { headers: Record<string, string> }).headers
    expect(headers).not.toHaveProperty('x-user-groups')
    expect(headers['x-user-roles']).toBe('')
    expect(headers['x-user-id']).toBe('')
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
  it('are rendered as written, plus the sign-in strength headers (X-User-AAL, X-User-2FA-At)', () => {
    const r = render(payrollSite(), platform)
    expect(gate(r, 'web').mutators).toEqual([{ handler: 'header', config: { headers: { ...SESSION_HEADERS, ...ROLE_BLANKS, ...STRIPPED_COOKIE_HEADER } } }])
    expect(SESSION_HEADERS['x-user-aal']).toContain('.Extra.authenticator_assurance_level')
    expect(SESSION_HEADERS['x-user-2fa-at']).toContain('.Extra.authentication_methods')
    expect(SESSION_HEADERS['x-user-2fa-at']).toContain('.completed_at')
  })

  it('a header the site names itself is kept as written, whatever its case; only the first header mutator gets them', () => {
    const site = payrollSite()
    site.gates[0] = { ...site.gates[0], mutators: [
      { handler: 'header', config: { headers: { 'X-User-AAL': 'mine', 'X-App': '{{ print .Subject }}' } } },
      { handler: 'header', config: { headers: { 'X-Other': 'x' } } },
    ] }
    expect(gate(render(site, platform), 'web').mutators).toEqual([
      { handler: 'header', config: { headers: { 'X-User-AAL': 'mine', 'X-App': '{{ print .Subject }}', 'x-user-2fa-at': SESSION_HEADERS['x-user-2fa-at'], ...ROLE_BLANKS, ...STRIPPED_COOKIE_HEADER } } },
      { handler: 'header', config: { headers: { 'X-Other': 'x' } } },
    ])
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

describe('decisionUrlOf', () => {
  it('the configured URL, else the gateway remote with /allow → /decision, else none', async () => {
    const { decisionUrlOf } = await import('../../sites/identity-headers.js')
    expect(decisionUrlOf('http://x/v1/data/rbac/decision', 'http://p/v1/data/rbac/allow')).toBe('http://x/v1/data/rbac/decision')
    expect(decisionUrlOf(undefined, 'http://auth-opa-authz-proxy:8080/v1/data/rbac/allow')).toBe('http://auth-opa-authz-proxy:8080/v1/data/rbac/decision')
    expect(decisionUrlOf(undefined, 'http://p/v1/data/rbac/decision')).toBe('http://p/v1/data/rbac/decision')
    expect(decisionUrlOf(undefined, 'http://p/other')).toBeNull()
    expect(decisionUrlOf(undefined, undefined)).toBeNull()
  })

  it('gatewayIdentity reads the global remote_json remote', () => {
    const spec = { mutators: {}, authorizers: { remote_json: { config: { remote: 'http://p/v1/data/rbac/allow' } } } } as unknown as GatewaySpec
    expect(gatewayIdentity(spec).policyRemote).toBe('http://p/v1/data/rbac/allow')
  })
})

/**
 * STRIPPED_COOKIE_HEADER run with Go text/template + sprig semantics for exactly the functions it
 * uses: regexReplaceAll (regexp ReplaceAllString), trimPrefix (strings.TrimPrefix), trim
 * (strings.TrimSpace). The regex is RE2-compatible and means the same in JS. Checked once by hand
 * against Go's own text/template as well.
 */
function runCookieTemplate(cookie: string | undefined): string {
  const tpl = STRIPPED_COOKIE_HEADER.Cookie
  const m = /^\{\{ \$c := \.MatchContext\.Header\.Get "Cookie" \}\}\{\{ \$c = regexReplaceAll `([^`]+)` \$c "" \}\}\{\{ trimPrefix ";" \$c \| trim \}\}$/.exec(tpl)
  if (!m) throw new Error(`unexpected template shape: ${tpl}`)
  const replaced = (cookie ?? '').replace(new RegExp(m[1], 'g'), '')
  return (replaced.startsWith(';') ? replaced.slice(1) : replaced).trim()
}

describe('the platform session cookie never reaches a site app', () => {
  it.each([
    ['only the session cookie', 'ory_kratos_session=s3cr3t', ''],
    ['session first', 'ory_kratos_session=s; a=1; b=2', 'a=1; b=2'],
    ['session in the middle', 'a=1; ory_kratos_session=s; b=2', 'a=1; b=2'],
    ['session last', 'a=1; b=2; ory_kratos_session=s', 'a=1; b=2'],
    ['no spaces', 'a=1;ory_kratos_session=s;b=2', 'a=1;b=2'],
    ['the sandbox variant', 'ory_kratos_session_sandbox=s; a=1', 'a=1'],
    ['both variants', 'ory_kratos_session=s; ory_kratos_session_sandbox=t; a=1', 'a=1'],
    ['a lookalike name is kept', 'my_ory_kratos_session=1; ory_kratos_session=s', 'my_ory_kratos_session=1'],
    ['no Cookie header', undefined, ''],
  ])('%s', (_label, cookie, expected) => {
    expect(runCookieTemplate(cookie)).toBe(expected)
  })

  it('reads the incoming request and anchors the name at a cookie start', () => {
    expect(STRIPPED_COOKIE_HEADER.Cookie).toContain('.MatchContext.Header.Get "Cookie"')
    expect(STRIPPED_COOKIE_HEADER.Cookie).toContain('`(^|;)\\s*ory_kratos_session[A-Za-z0-9_-]*=[^;]*`')
  })

  it('is set on every gate: public, nothing, identity, enrich, pre-flight', () => {
    const site = payrollSite()
    site.gates.push({ id: 'nothing', label: 'Nothing', authenticators: [{ handler: 'cookie_session' }], authorizer: 'policy', mutators: [{ handler: 'noop' }], errors: 'api' })
    site.gates.push({ id: 'enrich', label: 'Enrich', authenticators: [{ handler: 'cookie_session' }], authorizer: 'policy', mutators: [{ handler: 'hydrator', config: { api: { url: 'http://e.e.svc.cluster.local' } } }, { handler: 'header' }], errors: 'api' })
    site.routes.items.push(
      { id: 'n', methods: ['GET'], path: '/n', gate: 'nothing', access: { kind: 'signed-in' }, source: 'manual' },
      { id: 'e', methods: ['GET'], path: '/e', gate: 'enrich', access: { kind: 'signed-in' }, source: 'manual' },
    )
    const r = render(site, { ...platform, enabled: { ...platform.enabled, mutators: [...platform.enabled.mutators, 'hydrator'] } })
    for (const name of ['public', 'nothing', 'web', 'web-preflight', 'enrich']) {
      const header = gate(r, name).mutators.find((m) => m.handler === 'header')!
      expect((header.config as { headers: Record<string, string> }).headers.Cookie, name).toBe(STRIPPED_COOKIE_HEADER.Cookie)
    }
  })

  it('a gate\'s own header mutators cannot drop or override it', () => {
    const site = payrollSite()
    site.gates[0] = { ...site.gates[0], mutators: [
      { handler: 'header', config: { headers: { cookie: '{{ .MatchContext.Header.Get "Cookie" }}', 'X-App': 'a' } } },
      { handler: 'header', config: { headers: { COOKIE: 'raw', 'X-Other': 'b' } } },
    ] }
    const [first, second] = gate(render(site, platform), 'web').mutators as Array<{ config: { headers: Record<string, string> } }>
    expect(Object.keys(first.config.headers).filter((k) => k.toLowerCase() === 'cookie')).toEqual(['Cookie'])
    expect(first.config.headers.Cookie).toBe(STRIPPED_COOKIE_HEADER.Cookie)
    expect(second.config.headers).toEqual({ 'X-Other': 'b' })
  })
})

describe('role headers: opt-in per gate (passRoles), never by default', () => {
  const decisionUrl = 'http://auth-opa-authz-proxy:8080/v1/data/rbac/decision'
  const on = { ...platform, roleHeaders: true, decisionUrl }
  /** payroll with its web (policy, header mutator) gate, and the public gate turned into a policy gate with no header mutator. */
  const site = (passRoles?: boolean): Site => {
    const s = payrollSite()
    s.gates[0] = { ...s.gates[0], ...(passRoles === undefined ? {} : { passRoles }) }
    s.gates[1] = { ...s.gates[1], authenticators: [{ handler: 'cookie_session' }, { handler: 'anonymous' }], authorizer: 'policy', ...(passRoles === undefined ? {} : { passRoles }) }
    return s
  }
  const authz = (r: ReturnType<typeof render>, name: string) => gate(r, name).authorizer as { config: Record<string, unknown> }
  const headersOf = (r: ReturnType<typeof render>, name: string) => (gate(r, name).mutators.find((m) => m.handler === 'header')!.config as { headers: Record<string, string> }).headers

  it('default (no passRoles), switch on: the gateway\'s global remote, its forwarded X-User-Groups kept, roles and permissions blanked', () => {
    const r = render(site(), { ...on, authorizerHeaders: { remote_json: ['X-User-Groups', 'X-User-Roles'] } })
    for (const name of ['web', 'public']) {
      expect(authz(r, name).config).not.toHaveProperty('remote')
      expect(authz(r, name).config.forward_response_headers_to_upstream).toEqual(['X-User-Groups'])
      expect(headersOf(r, name)).not.toHaveProperty('x-user-groups')
      expect(headersOf(r, name)).toMatchObject({ 'x-user-roles': '', 'x-user-permissions': '' })
    }
  })

  it('passRoles on a policy gate, switch on: /decision and the three headers forwarded, not blanked', () => {
    const r = render(site(true), on)
    for (const name of ['web', 'public']) {
      expect(authz(r, name).config).toMatchObject({ remote: decisionUrl, forward_response_headers_to_upstream: ROLE_HEADERS })
      const h = headersOf(r, name)
      for (const n of Object.keys(ROLE_BLANKS)) expect(h).not.toHaveProperty(n)
    }
  })

  it('passRoles with the switch off, or no decision endpoint: nothing forwarded, all blanked', () => {
    for (const p of [{ ...platform, decisionUrl }, { ...platform, roleHeaders: true }]) {
      const r = render(site(true), p)
      expect(authz(r, 'web').config).not.toHaveProperty('remote')
      expect(authz(r, 'web').config.forward_response_headers_to_upstream).toEqual([])
      expect(headersOf(r, 'public')).toMatchObject(ROLE_BLANKS)
    }
  })

  it('a client cannot spoof them on a header-mutator gate: blanked unless the site names them itself', () => {
    const s = site()
    s.gates[0] = { ...s.gates[0], mutators: [{ handler: 'header', config: { headers: { 'X-User-Roles': 'static' } } }] }
    const h = headersOf(render(s, on), 'web')
    expect(h).toMatchObject({ 'X-User-Roles': 'static', 'x-user-groups': '', 'x-user-permissions': '' })
    expect(h).not.toHaveProperty('x-user-roles')
  })

  it('the rule changes with passRoles, so the sync loop sees drift on every site published before', () => {
    const before = render(site(), on)
    const optedIn = render(site(true), on)
    expect(before.siteCr.metadata.annotations['auth.w6d.io/spec-hash']).not.toBe(optedIn.siteCr.metadata.annotations['auth.w6d.io/spec-hash'])
  })
})

describe('a role header the gateway fills from a template is left to it', () => {
  /** payroll with an enrich gate (hydrator + header) on a policy authorizer, no passRoles. */
  const site = (): Site => {
    const s = payrollSite()
    s.gates.push({ id: 'enrich', label: 'Enrich', authenticators: [{ handler: 'cookie_session' }], authorizer: 'policy', mutators: [{ handler: 'hydrator', config: { api: { url: 'http://e.e.svc.cluster.local' } } }, { handler: 'header' }], errors: 'api' })
    s.routes.items.push({ id: 'e', methods: ['GET'], path: '/e', gate: 'enrich', access: { kind: 'signed-in' }, source: 'manual' })
    return s
  }
  const plat = (extra: object) => ({ ...platform, enabled: { ...platform.enabled, mutators: [...platform.enabled.mutators, 'hydrator'] }, ...extra })
  const headersOf = (r: ReturnType<typeof render>, name: string) => (gate(r, name).mutators.find((m) => m.handler === 'header')!.config as { headers: Record<string, string> }).headers

  it('an enrich gate keeps the global x-user-groups template; roles and permissions stay blanked', () => {
    const r = render(site(), plat({ identityHeaders: [...PLATFORM_IDENTITY_HEADERS, 'x-user-groups'], templatedHeaders: ['x-user-id', 'x-user-email', 'x-user-groups'] }))
    for (const name of ['enrich', 'web']) {
      const h = headersOf(r, name)
      expect(h, name).not.toHaveProperty('x-user-groups')
      expect(h, name).toMatchObject({ 'x-user-roles': '', 'x-user-permissions': '' })
    }
  })

  it('whatever the gateway\'s spelling: neither spelling is blanked', () => {
    const r = render(site(), plat({ identityHeaders: [...PLATFORM_IDENTITY_HEADERS, 'X-User-Groups'], templatedHeaders: ['X-User-Groups'] }))
    const h = headersOf(r, 'enrich')
    expect(h).not.toHaveProperty('x-user-groups')
    expect(h).not.toHaveProperty('X-User-Groups')
  })

  it('a gateway without that template: groups are blanked like roles and permissions', () => {
    const r = render(site(), plat({ templatedHeaders: ['x-user-id', 'x-user-email'] }))
    expect(headersOf(r, 'enrich')).toMatchObject(ROLE_BLANKS)
    expect(headersOf(render(site(), plat({})), 'enrich')).toMatchObject(ROLE_BLANKS)
  })

  it('a gate that passes no identity still blanks a templated x-user-groups', () => {
    const r = render(site(), plat({ templatedHeaders: ['x-user-groups'] }))
    expect(headersOf(r, 'public')['x-user-groups']).toBe('')
  })
})

describe('X-User-Groups as before on every gateway shape (no passRoles)', () => {
  /** payroll with an enrich gate on the policy, beside web (identity) and public (no identity, made a policy gate). */
  const site = (): Site => {
    const s = payrollSite()
    s.gates[1] = { ...s.gates[1], authenticators: [{ handler: 'cookie_session' }, { handler: 'anonymous' }], authorizer: 'policy' }
    s.gates.push({ id: 'enrich', label: 'Enrich', authenticators: [{ handler: 'cookie_session' }], authorizer: 'policy', mutators: [{ handler: 'hydrator', config: { api: { url: 'http://e.e.svc.cluster.local' } } }, { handler: 'header' }], errors: 'api' })
    s.routes.items.push({ id: 'e', methods: ['GET'], path: '/e', gate: 'enrich', access: { kind: 'signed-in' }, source: 'manual' })
    return s
  }
  const plat = (extra: object) => ({ ...platform, enabled: { ...platform.enabled, mutators: [...platform.enabled.mutators, 'hydrator'] }, roleHeaders: true, decisionUrl: 'http://p/v1/data/rbac/decision', ...extra })
  const forward = (r: ReturnType<typeof render>, name: string) => (gate(r, name).authorizer as { config: Record<string, unknown> }).config.forward_response_headers_to_upstream
  const headersOf = (r: ReturnType<typeof render>, name: string) => (gate(r, name).mutators.find((m) => m.handler === 'header')!.config as { headers: Record<string, string> }).headers

  it('a template gateway (x-user-groups from the global header mutator): unchanged — groups left to the template, nothing forwarded', () => {
    const r = render(site(), plat({ identityHeaders: [...PLATFORM_IDENTITY_HEADERS], templatedHeaders: ['x-user-id', 'x-user-groups'] }))
    for (const name of ['web', 'enrich']) {
      expect(forward(r, name)).toEqual([])
      expect(headersOf(r, name)).not.toHaveProperty('x-user-groups')
      expect(headersOf(r, name)).toMatchObject({ 'x-user-roles': '', 'x-user-permissions': '' })
    }
  })

  it('a forwarding gateway (global remote_json forwards X-User-Groups, the chart default): groups kept on every policy gate, roles and permissions blanked', () => {
    const r = render(site(), plat({ authorizerHeaders: { remote_json: ['X-User-Groups'] } }))
    for (const name of ['web', 'enrich', 'public']) {
      expect(forward(r, name), name).toEqual(['X-User-Groups'])
      expect((gate(r, name).authorizer as { config: Record<string, unknown> }).config, name).not.toHaveProperty('remote')
      expect(headersOf(r, name), name).not.toHaveProperty('x-user-groups')
      expect(headersOf(r, name), name).toMatchObject({ 'x-user-roles': '', 'x-user-permissions': '' })
    }
  })

  it('a gateway with neither: all three blanked, nothing forwarded', () => {
    const r = render(site(), plat({}))
    for (const name of ['web', 'enrich', 'public']) {
      expect(forward(r, name)).toEqual([])
      expect(headersOf(r, name)).toMatchObject(ROLE_BLANKS)
    }
  })
})
