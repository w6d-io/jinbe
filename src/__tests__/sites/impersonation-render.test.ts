import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { IMPERSONATOR_HEADERS, PLATFORM_IDENTITY_HEADERS, SESSION_HEADERS, STRIPPED_COOKIE_HEADER, strippedCookieHeader } from '../../sites/identity-headers.js'
import { impersonationAuthenticator, withImpersonation } from '../../sites/impersonation.js'
import { WHO, whoOf } from '../../sites/presets.js'
import { render, type Platform } from '../../sites/render.js'
import { securityFindings } from '../../sites/findings.js'
import type { Handler, Site } from '../../sites/schemas.js'
import { payrollSite, platform } from './fixtures.js'

// Impersonation at the gateway: with the platform configured, every gate that takes the session
// cookie is rendered with a second cookie_session asking jinbe, the impersonator headers and the
// impersonation cookie stripped — and with it off, nothing at all changes.

const IMP = { cookie: 'platform_impersonation', checkUrl: 'http://auth-jinbe:8080/api/oathkeeper/impersonation/session' }
const on: Platform = { ...platform, enabled: { ...platform.enabled, authenticators: [...platform.enabled.authenticators, 'oauth2_introspection'] }, impersonation: IMP }
const off: Platform = { ...on, impersonation: undefined }

const AUTHENTICATOR: Handler = {
  handler: 'cookie_session',
  config: { check_session_url: IMP.checkUrl, only: ['platform_impersonation'], preserve_path: true, preserve_host: true, subject_from: 'identity.id', extra_from: '@this' },
}

/** payroll plus one gate per remaining way in: tokens only, optional sign-in, session or tokens. */
function site(): Site {
  const s = payrollSite()
  s.gates.push(
    { id: 'machines', label: 'Machines', authenticators: WHO.machines, authorizer: 'policy', mutators: [{ handler: 'header' }], errors: 'api' },
    { id: 'optional', label: 'Optional', authenticators: WHO.optional, authorizer: { handler: 'allow' }, mutators: [{ handler: 'noop' }], errors: 'platform' },
    { id: 'both', label: 'Both', authenticators: WHO['people-and-org-keys'], authorizer: 'policy', mutators: [{ handler: 'header' }], errors: 'api' },
  )
  s.routes.items.push(
    { id: 'm', methods: ['GET'], path: '/m', gate: 'machines', access: { kind: 'signed-in' }, source: 'manual' },
    { id: 'o', methods: ['GET'], path: '/o', gate: 'optional', access: { kind: 'public' }, source: 'manual' },
    { id: 'b', methods: ['GET'], path: '/b', gate: 'both', access: { kind: 'signed-in' }, source: 'manual' },
    { id: 'no', methods: ['GET'], path: '/no', gate: 'web', access: { kind: 'deny' }, source: 'manual' },
  )
  return s
}

const gate = (r: ReturnType<typeof render>, name: string) => r.siteCr.spec.gates.find((g) => g.name === name)!
const headers = (r: ReturnType<typeof render>, name: string) => (gate(r, name).mutators.find((m) => m.handler === 'header')!.config as { headers: Record<string, string> }).headers

describe('with impersonation off', () => {
  it('renders byte for byte what it rendered before the feature existed', () => {
    // payroll plus an optional-sign-in gate, rendered on develop before impersonation was written:
    // the sha256 of JSON.stringify(render(...)). A change to any rendered byte with the feature off
    // fails here (a deliberate change to rendering re-pins it).
    const s = payrollSite()
    s.gates.push({ id: 'optional', label: 'Optional', authenticators: [{ handler: 'cookie_session' }, { handler: 'anonymous' }], authorizer: { handler: 'allow' }, mutators: [{ handler: 'noop' }], errors: 'platform' })
    s.routes.items.push({ id: 'o', methods: ['GET'], path: '/o', gate: 'optional', access: { kind: 'public' }, source: 'manual' })
    const before = render(s, platform)
    expect(createHash('sha256').update(JSON.stringify(before)).digest('hex')).toBe('e10a9f51549162c1c13d8245e09a0753a483ec970b11a7caa638dc2995228a10')
    expect(JSON.stringify(render(s, { ...platform, impersonation: undefined }))).toBe(JSON.stringify(before))
    expect(JSON.stringify(before)).not.toContain('impersonat')
    expect(gate(before, 'web').authenticators).toEqual([{ handler: 'cookie_session' }])
    expect(headers(before, 'web').Cookie).toBe(STRIPPED_COOKIE_HEADER.Cookie)
    expect(strippedCookieHeader(undefined)).toBe(STRIPPED_COOKIE_HEADER)
  })

  it('keeps every rule id, so turning the feature on later is the only thing that renames rules', () => {
    const ids = (p: Platform) => render(site(), p).rules.map((r) => r.id)
    expect(ids(off)).toEqual(ids({ ...on, impersonation: undefined }))
    expect(ids(on)).not.toEqual(ids(off))
  })
})

describe('with impersonation on', () => {
  const r = render(site(), on)

  it('puts the impersonation authenticator right before the first cookie_session', () => {
    expect(impersonationAuthenticator(IMP)).toEqual(AUTHENTICATOR)
    expect(gate(r, 'web').authenticators).toEqual([AUTHENTICATOR, { handler: 'cookie_session' }])
    expect(gate(r, 'optional').authenticators).toEqual([AUTHENTICATOR, { handler: 'cookie_session' }, { handler: 'anonymous' }])
    expect(gate(r, 'both').authenticators).toEqual([AUTHENTICATOR, { handler: 'cookie_session' }, { handler: 'oauth2_introspection' }])
    // Once, even when a gate lists cookie_session twice, and after whatever precedes it.
    const twice: Handler[] = [{ handler: 'oauth2_introspection' }, { handler: 'cookie_session' }, { handler: 'cookie_session', config: { only: ['other'] } }]
    expect(withImpersonation(twice, IMP)).toEqual([twice[0], AUTHENTICATOR, twice[1], twice[2]])
  })

  it('leaves alone the gates that take no session cookie: anyone, tokens only, pre-flight, deny', () => {
    expect(gate(r, 'public').authenticators).toEqual([{ handler: 'noop' }])
    expect(gate(r, 'machines').authenticators).toEqual(WHO.machines)
    expect(gate(r, 'web-preflight').authenticators).toEqual([{ handler: 'noop' }])
    expect(gate(r, 'deny').authenticators).toEqual([{ handler: 'noop' }])
  })

  it('renders the same thing in the rules gatekit is asked about, with no error check', () => {
    expect(r.rules.find((x) => x.id.startsWith('site-payroll-web-'))!.authenticators).toEqual(gate(r, 'web').authenticators)
    expect(r.checks.filter((c) => c.level === 'error')).toEqual(render(site(), off).checks.filter((c) => c.level === 'error'))
  })

  it('is a render-time addition: the intent is untouched and a preset gate stays a preset', () => {
    const s = site()
    const before = JSON.stringify(s)
    const rendered = render(s, on)
    expect(JSON.stringify(s)).toBe(before)
    expect(s.gates.map((g) => whoOf(g))).toEqual(['signed-in', 'anyone', 'machines', 'optional', 'people-and-org-keys'])
    const codes = (p: Platform) => securityFindings(s, render(s, p), { groups: {}, protection: null }).map((f) => f.code)
    expect(codes(on)).toEqual(codes(off))
    expect(codes(on)).not.toContain('gate_not_preset')
    expect(rendered.routeMap).toEqual(render(s, off).routeMap)
  })

  it('says who is impersonating on every gate that passes identity', () => {
    for (const name of ['web', 'both', 'machines']) {
      expect(headers(r, name)['x-impersonator-id'], name).toBe(IMPERSONATOR_HEADERS['x-impersonator-id'])
      expect(headers(r, name)['x-impersonator-email'], name).toBe(IMPERSONATOR_HEADERS['x-impersonator-email'])
    }
    expect(IMPERSONATOR_HEADERS['x-impersonator-id']).toBe('{{ if .Extra }}{{ if .Extra.impersonator }}{{ print .Extra.impersonator.id }}{{ end }}{{ end }}')
    expect(IMPERSONATOR_HEADERS['x-impersonator-email']).toContain('.Extra.impersonator.email')
    // The session headers are still there, and a header the gate names itself is kept as written.
    expect(headers(r, 'web')['x-user-aal']).toBe(SESSION_HEADERS['x-user-aal'])
    const own = site()
    own.gates[0] = { ...own.gates[0], mutators: [{ handler: 'header', config: { headers: { 'X-Impersonator-Id': 'mine' } } }] }
    const h = headers(render(own, on), 'web')
    expect(h['X-Impersonator-Id']).toBe('mine')
    expect(h['x-impersonator-id']).toBeUndefined()
    expect(h['x-impersonator-email']).toBe(IMPERSONATOR_HEADERS['x-impersonator-email'])
  })

  it('blanks them on every gate that passes none, like every platform identity header', () => {
    for (const name of ['public', 'optional', 'web-preflight']) {
      const h = headers(r, name)
      expect(h['x-impersonator-id'], name).toBe('')
      expect(h['x-impersonator-email'], name).toBe('')
      for (const n of PLATFORM_IDENTITY_HEADERS) expect(h[n], `${name} ${n}`).toBe('')
    }
    // Off: the names are not rendered at all.
    expect(headers(render(site(), off), 'public')['x-impersonator-id']).toBeUndefined()
  })
})

/** The Cookie template run as Oathkeeper would (see identity-headers.test.ts runCookieTemplate). */
function runCookieTemplate(tpl: string, cookie: string | undefined): string {
  const m = /^\{\{ \$c := \.MatchContext\.Header\.Get "Cookie" \}\}\{\{ \$c = regexReplaceAll `([^`]+)` \$c "" \}\}\{\{ trimPrefix ";" \$c \| trim \}\}$/.exec(tpl)
  if (!m) throw new Error(`unexpected template shape: ${tpl}`)
  const replaced = (cookie ?? '').replace(new RegExp(m[1], 'g'), '')
  return (replaced.startsWith(';') ? replaced.slice(1) : replaced).trim()
}

describe('the impersonation cookie never reaches a site app either', () => {
  const tpl = strippedCookieHeader('platform_impersonation').Cookie

  it.each([
    ['only the impersonation cookie', 'platform_impersonation=t0k', ''],
    ['with the session cookie', 'ory_kratos_session=s; platform_impersonation=t0k; a=1', 'a=1'],
    ['in the middle', 'a=1; platform_impersonation=t0k; b=2', 'a=1; b=2'],
    ['last, no spaces', 'a=1;b=2;platform_impersonation=t0k', 'a=1;b=2'],
    ['the sandbox session variant still goes', 'ory_kratos_session_sandbox=s; a=1', 'a=1'],
    ['a longer name is kept', 'platform_impersonation_x=1; platform_impersonation=t', 'platform_impersonation_x=1'],
    ['a lookalike is kept', 'my_platform_impersonation=1; a=2', 'my_platform_impersonation=1; a=2'],
    ['no Cookie header', undefined, ''],
  ])('%s', (_label, cookie, expected) => {
    expect(runCookieTemplate(tpl, cookie)).toBe(expected)
  })

  it('matches the cookie by its exact name, beside the session prefix', () => {
    expect(tpl).toContain('`(^|;)\\s*(?:ory_kratos_session[A-Za-z0-9_-]*|platform_impersonation)=[^;]*`')
  })

  it('is the Cookie every gate sets: identity, nothing, pre-flight, public', () => {
    const r = render(site(), on)
    for (const name of ['web', 'both', 'machines', 'optional', 'public', 'web-preflight']) expect(headers(r, name).Cookie, name).toBe(tpl)
  })
})
