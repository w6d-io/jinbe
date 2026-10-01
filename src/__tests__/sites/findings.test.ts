import { describe, it, expect } from 'vitest'
import { assertPublishable, blockingFindings, publishState, securityFindings, unresolved, type Finding } from '../../sites/findings.js'
import { SESSION_TOKEN, WHO, isBareBearer, whoOf } from '../../sites/presets.js'
import { expandRoles } from '../../sites/render.js'
import type { Gate, Site } from '../../sites/schemas.js'
import type { ProtectionStatus } from '../../sites/protection.js'
import { payrollSite } from './fixtures.js'

// Security findings on a site (sites/findings.ts): what the check endpoint reports and what the
// publish gate refuses until fixed (error) or acknowledged (confirm).

const WAF: ProtectionStatus = { state: 'waf', reason: 'gateway', gateway: 'edge/eg', waf: 'edge/coraza', ipReputation: null, message: 'WAF in force' }
const run = (site: Site, groups = {}, protection: ProtectionStatus | null = WAF) => securityFindings(site, { roles: expandRoles(site) }, { groups, protection })
const codes = (f: Finding[]) => f.map((x) => x.code)
const gate = (over: Partial<Gate>): Gate => ({ id: 'api', label: 'API', authenticators: WHO['signed-in'], authorizer: 'policy', mutators: [{ handler: 'header' }], errors: 'api', ...over })

/** payroll with every route behind a permission, a deny catch-all, no wildcard role and the public Host kept: no finding at all. */
function tidy(over: Partial<Site> = {}): Site {
  const base = payrollSite()
  return {
    ...base,
    upstream: { ...base.upstream, preserveHost: true },
    gates: [base.gates[0]],
    routes: { items: base.routes.items.filter((r) => r.access.kind === 'permission'), catchAll: { gate: 'web', access: { kind: 'deny' } } },
    roles: { editor: ['payslips:read', 'payslips:create'], viewer: ['payslips:read'] },
    groups: { platform: { 'payroll-staff': ['viewer'] }, orgGrantable: { 'payroll-editors': { label: 'Editors', roles: ['editor'] } } },
    ...over,
  }
}

describe('presets (a copy of kuma src/lib/sites/presets.ts)', () => {
  it('reads a gate back to its preset, custom otherwise', () => {
    expect(whoOf({ authenticators: WHO['signed-in-or-tokens'] })).toBe('signed-in-or-tokens')
    expect(whoOf({ authenticators: [{ handler: 'cookie_session' }, { handler: 'bearer_token' }] })).toBe('custom')
  })

  it('a bearer_token is bare when it reads Authorization (no token_from, or header Authorization)', () => {
    expect(isBareBearer({ handler: 'bearer_token' })).toBe(true)
    expect(isBareBearer({ handler: 'bearer_token', config: { token_from: { header: 'authorization' } } })).toBe(true)
    expect(isBareBearer(SESSION_TOKEN)).toBe(false)
    expect(isBareBearer({ handler: 'bearer_token', config: { token_from: { cookie: 'sid' } } })).toBe(false)
    expect(isBareBearer({ handler: 'cookie_session' })).toBe(false)
  })
})

describe('securityFindings', () => {
  it('a tidy site has none', () => {
    expect(run(tidy())).toEqual([])
  })

  it('the simulation-api gate [cookie_session, bare bearer_token]: not a preset, and API tokens refused', () => {
    const f = run(tidy({ gates: [gate({ id: 'web', authenticators: [{ handler: 'cookie_session' }, { handler: 'bearer_token' }] })] }))
    expect(f).toEqual([
      expect.objectContaining({ code: 'gate_not_preset', level: 'confirm', path: 'gates.0.authenticators' }),
      expect.objectContaining({ code: 'bare_bearer_token', level: 'confirm', message: expect.stringContaining('API (OAuth2) tokens are refused') }),
    ])
    expect(f.every((x) => x.fix.length > 0)).toBe(true)
  })

  it('a bare bearer_token before oauth2_introspection is an error; after the session-token preset it is fine', () => {
    const shadow = run(tidy({ gates: [gate({ id: 'web', authenticators: [{ handler: 'bearer_token' }, { handler: 'oauth2_introspection' }] })] }))
    expect(shadow.find((x) => x.code === 'bearer_before_oauth2')?.level).toBe('error')
    expect(run(tidy({ gates: [gate({ id: 'web', authenticators: WHO['signed-in-or-tokens'] })] }))).toEqual([])
  })

  it('noop with the policy: first is an error (nobody identified), later a warning', () => {
    expect(run(tidy({ gates: [gate({ id: 'web', authenticators: [{ handler: 'noop' }] })] })).find((x) => x.code === 'noop_with_policy')?.level).toBe('error')
    const later = run(tidy({ gates: [gate({ id: 'web', authenticators: [{ handler: 'cookie_session' }, { handler: 'noop' }] })] }))
    expect(later.find((x) => x.code === 'noop_before_policy')?.level).toBe('warn')
    // A public gate (noop + allow) is not a policy gate.
    expect(codes(run(tidy({ gates: [...tidy().gates, gate({ id: 'pub', authenticators: WHO.anyone, authorizer: { handler: 'allow' } })] })))).toEqual([])
  })

  it('public and signed-in routes and catch-alls ask for confirmation, a public write under its own code', () => {
    const f = run(payrollSite({
      routes: {
        items: [
          ...payrollSite().routes.items,
          { id: 'signup', methods: ['POST'], path: '/signup', gate: 'public', access: { kind: 'public' }, source: 'manual' },
          { id: 'me', methods: ['GET'], path: '/me', gate: 'web', access: { kind: 'signed-in' }, source: 'manual' },
        ],
        catchAll: { gate: 'web', access: { kind: 'signed-in' } },
      },
    }))
    expect(f.filter((x) => x.level === 'confirm').map((x) => [x.code, x.path])).toEqual([
      ['public_route', 'routes.items.0'],
      ['public_write_route', 'routes.items.3'],
      ['signed_in_route', 'routes.items.4'],
      ['signed_in_catch_all', 'routes.catchAll'],
    ])
    const open = run(payrollSite({ routes: { ...payrollSite().routes, catchAll: { gate: 'public', access: { kind: 'public' } } } }))
    expect(codes(open)).toContain('public_catch_all')
  })

  it('a role no group holds, and a permission no held role grants, are warned', () => {
    const f = run(tidy({ groups: { platform: {}, orgGrantable: { 'payroll-editors': { label: 'Editors', roles: ['editor'] } } }, roles: { editor: ['payslips:create'], viewer: ['payslips:read'] } }))
    expect(f.map((x) => [x.code, x.level])).toEqual([
      ['permission_unreachable', 'warn'],
      ['role_unheld', 'warn'],
    ])
    expect(f[0].message).toContain('payslips:read')
  })

  it('a group outside the site holding its role counts (the platform now)', () => {
    const site = tidy({ groups: { platform: {}, orgGrantable: { 'payroll-editors': { label: 'Editors', roles: ['editor'] } } } })
    expect(codes(run(site, { auditors: { payroll: ['viewer'] } }))).toEqual([])
  })

  it('matching is exact: a role listing payslips:* does not reach payslips:read', () => {
    const f = run(tidy({ roles: { editor: ['payslips:*'], viewer: ['payslips:create'] } }))
    expect(codes(f)).toContain('permission_unreachable')
    expect(codes(f)).not.toContain('wildcard_role')
  })

  it('an upstream that does not keep the public Host is an info finding, never blocking', () => {
    for (const preserveHost of [false, undefined]) {
      const f = run(tidy({ upstream: { service: 'payroll', namespace: 'payroll', port: 8080, preserveHost } }))
      expect(f).toEqual([expect.objectContaining({ code: 'preserve_host_off', level: 'info', path: 'upstream.preserveHost', message: expect.stringContaining('payroll.payroll.svc.cluster.local') })])
      expect(publishState(f)).toEqual({ blocked: false, acknowledge: [] })
      expect(unresolved(f)).toEqual([])
    }
  })

  it('orgs that would lose the site on publish are warned, by name when known', () => {
    const f = securityFindings(tidy(), { roles: expandRoles(tidy()) }, { groups: {}, protection: WAF, orgsRemoved: [{ id: 'o-1', name: 'Test org' }, { id: 'o-2' }] })
    expect(f).toEqual([expect.objectContaining({ code: 'publish_removes_orgs', level: 'warn', message: 'publishing removes this site from: Test org (o-1), o-2' })])
    expect(publishState(f).blocked).toBe(false)
  })

  it('the WAF: off is warned with the reason, unknown is warned as unknown', () => {
    const off: ProtectionStatus = { ...WAF, state: 'none', reason: 'no_gateway', message: 'Served by the nginx Ingress: no WAF, no IP bans' }
    expect(run(tidy(), {}, off)).toEqual([expect.objectContaining({ code: 'waf_off', level: 'warn', message: expect.stringContaining('nginx Ingress') })])
    expect(codes(run(tidy(), {}, null))).toEqual(['waf_unknown'])
  })
})

describe('the publish gate', () => {
  const f: Finding[] = [
    { code: 'public_route', level: 'confirm', message: 'm', fix: 'f' },
    { code: 'public_route', level: 'confirm', message: 'm2', fix: 'f' },
    { code: 'waf_off', level: 'warn', message: 'm', fix: 'f' },
  ]

  it('an acknowledged code covers every finding with it; warnings never block', () => {
    expect(unresolved(f)).toHaveLength(2)
    expect(unresolved(f, ['public_route'])).toEqual([])
    expect(publishState(f)).toEqual({ blocked: false, acknowledge: ['public_route'] })
  })

  it('an error blocks whatever is acknowledged', () => {
    const withError = [...f, { code: 'bearer_before_oauth2', level: 'error' as const, message: 'm', fix: 'f' }]
    expect(publishState(withError).blocked).toBe(true)
    expect(() => assertPublishable(withError, ['public_route', 'bearer_before_oauth2'])).toThrow(expect.objectContaining({
      statusCode: 422, code: 'unconfirmed_findings', findings: [expect.objectContaining({ code: 'bearer_before_oauth2' })],
    }))
  })

  it('422 unconfirmed_findings names the codes to acknowledge', () => {
    expect(() => assertPublishable(f)).toThrow(/acknowledge: \["public_route"\]/)
    expect(() => assertPublishable(f, ['public_route'])).not.toThrow()
  })
})

describe('blockingFindings', () => {
  it('error checks become error findings with a fix (known code or the generic one), deduplicated; warnings are left out', () => {
    expect(blockingFindings([
      { level: 'error', code: 'unknown_group', message: "platform group 'x' does not exist", path: 'groups.platform.x' },
      { level: 'error', code: 'unknown_group', message: "platform group 'x' does not exist", path: 'groups.platform.x' },
      { level: 'error', code: 'something_new', message: 'm' },
      { level: 'warn', code: 'no_sso', message: 'w' },
    ])).toEqual([
      { code: 'unknown_group', level: 'error', message: "platform group 'x' does not exist", fix: expect.stringContaining('Create the group first'), path: 'groups.platform.x' },
      { code: 'something_new', level: 'error', message: 'm', fix: expect.stringContaining('409 checks_failed') },
    ])
    expect(publishState(blockingFindings([{ level: 'error', code: 'host_taken', message: 'm' }])).blocked).toBe(true)
  })
})

describe('two-step sign-in the gates cannot enforce', () => {
  const mfa = (scope: 'all' | 'writes' | 'routes', over: Partial<Gate>, routes?: string[]) =>
    tidy({ gates: [gate({ id: 'web', ...over })], login: { twoFactor: { scope, clients: 'exempt', ...(routes ? { routes } : {}) }, reach: 'granted' } })

  it('echo-mfa: 2FA on, web gate cookie_session + allow → error second_factor_not_enforced, and gate_signed_in_only', () => {
    const f = run(mfa('all', { authorizer: { handler: 'allow' } }))
    expect(f.map((x) => [x.code, x.level])).toEqual([['gate_signed_in_only', 'confirm'], ['second_factor_not_enforced', 'error']])
    expect(f[1]).toMatchObject({ fix: "Set Who may pass to the policy on gate 'web'", path: 'gates.0.authorizer', message: expect.stringContaining('lets every signed-in person pass') })
    expect(publishState(f).blocked).toBe(true)
  })

  it('a policy gate enforces it; deny lets nobody in; 2FA off asks nothing of the gates', () => {
    expect(run(mfa('all', {}))).toEqual([])
    expect(codes(run(mfa('all', { authorizer: { handler: 'deny' } })))).toEqual([])
    expect(codes(run(tidy({ gates: [gate({ id: 'web', authorizer: { handler: 'allow' } })] })))).toEqual(['gate_signed_in_only'])
  })

  it('a noop + allow gate on a protected route: lets anyone in', () => {
    const f = run(mfa('all', { authenticators: WHO.anyone, authorizer: { handler: 'allow' } }))
    expect(f.find((x) => x.code === 'second_factor_not_enforced')?.message).toContain('lets anyone in')
    expect(codes(f)).not.toContain('gate_signed_in_only')
  })

  it('only the routes the 2FA applies to count: writes scope and read-only gates, routes scope and chosen ids', () => {
    // tidy's web gate serves GET payslips and POST create: a write, so writes scope needs it.
    expect(codes(run(mfa('writes', { authorizer: { handler: 'allow' } })))).toContain('second_factor_not_enforced')
    const reads = tidy({
      gates: [gate({ id: 'web' }), gate({ id: 'ro', authorizer: { handler: 'allow' } })],
      routes: { items: [{ id: 'list', methods: ['GET'], path: '/list', gate: 'ro', access: { kind: 'signed-in' }, source: 'manual' }, ...tidy().routes.items], catchAll: { gate: 'web', access: { kind: 'deny' } } },
      login: { twoFactor: { scope: 'writes', clients: 'exempt' }, reach: 'granted' },
    })
    expect(codes(run(reads))).not.toContain('second_factor_not_enforced')
    expect(codes(run({ ...reads, login: { twoFactor: { scope: 'routes', routes: ['list'], clients: 'exempt' }, reach: 'granted' } }))).toContain('second_factor_not_enforced')
  })
})

describe('siteSecondFactor', () => {
  it('says NOT enforced (minAal aal1) when a gate it needs never asks the policy; null when only login is given', async () => {
    const { siteSecondFactor } = await import('../../second-factor/requirements.js')
    const site = tidy({ gates: [gate({ id: 'web', authorizer: { handler: 'allow' } })], login: { twoFactor: { scope: 'all', clients: 'exempt' }, reach: 'granted' } })
    expect(siteSecondFactor(site)).toMatchObject({ enforced: false, notEnforcedOn: ['web'], minAal: 'aal1', summary: expect.stringMatching(/^Two-step sign-in is set but NOT enforced: gate 'web' never asks the policy/) })
    expect(siteSecondFactor({ ...site, gates: [gate({ id: 'web' })] })).toMatchObject({ enforced: true, notEnforcedOn: [], minAal: 'aal2' })
    expect(siteSecondFactor({ login: site.login })).toMatchObject({ enforced: null, minAal: 'aal2' })
    expect(siteSecondFactor(tidy())).toMatchObject({ enforced: null, minAal: 'aal1' })
  })
})

describe('a sign-in gate that passes no identity', () => {
  const site = (over: Partial<Gate>) => tidy({ gates: [gate({ id: 'web', ...over })] })

  it('signed-in + Gets nothing (noop): warned, with the gate, the fix and gates.N.mutators', () => {
    const f = run(site({ mutators: [{ handler: 'noop' }] }))
    expect(f).toEqual([{
      code: 'gate_passes_no_identity', level: 'warn', path: 'gates.0.mutators',
      message: "gate 'web' signs people in but passes nothing on: the app receives the X-User-* headers (id, email, groups, AAL…) empty",
      fix: "Set Gets to identity headers (or enrich) on gate 'web'",
    }])
    expect(publishState(f)).toEqual({ blocked: false, acknowledge: [] })
  })

  it('optional sign-in (cookie_session + anonymous) identifies people too', () => {
    expect(codes(run(site({ authenticators: WHO.optional, mutators: [{ handler: 'noop' }] })))).toEqual(['gate_passes_no_identity'])
  })

  it('no finding for a public gate (noop), identity headers, enrich, or a signed token', () => {
    expect(codes(run(tidy({ gates: [...tidy().gates, gate({ id: 'pub', authenticators: WHO.anyone, authorizer: { handler: 'allow' }, mutators: [{ handler: 'noop' }] })] })))).toEqual([])
    expect(codes(run(site({ mutators: [{ handler: 'header' }] })))).toEqual([])
    expect(codes(run(site({ mutators: [{ handler: 'hydrator' }, { handler: 'header' }] })))).toEqual([])
    expect(codes(run(site({ mutators: [{ handler: 'id_token' }] })))).toEqual([])
    expect(codes(run(site({ authenticators: [{ handler: 'unauthorized' }], authorizer: { handler: 'deny' }, mutators: [{ handler: 'noop' }] })))).not.toContain('gate_passes_no_identity')
  })
})
