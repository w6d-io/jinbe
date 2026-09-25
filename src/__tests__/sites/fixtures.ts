import type { Site } from '../../sites/schemas.js'
import type { Platform } from '../../sites/render.js'

export const ACME = '11111111-1111-1111-1111-111111111111'

export function payrollSite(overrides: Partial<Site> = {}): Site {
  return {
    name: 'payroll',
    displayName: 'Payroll',
    address: { host: 'payroll.dev.stairling.com' },
    upstream: { service: 'payroll', namespace: 'payroll', port: 8080 },
    exposure: { mode: 'zone' },
    gates: [
      {
        id: 'web',
        label: 'Browser and API',
        authenticators: [{ handler: 'cookie_session' }],
        authorizer: 'policy',
        mutators: [{ handler: 'header' }],
        errors: 'website',
        preflight: true,
      },
      {
        id: 'public',
        label: 'Public',
        authenticators: [{ handler: 'noop' }],
        authorizer: { handler: 'allow' },
        mutators: [{ handler: 'noop' }],
        errors: 'platform',
      },
    ],
    routes: {
      items: [
        { id: 'health', methods: ['GET'], path: '/health', gate: 'public', access: { kind: 'public' }, source: 'manual' },
        {
          id: 'payslips', methods: ['GET'], path: '/api/orgs/:orgId/payslips', gate: 'web',
          access: { kind: 'permission', permission: 'payslips:read' }, orgParam: 'orgId', source: 'manual',
        },
        {
          id: 'create', methods: ['POST'], path: '/api/orgs/:orgId/payslips', gate: 'web',
          access: { kind: 'permission', permission: 'payslips:create' }, orgParam: 'orgId', source: 'manual',
        },
      ],
      catchAll: { gate: 'web', access: { kind: 'signed-in' } },
    },
    roles: { admin: ['*'], editor: ['payslips:read', 'payslips:create'], viewer: ['payslips:read'] },
    groups: {
      platform: { admins: ['admin'] },
      orgGrantable: { 'payroll-editors': { label: 'Payroll editors', roles: ['editor'] } },
    },
    orgs: [ACME],
    state: 'active',
    ...overrides,
  }
}

export const platform: Platform = {
  namespace: 'auth',
  enabled: {
    authenticators: ['cookie_session', 'bearer_token', 'noop', 'anonymous'],
    authorizers: ['allow', 'deny', 'remote_json'],
    mutators: ['noop', 'header', 'id_token'],
    errors: ['redirect', 'json'],
  },
  zones: [{ suffix: 'dev.stairling.com', wildcardTls: true }],
  cookieDomain: '.dev.stairling.com',
  platformNamespaces: ['auth', 'kube-system'],
}

/** Oathkeeper's regexp strategy, for tests: `<…>` is regex, everything else literal, anchored. */
export function oathkeeperRegex(pattern: string): RegExp {
  let out = ''
  let depth = 0
  let chunk = ''
  for (const ch of pattern) {
    if (ch === '<' && depth === 0) {
      out += chunk.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')
      chunk = ''
      depth = 1
    } else if (ch === '<') {
      depth++
      chunk += ch
    } else if (ch === '>' && depth === 1) {
      out += chunk
      chunk = ''
      depth = 0
    } else {
      if (ch === '>' && depth > 1) depth--
      chunk += ch
    }
  }
  out += chunk.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')
  return new RegExp(`^${out}$`)
}
