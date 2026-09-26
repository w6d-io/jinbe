import { vi } from 'vitest'

/**
 * A stand-in for `src/authz/opa.js` — what OPA answers, per address — for suites that test what a
 * route or service DOES with an answer. The HTTP contract itself (rule, input, token, 503) is proven
 * in src/__tests__/authz/opa-guards.test.ts against a mocked fetch.
 *
 * Use: `vi.mock("<rel>/authz/opa.js", async () => (await import("<rel>/helpers/opa-authz-mock.js")).opaAuthzMock())`.
 */
export const opaWorld = {
  /** email → permissions in jinbe (global roles included). */
  permissions: {} as Record<string, string[]>,
  /** email → groups, as user_info reports them. */
  groups: {} as Record<string, string[]>,
  manageable: {} as Record<string, string[]>,
  members: {} as Record<string, string[]>,
  superAdmins: new Set<string>(),
  /** Verdict for rbac.decision; default: super_admin, or the roster admin of the org in the path. */
  decide: null as null | ((q: { email: string; method: string; path: string }) => boolean),
  down: false,
}

export function resetOpaWorld(): void {
  opaWorld.permissions = {}
  opaWorld.groups = {}
  opaWorld.manageable = {}
  opaWorld.members = {}
  opaWorld.superAdmins = new Set()
  opaWorld.decide = null
  opaWorld.down = false
}

export class AuthzUnavailableError extends Error {}

function up(): void {
  if (opaWorld.down) throw new AuthzUnavailableError('OPA is unreachable (TypeError).')
}

const holds = (permissions: readonly string[], required: string) =>
  permissions.includes('*') ||
  permissions.some((held) => {
    if (held === required) return true
    const [hr, hv] = held.split(':')
    const [rr, rv] = required.split(':')
    return hv === rv && rr.startsWith(`${hr}.`)
  })

export function opaAuthzMock() {
  const rights = vi.fn(async (email: string, _app?: string) => {
    up()
    return { groups: opaWorld.groups[email] ?? [], roles: [], permissions: [...(opaWorld.permissions[email] ?? [])].sort() }
  })
  return {
    AUTHZ_TTL_MS: 5000,
    JINBE_APP: 'jinbe',
    AuthzUnavailableError,
    rights,
    decide: vi.fn(async (q: { email: string; method: string; path: string }) => {
      up()
      const org = q.path.split('/')[3]
      const allow = opaWorld.decide
        ? opaWorld.decide(q)
        : opaWorld.superAdmins.has(q.email) || (opaWorld.manageable[q.email] ?? []).includes(org)
      return { allow, reason: allow ? 'ok' : 'forbidden' }
    }),
    manageableOrgs: vi.fn(async (email: string) => { up(); return opaWorld.manageable[email] ?? [] }),
    memberOrgs: vi.fn(async (email: string) => { up(); return opaWorld.members[email] ?? [] }),
    isSuperAdmin: vi.fn(async (email: string) => { up(); return opaWorld.superAdmins.has(email) }),
    holds,
    holdsInJinbe: vi.fn(async (email: string, required: string) => holds((await rights(email)).permissions, required)),
    clearAuthzCache: vi.fn(),
  }
}
