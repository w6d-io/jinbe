import { vi } from 'vitest'
import { grants } from '../../policy/catalog.js'

/**
 * A stand-in for `src/authz/opa.js` — what OPA answers, per address — for suites that test what a
 * route or service DOES with an answer. The HTTP contract itself (rule, input, token, 503) is proven
 * in src/__tests__/authz/opa-guards.test.ts against a mocked fetch.
 *
 * Use: `vi.mock("<rel>/authz/opa.js", async () => (await import("<rel>/helpers/opa-authz-mock.js")).opaAuthzMock())`.
 */
export const opaWorld = {
  /** email → platform permissions in jinbe. */
  permissions: {} as Record<string, string[]>,
  /** email → groups, as user_info reports them. */
  groups: {} as Record<string, string[]>,
  manageable: {} as Record<string, string[]>,
  members: {} as Record<string, string[]>,
  /** email → org → org permissions held there (rbac.org_permissions_by_org). */
  orgPermissions: {} as Record<string, Record<string, string[]>>,
  /** Verdict for rbac.decision; default: holds anything in the org named by the path. */
  decide: null as null | ((q: { email: string; method: string; path: string }) => boolean),
  /** The policy's grant verdict (rbac.delegation.*_verdict); default: allowed. */
  verdict: null as null | ((q: GrantQ) => Partial<Verdict> | null),
  /** actor → org → assignable org roles (rbac.delegation.assignable_roles). */
  assignable: {} as Record<string, Record<string, string[]>>,
  down: false,
}

type GrantQ = { kind: string; actor: string; [k: string]: unknown }
type Verdict = { allow: boolean; reasons: string[]; missing: Record<string, string[]>; missingEveryOrg: Record<string, string[]>; grantedBy: string[] }

/** A refused verdict, as the policy answers one. */
export function refused(over: Partial<Verdict> = {}): Verdict {
  return { allow: false, reasons: ['missing_permissions'], missing: {}, missingEveryOrg: {}, grantedBy: ['super_admins'], ...over }
}

export function resetOpaWorld(): void {
  opaWorld.permissions = {}
  opaWorld.groups = {}
  opaWorld.manageable = {}
  opaWorld.members = {}
  opaWorld.orgPermissions = {}
  opaWorld.decide = null
  opaWorld.verdict = null
  opaWorld.assignable = {}
  opaWorld.down = false
}

export class AuthzUnavailableError extends Error {}

function up(): void {
  if (opaWorld.down) throw new AuthzUnavailableError('OPA is unreachable (TypeError).')
}

// The real rule (exact match): pure, so the stand-in uses it rather than a copy.
const holds = grants

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
        : (opaWorld.orgPermissions[q.email]?.[org] ?? []).length > 0 || (opaWorld.manageable[q.email] ?? []).includes(org)
      return { allow, reason: allow ? 'ok' : 'forbidden' }
    }),
    manageableOrgs: vi.fn(async (email: string) => { up(); return opaWorld.manageable[email] ?? [] }),
    memberOrgs: vi.fn(async (email: string) => { up(); return opaWorld.members[email] ?? [] }),
    orgPermissionsByOrg: vi.fn(async (email: string) => { up(); return { ...(opaWorld.orgPermissions[email] ?? {}) } }),
    grantVerdict: vi.fn(async (q: GrantQ): Promise<Verdict> => {
      up()
      const v = opaWorld.verdict?.(q)
      return v ? { allow: false, reasons: [], missing: {}, missingEveryOrg: {}, grantedBy: [], ...v } : { allow: true, reasons: [], missing: {}, missingEveryOrg: {}, grantedBy: [] }
    }),
    assignableRoles: vi.fn(async (email: string, org: string) => { up(); return [...(opaWorld.assignable[email]?.[org] ?? [])] }),
    holds,
    holdsInJinbe: vi.fn(async (email: string, required: string) => holds((await rights(email)).permissions, required)),
    clearAuthzCache: vi.fn(),
  }
}
