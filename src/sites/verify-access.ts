import { queryOpaAdhoc } from '../services/opa-client.js'
import type { FlatRolesMap } from '../services/redis-rbac.repository.js'
import type { Site } from './schemas.js'
import { examplePath } from './patterns.js'
import type { ProbeTarget } from './verify-probe.js'

/**
 * Who may call what on a published site, asked of the policy that decides it — never a JS replay.
 *
 * One ad-hoc OPA query evaluates `data.rbac.decision` for a synthetic caller (PROBE_EMAIL, which no
 * binding names) once per (subject, route), each time `with` the bindings that subject stands for:
 * a platform group through group membership, a role through a probe group binding just that role, an
 * org role through an assignment in the route's organization (entitled to the site), or a signed-in
 * account holding nothing. Always as a member of that organization and at aal2, so an org route and a
 * 2FA site answer on the grant alone. No session is made and nothing is written.
 */

export const PROBE_EMAIL = 'site-verify@jinbe.invalid'
/** The organization a synthetic caller belongs to; org routes are asked about it. */
export const PROBE_ORG = '00000000-0000-4000-8000-00000000c0de'
const MAX_CASES = 1000
/** The group a role subject is held through: bound to that one role, named by no real binding. */
const PROBE_GROUP = 'site_verify_probe'

const QUERY = [
  'x := {k: d |',
  '  c := input.cases[k]',
  '  d := data.rbac.decision with input as c.input',
  '    with data.bindings.group_membership as c.membership',
  `    with data.bindings.groups.${PROBE_GROUP} as c.probeBinding`,
  '    with data.bindings.user_organizations as c.orgs',
  '    with data.bindings.org_assignments as c.assignments',
  `    with data.org_sites["${PROBE_ORG}"] as c.entitled`,
  '}',
].join('\n')

export type SubjectKind = 'group' | 'org-role' | 'role' | 'signed-in'
export interface Subject { key: string; kind: SubjectKind; name: string }

export interface AccessRow {
  route: string
  method: string
  path: string
  access: string
  /** Subject key → the policy's reason: ok | forbidden | not_found | needs_2fa. */
  answers: Record<string, string>
}

export interface AccessMatrix {
  available: boolean
  reason?: string
  source: 'opa'
  subjects: Subject[]
  rows: AccessRow[]
  /** Routes left out to stay under the query's size cap. */
  notChecked: string[]
}

export function subjectsOf(site: Pick<Site, 'groups'>, roles: FlatRolesMap, orgRoles: FlatRolesMap = {}): Subject[] {
  return [
    ...Object.keys(site.groups.platform).map((g) => ({ key: `group:${g}`, kind: 'group' as const, name: g })),
    ...Object.keys(orgRoles).map((r) => ({ key: `org-role:${r}`, kind: 'org-role' as const, name: r })),
    ...Object.keys(roles).map((r) => ({ key: `role:${r}`, kind: 'role' as const, name: r })),
    { key: 'signed-in', kind: 'signed-in' as const, name: 'any signed-in account' },
  ]
}

/** The request path asked about: the route's example path, its org segment naming PROBE_ORG. */
export function objectPath(path: string, orgParam?: string): string {
  const example = examplePath(path).split('/')
  const at = orgParam ? path.split('/').indexOf(`:${orgParam}`) : -1
  if (at >= 0) example[at] = PROBE_ORG
  return example.join('/')
}

function bindings(site: string, s: Subject) {
  return {
    membership: s.kind === 'group' ? { [PROBE_EMAIL]: [s.name] } : s.kind === 'role' ? { [PROBE_EMAIL]: [PROBE_GROUP] } : {},
    probeBinding: s.kind === 'role' ? { [site]: [s.name] } : {},
    orgs: { [PROBE_EMAIL]: [PROBE_ORG] },
    assignments: s.kind === 'org-role' ? { [PROBE_EMAIL]: { [PROBE_ORG]: [`${site}:${s.name}`] } } : {},
    entitled: ['jinbe', site],
  }
}

const accessLabel = (t: ProbeTarget) => (t.access.kind === 'permission' ? t.access.permission : t.access.kind)

export async function accessMatrix(site: Site, roles: FlatRolesMap, targets: readonly (ProbeTarget & { orgParam?: string })[], orgRoles: FlatRolesMap = {}): Promise<AccessMatrix> {
  const subjects = subjectsOf(site, roles, orgRoles)
  const perRoute = Math.max(1, Math.floor(MAX_CASES / subjects.length))
  const checked = targets.slice(0, perRoute)
  const notChecked = targets.slice(perRoute).map((t) => t.route)
  const rows: AccessRow[] = checked.map((t) => ({ route: t.route, method: t.methods.includes('GET') ? 'GET' : t.methods[0], path: t.path, access: accessLabel(t), answers: {} }))
  const cases: Record<string, unknown> = {}
  checked.forEach((t, i) => {
    const input = { email: PROBE_EMAIL, action: rows[i].method, object: objectPath(t.path, t.orgParam), app: site.name, aal: 'aal2' }
    subjects.forEach((s, j) => { cases[`${i}:${j}`] = { input, ...bindings(site.name, s) } })
  })
  let answers: Record<string, { allow?: boolean; reason?: string }> | undefined
  try {
    answers = await queryOpaAdhoc<Record<string, { allow?: boolean; reason?: string }>>(QUERY, { cases })
  } catch (err) {
    return { available: false, reason: `access matrix unavailable: ${(err as Error).message}`, source: 'opa', subjects, rows: [], notChecked: targets.map((t) => t.route) }
  }
  if (!answers) return { available: false, reason: 'access matrix unavailable: OPA returned no decision (is the policy loaded?)', source: 'opa', subjects, rows: [], notChecked: targets.map((t) => t.route) }
  rows.forEach((row, i) => subjects.forEach((s, j) => {
    const d = answers![`${i}:${j}`]
    row.answers[s.key] = d ? (d.allow ? 'ok' : d.reason ?? 'forbidden') : 'unknown'
  }))
  return { available: true, source: 'opa', subjects, rows, notChecked }
}
