import type { Plan } from './review.js'

/** The plan as Markdown, for the owner to read and tick rule by rule. */

const cell = (v: unknown) => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ')
const list = (xs: readonly string[], max = 6) => (xs.length <= max ? xs.join(', ') : `${xs.slice(0, max).join(', ')} … +${xs.length - max}`)

function table(head: string[], rows: unknown[][]): string {
  if (rows.length === 0) return '_none_\n'
  return [
    `| ${head.join(' | ')} |`,
    `| ${head.map(() => '---').join(' | ')} |`,
    ...rows.map((r) => `| ${r.map(cell).join(' | ')} |`),
    '',
  ].join('\n')
}

export function renderPlanMarkdown(plan: Plan): string {
  const out: string[] = []
  out.push('# Authorization v2: review list', '')
  out.push(`planHash \`${plan.planHash}\` · generated ${plan.generatedAt}`, '')
  if (plan.unavailable.length) out.push(`**Could not be read (the sections below treat them as empty):** ${plan.unavailable.join(', ')}`, '')

  const changed = plan.people.filter((p) => p.gains.length || p.losses.length)
  out.push('## Summary', '')
  out.push(table(['', 'count'], [
    ['v2 rules (jinbe)', plan.rules.length],
    ['people holding anything (v1 or v2)', plan.people.length],
    ['people whose access changes', changed.length],
    ['memberships to groups v2 does not define', plan.orphans.memberships.length],
    ['org roles v2 ignores', plan.orphans.orgRoles.length],
    ['roster entries', plan.orphans.roster.length],
    ['org grants', plan.orphans.orgGrants.length],
    ['OAuth clients with retired scopes', plan.orphans.clients.length],
    ['stale jinbe rows in Redis', plan.v1.staleJinbeRows.length],
  ]))

  out.push('## 1. v1 today (live)', '')
  out.push(table(['service', 'roles', 'rows', 'roles granting *'], plan.v1.services.map((s) => [s.name, s.roles, s.rows, s.wildcardRoles.join(', ')])))
  const r = plan.v1.jinbeRows
  out.push(`jinbe route_map: ${r.total} rows — ${r.catalogue} catalogue, ${r.alias} legacy alias, ${r.dead} dead names, ${r.noPermission} without a permission, ${r.other} other.`, '')
  out.push('### Stale jinbe rows (no built-in produces them)', '')
  out.push(table(['method', 'path', 'permission', 'why'], plan.v1.staleJinbeRows.map((x) => [x.method, x.path, x.permission, x.reason])))
  out.push('### Groups', '')
  out.push(table(['group', 'bindings', 'members', 'system', 'in v2'], plan.v1.groups.map((g) => [
    g.name, Object.entries(g.bindings).map(([s, rs]) => `${s}:[${rs.join(',')}]`).join(' '), g.members, g.system ? 'yes' : '', g.inV2 ? 'yes' : 'dropped',
  ])))
  out.push('### Org roster, service map, grants', '')
  out.push(table(['org', 'roster', 'services', 'grants'], [...new Set([...Object.keys(plan.v1.roster), ...Object.keys(plan.v1.orgServiceMap), ...Object.keys(plan.v1.orgGrants)])].sort().map((o) => [
    o, list(plan.v1.roster[o] ?? []), (plan.v1.orgServiceMap[o] ?? []).join(', '),
    Object.entries(plan.v1.orgGrants[o] ?? {}).map(([e, gs]) => `${e}:[${gs.join(',')}]`).join(' '),
  ])))
  if (plan.v1.customOathkeeperRules.length) out.push(`Custom Oathkeeper rules: ${plan.v1.customOathkeeperRules.join(', ')}`, '')

  out.push('## 2. Rule by rule (v2)', '', 'Tick each row you approve. Holders are computed from today\'s memberships and org roles.', '')
  out.push(table(['ok', 'service', 'method', 'path', 'class', 'permission', 'roles', 'groups', 'holders', 'step-up', '4-eyes', 'delegable'], plan.rules.map((x) => [
    '[ ]', x.service, x.method, x.path, x.class, x.permission ?? '', list(x.roles, 4), list(x.groups, 4),
    x.permission ? `${x.holders.count}: ${list(x.holders.emails, 3)}` : '', x.stepUp ? 'yes' : '', x.fourEyes ? 'prod' : '', x.delegable ?? '',
  ])))

  out.push('## 3. People: gains and losses', '', '`p@org` is a permission in one org; `p@*` in every org.', '')
  out.push(table(['person', 'loses', 'gains'], changed.map((p) => [p.email, p.losses.join(', '), p.gains.join(', ')])))
  out.push(`${plan.people.length - changed.length} more people keep exactly what they hold.`, '')

  out.push('## 4. Orphans (kept on the identity, dropped from the policy: D4)', '')
  out.push('### Memberships to groups v2 does not define', '')
  out.push(table(['person', 'group'], plan.orphans.memberships.map((m) => [m.email, m.group])))
  out.push('### Org roles v2 ignores', '')
  out.push(table(['person', 'org', 'role', 'why'], plan.orphans.orgRoles.map((m) => [m.email, m.org, m.role, m.why])))
  out.push('### Roster entries', '')
  out.push(table(['org', 'person', 'member'], plan.orphans.roster.map((m) => [m.org, m.email, m.member ? 'yes' : 'no (grants nothing today either)'])))
  out.push('### Org grants (no v2 equivalent until the sites carry org roles, wave V4)', '')
  out.push(table(['org', 'person', 'groups'], plan.orphans.orgGrants.map((m) => [m.org, m.email, m.groups.join(', ')])))
  out.push('### OAuth clients with retired scopes', '')
  out.push(table(['client', 'kind', 'owner', 'retired', 'proposed', 're-scoped to'], plan.orphans.clients.map((c) => [c.clientId, c.kind, c.owner, c.retired.join(', '), c.proposed, c.rescopedTo.join(', ')])))

  out.push('## 5. Migration map (proposed, owner-editable)', '')
  out.push(table(['org', 'person', 'assign'], plan.migration.rosterToOwner.map((m) => [m.org, m.email, m.assign])))
  out.push(table(['person', 'org', 'v1 role', 'v2 role'], plan.migration.orgRoleRenames.map((m) => [m.email, m.org, m.from, m.to ?? 'unmapped (drop)'])))
  out.push(table(['v1 group', 'v2 group'], plan.migration.groups.map((g) => [g.v1, g.v2 ?? 'none (memberships dropped from policy)'])))
  return out.join('\n')
}
