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
  out.push('# Authorization: review list before --apply', '')
  out.push(`planHash \`${plan.planHash}\` · generated ${plan.generatedAt}`, '')
  if (plan.unavailable.length) out.push(`**Could not be read (the sections below treat them as empty):** ${plan.unavailable.join(', ')}`, '')

  const changed = plan.people.filter((p) => p.gains.length || p.losses.length)
  out.push('## Summary', '')
  out.push(table(['', 'count'], [
    ['rules after the apply (jinbe)', plan.rules.length],
    ['people holding anything (before or after)', plan.people.length],
    ['people whose access changes', changed.length],
    ['people who LOSE something', plan.people.filter((p) => p.losses.length).length],
    ['groups whose every member loses something (see "Losses to approve")', plan.lossesByGroup.length],
    ['memberships to groups that will not exist', plan.orphans.memberships.length],
    ['org roles the policy will ignore', plan.orphans.orgRoles.length],
    ['org roles the apply writes (migration)', plan.migration.orgRoles.length],
    ['roster entries', plan.orphans.roster.length],
    ['org grants with no site org role behind them (dropped)', plan.orphans.orgGrants.length],
    ['OAuth clients with retired scopes', plan.orphans.clients.length],
    ['stale jinbe rows in Redis', plan.before.staleJinbeRows.length],
    ['applied sites that cannot be rendered (left unpublished)', plan.before.siteFailures.length],
    ['sites whose stored roles hold a wildcard (a new, explicit version is saved)', plan.before.sitesMadeExplicit.length],
  ]))

  if (plan.before.siteFailures.length) {
    out.push('## Sites the apply cannot republish', '', 'Fix and publish each again before applying, or its people lose access to it.', '')
    out.push(table(['site', 'error'], plan.before.siteFailures.map((f) => [f.site, f.error])))
  }

  if (plan.before.sitesMadeExplicit.length) {
    out.push('## Sites saved again with explicit roles', '',
      "Each stored intent below still holds a wildcard (`*`, `resource:*`). The apply saves a new version with it made explicit — the permissions the site's routes declare, exactly what is published — noted \"roles made explicit by the authz release (was '*')\", so the first edit after the release saves. Nothing published changes.", '')
    out.push(plan.before.sitesMadeExplicit.map((s) => `- ${s}`).join('\n'), '')
  }

  out.push('## Losses to approve', '',
    'What every member of a group loses after the apply — a model decision read once (D1: platform roles keep only the ' +
    'every-org reach the decision gives them). `p@*` was reach into every organisation. Each person is listed again in section 3.', '')
  out.push(plan.lossesByGroup.length
    ? table(['group', 'members', 'every member loses', 'of which every-org reach'], plan.lossesByGroup.map((l) => [l.group, l.members.length, l.losses.join(', '), l.everyOrg.join(', ')]))
    : 'Nobody loses anything as a group.\n')

  out.push('## 1. Today (live)', '')
  out.push(table(['service', 'roles', 'rows', 'roles granting *'], plan.before.services.map((s) => [s.name, s.roles, s.rows, s.wildcardRoles.join(', ')])))
  const r = plan.before.jinbeRows
  out.push(`jinbe route_map: ${r.total} rows — ${r.catalogue} catalogue, ${r.alias} legacy alias, ${r.dead} dead names, ${r.noPermission} without a permission, ${r.other} other.`, '')
  out.push('### Stale jinbe rows (no built-in produces them)', '')
  out.push(table(['method', 'path', 'permission', 'why'], plan.before.staleJinbeRows.map((x) => [x.method, x.path, x.permission, x.reason])))
  out.push('### Groups', '')
  out.push(table(['group', 'bindings', 'members', 'system', 'after'], plan.before.groups.map((g) => [
    g.name, Object.entries(g.bindings).map(([s, rs]) => `${s}:[${rs.join(',')}]`).join(' '), g.members, g.system ? 'yes' : '', g.kept ? 'kept' : 'gone',
  ])))
  out.push('### Org roster, service map, grants', '')
  out.push(table(['org', 'roster', 'services', 'grants'], [...new Set([...Object.keys(plan.before.roster), ...Object.keys(plan.before.orgServiceMap), ...Object.keys(plan.before.orgGrants)])].sort().map((o) => [
    o, list(plan.before.roster[o] ?? []), (plan.before.orgServiceMap[o] ?? []).join(', '),
    Object.entries(plan.before.orgGrants[o] ?? {}).map(([e, gs]) => `${e}:[${gs.join(',')}]`).join(' '),
  ])))
  if (plan.before.customOathkeeperRules.length) out.push(`Custom Oathkeeper rules: ${plan.before.customOathkeeperRules.join(', ')}`, '')

  out.push('## 2. Rule by rule (after the apply)', '', 'Tick each row you approve. Holders are computed from today\'s memberships and the org roles after the migration.', '')
  out.push(table(['ok', 'service', 'method', 'path', 'class', 'permission', 'roles', 'groups', 'holders', 'step-up', '4-eyes', 'delegable'], plan.rules.map((x) => [
    '[ ]', x.service, x.method, x.path, x.class, x.permission ?? '', list(x.roles, 4), list(x.groups, 4),
    x.permission ? `${x.holders.count}: ${list(x.holders.emails, 3)}` : '', x.stepUp ? 'yes' : '', x.fourEyes ? 'prod' : '', x.delegable ?? '',
  ])))

  out.push('## 3. People: gains and losses', '', '`p@org` is a permission in one org; `p@*` in every org.', '')
  // Losses first: the people losing access lead the table, the most lost first.
  const ranked = [...changed].sort((a, b) => b.losses.length - a.losses.length || a.email.localeCompare(b.email))
  out.push(table(['person', 'LOSES', 'gains'], ranked.map((p) => [p.email, p.losses.length ? `**${p.losses.join(', ')}**` : '', p.gains.join(', ')])))
  out.push(`${plan.people.length - changed.length} more people keep exactly what they hold.`, '')

  out.push('## 4. Orphans (kept on the identity, dropped from the policy: D4)', '')
  out.push('### Memberships to groups that will not exist', '')
  out.push(table(['person', 'group'], plan.orphans.memberships.map((m) => [m.email, m.group])))
  out.push('### Org roles the policy will ignore', '')
  out.push(table(['person', 'org', 'role', 'why'], plan.orphans.orgRoles.map((m) => [m.email, m.org, m.role, m.why])))
  out.push('### Roster entries', '')
  out.push(table(['org', 'person', 'member'], plan.orphans.roster.map((m) => [m.org, m.email, m.member ? 'yes' : 'no (grants nothing today either)'])))
  out.push('### Org grants with no equivalent (the group is no site\'s org role; carried ones are in section 5)', '')
  out.push(table(['org', 'person', 'groups'], plan.orphans.orgGrants.map((m) => [m.org, m.email, m.groups.join(', ')])))
  out.push('### OAuth clients with retired scopes', '')
  out.push(table(['client', 'kind', 'owner', 'retired', 'proposed', 're-scoped to'], plan.orphans.clients.map((c) => [
    c.clientId, c.kind, c.ownerEmail ?? c.owner ?? (c.kind === 'mcp' ? '(never consented)' : ''), c.retired.join(', '), c.proposed, c.rescopedTo.join(', '),
  ])))

  out.push('## 5. Migration map (proposed, owner-editable)', '')
  out.push('### Org roles the apply writes', '')
  out.push(table(['org', 'person', 'role', 'from'], plan.migration.orgRoles.map((m) => [m.org, m.email, m.role, m.from === 'roster' ? 'org admin roster' : 'role on the identity'])))
  out.push('### Org roles on identities, renamed', '')
  out.push(table(['person', 'org', 'before', 'after'], plan.migration.orgRoleRenames.map((m) => [m.email, m.org, m.from, m.to ?? 'unmapped (dropped)'])))
  out.push('### Groups', '')
  out.push(table(['before', 'after'], plan.migration.groups.map((g) => [g.before, g.after ?? 'gone (memberships dropped from policy)'])))
  out.push('### Org entitlements (org_sites)', '', 'Every organisation keeps jinbe (its own org routes); the sites are those whose intent lists the organisation.', '')
  out.push(table(['org', 'sites'], Object.entries(plan.migration.orgSites).map(([o, sites]) => [o, sites.join(', ')])))
  return out.join('\n')
}
