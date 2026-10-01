import { mkdir, writeFile } from 'fs/promises'
import { join } from 'path'
import { redisRbacRepository } from '../../services/redis-rbac.repository.js'
import { getRedisClient } from '../../services/redis-client.service.js'
import { directGrantsRepository } from '../../services/direct-grants.repository.js'
import { orgRolesRepository } from '../../services/org-roles.repository.js'
import { hydraService } from '../../services/hydra.service.js'
import { kratosService } from '../../services/kratos.service.js'
import { rolesByOrganisation } from '../../services/organisation-store/membership.js'
import { allOrganisations, organisationStoreConfigured } from '../../services/organisation-store.js'
import { MCP_CLIENT_KIND } from '../../oauth/register.js'
import { renderAppliedSites } from '../../sites/republish.js'
import { rights } from '../../authz/opa.js'
import { readMarker } from '../marker.js'
import type { Inventory, OAuthClientFacts } from './inventory.js'
import { buildPlan, type Plan } from './review.js'
import { renderPlanMarkdown } from './render.js'
import { beforeHoldings } from './v1-model.js'

/**
 * `node dist/cli/bootstrap.js --plan` (wave V0): reads the live RBAC state with jinbe's own
 * credentials, builds the review list against the model code defines, writes plan.json and plan.md.
 * READ-ONLY: no lock, no marker, no RBAC key written, no publish (the shared identity-directory
 * cache may be refreshed, as by any directory read).
 */

interface Logger { info(obj: object, msg?: string): void; warn(obj: object, msg?: string): void }

async function attempt<T>(what: string, unavailable: string[], logger: Logger, fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn()
  } catch (err) {
    unavailable.push(what)
    logger.warn({ what, err: (err as Error).message }, 'plan: could not read — reported as unavailable')
    return fallback
  }
}

/** A hash of JSON values, read raw (the previous model's keys have no repository any more). */
async function rawHash<T>(key: string, parse: (v: unknown) => T | null): Promise<Record<string, T>> {
  const out: Record<string, T> = {}
  for (const [field, value] of Object.entries(await getRedisClient().hgetall(key))) {
    let parsed: unknown = value
    try {
      parsed = JSON.parse(value)
    } catch { /* a bare value */ }
    const v = parse(parsed)
    if (v !== null) out[field] = v
  }
  return out
}

const stringList = (v: unknown): string[] | null =>
  Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string' && s.length > 0) : typeof v === 'string' && v ? [v] : null

export async function readInventory(logger: Logger, builtInRuleIds: ReadonlySet<string>): Promise<Inventory> {
  const unavailable: string[] = []
  const services = await redisRbacRepository.getServices()
  const roles: Inventory['roles'] = {}
  const routeMaps: Inventory['routeMaps'] = {}
  const orgRoles: Inventory['orgRoles'] = {}
  const everyOrg: Inventory['everyOrg'] = {}
  for (const svc of [...new Set(['global', ...services])]) {
    const r = await redisRbacRepository.getRoles(svc)
    if (r) roles[svc] = r
    const map = await redisRbacRepository.getRouteMap(svc)
    if (map) routeMaps[svc] = map.rules
    const o = await redisRbacRepository.getOrgRoles(svc)
    if (o) orgRoles[svc] = o
    const e = await redisRbacRepository.getEveryOrg(svc)
    if (e) everyOrg[svc] = e
  }
  const meta = await redisRbacRepository.getAllGroupMetadata()
  const rules = (await redisRbacRepository.getAccessRules()) ?? []
  const directory = await attempt('identities (Kratos)', unavailable, logger, () => kratosService.getAllIdentitiesWithBindings({ maxAgeMs: 0 }), new Map())
  const identities: Inventory['identities'] = new Map()
  for (const [email, b] of directory) {
    const organizations = [...b.organizations]
    if (b.primaryOrganization && !organizations.includes(b.primaryOrganization)) organizations.push(b.primaryOrganization)
    identities.set(email, { id: b.id ?? null, groups: b.groups, organizations, organizationRoles: rolesByOrganisation(b.organizationRoles) })
  }
  const clients = await attempt<OAuthClientFacts[] | null>('OAuth clients (Hydra)', unavailable, logger, async () =>
    (await hydraService.listAllClients()).map(clientFacts), null)
  const marker = await attempt('bootstrap marker', unavailable, logger, async () => {
    const m = await readMarker()
    return m ? { schemaVersion: m.schemaVersion, gitSha: m.gitSha } : null
  }, null)
  const applied = await attempt('sites', unavailable, logger, () => renderAppliedSites(), { models: [], failed: [], records: [] })
  const siteModels: Inventory['siteModels'] = Object.fromEntries(applied.models.map(({ site, rendered }) => [site.name, {
    roles: rendered.roles,
    routeMap: rendered.routeMap,
    groups: Object.fromEntries(Object.entries(rendered.groups.platform).map(([g, def]) => [g, def[site.name] ?? []])),
    orgRoles: rendered.orgRoles,
    everyOrg: rendered.everyOrg,
    orgs: Object.keys(rendered.orgServiceMap).sort(),
  }]))
  const sites = Object.keys(siteModels).sort()
  return {
    services: services.sort(),
    roles,
    routeMaps,
    groups: await redisRbacRepository.getGroups(),
    systemGroups: Object.entries(meta).filter(([, v]) => v?.system).map(([k]) => k).sort(),
    orgAdmins: await rawHash('rbac:org_admins', stringList),
    orgServices: await rawHash('rbac:org_service_map', stringList),
    orgGrants: await rawHash('rbac:org_grants', (v) => (v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([e, gs]) => [e, stringList(gs) ?? []]))
      : null)),
    orgSites: await redisRbacRepository.getOrgSites(),
    orgRoles,
    everyOrg,
    orgAssignments: await orgRolesRepository.getAll(),
    directGrants: await directGrantsRepository.getAll(),
    sites,
    siteModels,
    siteFailures: applied.failed,
    oathkeeperRuleIds: rules.map((r) => r.id).filter((id) => !builtInRuleIds.has(id)).sort(),
    marker,
    identities,
    organisations: await attempt('organisation registry', unavailable, logger,
      async () => (organisationStoreConfigured() ? (await allOrganisations()).map((o) => o.id) : []), [] as string[]),
    clients,
    unavailable,
  }
}

/**
 * Asks OPA (`rbac.user_info`, whatever policy is loaded) for each person the plan lists and reports
 * where the local "before" recomputation disagrees on platform permissions. Empty = it is exact.
 */
export async function crossCheckWithOpa(inv: Inventory, plan: Plan): Promise<Array<{ email: string; onlyLocal: string[]; onlyOpa: string[] }>> {
  const out: Array<{ email: string; onlyLocal: string[]; onlyOpa: string[] }> = []
  for (const p of plan.people) {
    const opa = (await rights(p.email)).permissions
    const local = beforeHoldings(inv, p.email).platform
    const onlyLocal = local.filter((x) => !opa.includes(x))
    const onlyOpa = opa.filter((x) => !local.includes(x))
    if (onlyLocal.length || onlyOpa.length) out.push({ email: p.email, onlyLocal, onlyOpa })
  }
  return out
}

export async function writePlan(plan: Plan, outDir: string, extra: Record<string, unknown> = {}): Promise<void> {
  await mkdir(outDir, { recursive: true })
  await writeFile(join(outDir, 'plan.json'), JSON.stringify({ ...plan, ...extra }, null, 2), 'utf8')
  let md = renderPlanMarkdown(plan)
  for (const [k, v] of Object.entries(extra)) md += `\n\n## ${k}\n\n\`\`\`json\n${JSON.stringify(v, null, 2)}\n\`\`\`\n`
  await writeFile(join(outDir, 'plan.md'), md, 'utf8')
}

export async function runPlan(opts: { logger: Logger; outDir: string; opa: boolean; builtInRuleIds: ReadonlySet<string> }): Promise<Plan> {
  const inv = await readInventory(opts.logger, opts.builtInRuleIds)
  const plan = buildPlan(inv)
  const extra: Record<string, unknown> = {}
  if (opts.opa) {
    try {
      extra['OPA cross-check (platform permissions today)'] = await crossCheckWithOpa(inv, plan)
    } catch (err) {
      extra['OPA cross-check (platform permissions today)'] = { error: (err as Error).message }
    }
  }
  await writePlan(plan, opts.outDir, extra)
  opts.logger.info({ outDir: opts.outDir, planHash: plan.planHash, rules: plan.rules.length, people: plan.people.length }, 'plan written (read-only: nothing was changed)')
  return plan
}

/** What the review needs of one Hydra client: its kind, its owner, its scopes. */
export function clientFacts(c: { client_id: string; client_name?: string; scope?: string; metadata?: unknown }): OAuthClientFacts {
  const m = (c.metadata ?? {}) as Record<string, unknown>
  // An MCP client jinbe registered (DCR) carries the same marker the consent flow reads (isMcpClient),
  // and the person it is bound to once they consented (bound_subject).
  const kind = m.kind === MCP_CLIENT_KIND ? 'mcp' : m.kind === 'personal' ? 'personal' : typeof m.organization_id === 'string' ? 'org' : 'other'
  const owner = kind === 'personal' ? (typeof m.subject === 'string' ? m.subject : null)
    : kind === 'org' ? (m.organization_id as string)
      : kind === 'mcp' ? (typeof m.bound_subject === 'string' && m.bound_subject ? m.bound_subject : null) : null
  return {
    clientId: c.client_id, kind, owner, name: c.client_name ?? null, scopes: (c.scope ?? '').split(' ').filter(Boolean).sort(),
    ...(kind === 'mcp' ? { registeredAt: typeof m.registered_at === 'string' ? m.registered_at : null } : {}),
  }
}
