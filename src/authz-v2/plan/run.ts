import { mkdir, writeFile } from 'fs/promises'
import { join } from 'path'
import { redisRbacRepository } from '../../services/redis-rbac.repository.js'
import { orgGrantsRepository } from '../../services/org-grants.repository.js'
import { hydraService } from '../../services/hydra.service.js'
import { kratosService } from '../../services/kratos.service.js'
import { rights } from '../../authz/opa.js'
import { readMarker } from '../../bootstrap/marker.js'
import { jinbeOwnedKeys } from '../store.js'
import { knownOrganisations } from '../service.js'
import type { V2Keys } from '../dataset.js'
import { JINBE } from '../roles.js'
import type { OAuthClientFacts, V1Inventory } from './inventory.js'
import { buildPlan, type Plan } from './review.js'
import { renderPlanMarkdown } from './render.js'
import { v1Holdings } from './v1-model.js'
import { platformNameOf } from '../catalogue.js'
import { effectivePermissions } from '../../policy/catalog.js'

/**
 * `node dist/cli/bootstrap.js --plan` (wave V0): reads the live v1 state with jinbe's own
 * credentials, builds the v2 review list against the model code defines, writes plan.json and
 * plan.md. READ-ONLY: no lock, no marker, no RBAC key written, no publish (the shared identity-directory
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

export async function readV1Inventory(logger: Logger, builtInRuleIds: ReadonlySet<string>): Promise<V1Inventory> {
  const unavailable: string[] = []
  const services = await redisRbacRepository.getServices()
  const roles: V1Inventory['roles'] = {}
  const routeMaps: V1Inventory['routeMaps'] = {}
  for (const svc of [...new Set(['global', ...services])]) {
    roles[svc] = (await redisRbacRepository.getRoles(svc)) ?? {}
    const map = await redisRbacRepository.getRouteMap(svc)
    if (map) routeMaps[svc] = map.rules
  }
  const meta = await redisRbacRepository.getAllGroupMetadata()
  const rules = (await redisRbacRepository.getAccessRules()) ?? []
  const directory = await attempt('identities (Kratos)', unavailable, logger, () => kratosService.getAllIdentitiesWithBindings({ maxAgeMs: 0 }), new Map())
  const identities: V1Inventory['identities'] = new Map()
  for (const [email, b] of directory) {
    const organizations = [...b.organizations]
    if (b.primaryOrganization && !organizations.includes(b.primaryOrganization)) organizations.push(b.primaryOrganization)
    identities.set(email, { id: b.id ?? null, groups: b.groups, organizations, organizationRoles: b.organizationRoles })
  }
  const clients = await attempt<OAuthClientFacts[] | null>('OAuth clients (Hydra)', unavailable, logger, async () =>
    (await hydraService.listAllClients()).map((c) => {
      const m = (c.metadata ?? {}) as Record<string, unknown>
      const kind = m.kind === 'personal' ? 'personal' : typeof m.organization_id === 'string' ? 'org' : 'other'
      const owner = kind === 'personal' ? (typeof m.subject === 'string' ? m.subject : null) : kind === 'org' ? (m.organization_id as string) : null
      return { clientId: c.client_id, kind, owner, name: c.client_name ?? null, scopes: (c.scope ?? '').split(' ').filter(Boolean).sort() } as OAuthClientFacts
    }), null)
  const marker = await attempt('bootstrap marker', unavailable, logger, async () => {
    const m = await readMarker()
    return m ? { schemaVersion: m.schemaVersion, gitSha: m.gitSha } : null
  }, null)
  return {
    services: services.sort(),
    roles,
    routeMaps,
    groups: await redisRbacRepository.getGroups(),
    systemGroups: Object.entries(meta).filter(([, v]) => v?.system).map(([k]) => k).sort(),
    orgAdmins: await redisRbacRepository.getOrgAdminMapAsStored(),
    orgServices: await redisRbacRepository.getOrgServiceMap(),
    orgGrants: await orgGrantsRepository.getAll(),
    oathkeeperRuleIds: rules.map((r) => r.id).filter((id) => !builtInRuleIds.has(id)).sort(),
    marker,
    identities,
    organisations: await attempt('organisation registry', unavailable, logger, knownOrganisations, []),
    clients,
    unavailable,
  }
}

/** The v2 keys code defines (what `--apply` would write), parsed. */
export function codeV2Keys(docs: boolean): V2Keys {
  const k = jinbeOwnedKeys({ docs })
  const parse = (key: string) => JSON.parse(k[key])
  return {
    apps: [JINBE],
    roles: { [JINBE]: parse(`rbac2:roles:${JINBE}`) },
    groups: parse(`rbac2:groups:${JINBE}`),
    orgRoles: { [JINBE]: parse(`rbac2:org_roles:${JINBE}`) },
    everyOrg: { [JINBE]: parse(`rbac2:every_org:${JINBE}`) },
    routeMap: { [JINBE]: parse(`rbac2:route_map:${JINBE}`) },
  }
}

/**
 * Asks OPA (`rbac.user_info`, the v1 engine) for each person the plan lists and reports where the
 * local v1 recomputation disagrees on platform permissions. Empty = the "before" column is exact.
 */
export async function crossCheckWithOpa(inv: V1Inventory, plan: Plan): Promise<Array<{ email: string; onlyLocal: string[]; onlyOpa: string[] }>> {
  const out: Array<{ email: string; onlyLocal: string[]; onlyOpa: string[] }> = []
  for (const p of plan.people) {
    const opa = effectivePermissions((await rights(p.email)).permissions).map(platformNameOf).filter((x): x is string => x !== null)
    const local = v1Holdings(inv, p.email).platform
    const onlyLocal = local.filter((x) => !opa.includes(x))
    const onlyOpa = opa.filter((x) => !local.includes(x))
    if (onlyLocal.length || onlyOpa.length) out.push({ email: p.email, onlyLocal, onlyOpa })
  }
  return out
}

export async function runPlan(opts: { logger: Logger; outDir: string; opa: boolean; docs: boolean; builtInRuleIds: ReadonlySet<string> }): Promise<Plan> {
  const inv = await readV1Inventory(opts.logger, opts.builtInRuleIds)
  const plan = buildPlan(inv, codeV2Keys(opts.docs))
  const extra: Record<string, unknown> = {}
  if (opts.opa) {
    try {
      extra.opaCrossCheck = await crossCheckWithOpa(inv, plan)
    } catch (err) {
      extra.opaCrossCheck = { error: (err as Error).message }
    }
  }
  await mkdir(opts.outDir, { recursive: true })
  await writeFile(join(opts.outDir, 'plan.json'), JSON.stringify({ ...plan, ...extra }, null, 2), 'utf8')
  let md = renderPlanMarkdown(plan)
  if (extra.opaCrossCheck !== undefined) md += `\n\n## OPA cross-check (v1 platform permissions)\n\n\`\`\`json\n${JSON.stringify(extra.opaCrossCheck, null, 2)}\n\`\`\`\n`
  await writeFile(join(opts.outDir, 'plan.md'), md, 'utf8')
  opts.logger.info({ outDir: opts.outDir, planHash: plan.planHash, rules: plan.rules.length, people: plan.people.length }, 'plan written (read-only: nothing was changed)')
  return plan
}
