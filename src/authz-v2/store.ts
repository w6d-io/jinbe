import type { Redis } from 'ioredis'
import { createHash } from 'crypto'
import { canonicalJson } from '../bootstrap/hash.js'
import type { RouteRule } from '../services/redis-rbac.repository.js'
import { GENERATED_ROUTE_MAP_V2 } from './route-map.generated.js'
import { DOCS_ROW } from './route-rows.js'
import { JINBE, everyOrgDefinitions, modelProblems, orgRoleDefinitions, platformRoleDefinitions, staffGroupsV2 } from './roles.js'

/**
 * The v2 RBAC data in Redis, BESIDE v1 (authz-v2-design §3.2): prefix `rbac2:`, never read by the v1
 * model, published by OPAL at data.v2 only when RBAC_V2_PUBLISH is on. Writing it changes no decision
 * while `rbac:authz_active` is v1.
 *
 * One key per kind and OWNER, so jinbe replaces exactly what it owns and a site (wave V4) exactly its
 * own, never merging:
 *
 *   rbac2:apps                  JSON [app]                    every owner that wrote keys
 *   rbac2:roles:{app}           JSON {role: [perm]}           platform roles
 *   rbac2:groups:{owner}        JSON {group: {app: [role]}}   groups the owner defines
 *   rbac2:org_roles:{svc}       JSON {role: [perm]}
 *   rbac2:every_org:{app}       JSON {role: [org perm]}
 *   rbac2:route_map:{app}       JSON {rules: [...]}
 *   rbac2:owned:{owner}         JSON {key: sha256}            what the owner last wrote (drift check)
 *
 * The switch itself, `rbac:authz_active`, lives in the v1 namespace on purpose: it outlives both.
 */

export const V2_PREFIX = 'rbac2:'
export const APPS_KEY = 'rbac2:apps'
export const ownedKey = (owner: string) => `rbac2:owned:${owner}`

const sha = (s: string) => createHash('sha256').update(s).digest('hex')

/** jinbe's own v2 keys, exactly as code defines them. */
export function jinbeOwnedKeys(opts: { docs: boolean }): Record<string, string> {
  const problems = modelProblems()
  if (problems.length > 0) throw new Error(`authz v2 model is unsound: ${problems.join('; ')}`)
  const rules: RouteRule[] = [...GENERATED_ROUTE_MAP_V2, ...(opts.docs ? [DOCS_ROW] : [])]
  return {
    [`rbac2:roles:${JINBE}`]: canonicalJson(platformRoleDefinitions()),
    [`rbac2:groups:${JINBE}`]: canonicalJson(staffGroupsV2()),
    [`rbac2:org_roles:${JINBE}`]: canonicalJson(orgRoleDefinitions()),
    [`rbac2:every_org:${JINBE}`]: canonicalJson(everyOrgDefinitions()),
    [`rbac2:route_map:${JINBE}`]: canonicalJson({ rules }),
  }
}

export interface ConvergeResult {
  /** Keys rewritten because code changed them since the last write (an upgrade). */
  updated: string[]
  /** Keys rewritten because somebody changed them outside jinbe (alerted: rbac.owned_drift). */
  drifted: string[]
  /** Keys written for the first time. */
  created: string[]
}

/**
 * Converges one owner's keys on `desired`: unchanged keys are left alone, the rest replaced in ONE
 * MULTI with the owned record, so a reader never sees half a model. A key whose stored value is not
 * what the owner last wrote is DRIFT (someone wrote it by hand): reported so the caller alerts, and
 * rewritten anyway (D5: converge and alert on dev; refuse on prod comes one quiet release later).
 */
export async function convergeOwned(redis: Redis, owner: string, desired: Record<string, string>): Promise<ConvergeResult> {
  const keys = Object.keys(desired).sort()
  const [ownedRaw, ...stored] = await redis.mget(ownedKey(owner), ...keys)
  let lastWritten: Record<string, string> = {}
  try {
    lastWritten = ownedRaw ? (JSON.parse(ownedRaw) as Record<string, string>) : {}
  } catch {
    lastWritten = {}
  }
  const result: ConvergeResult = { updated: [], drifted: [], created: [] }
  const tx = redis.multi()
  keys.forEach((key, i) => {
    const current = stored[i]
    if (current === desired[key]) return
    if (current === null || current === undefined) result.created.push(key)
    else if (lastWritten[key] && sha(current) !== lastWritten[key]) result.drifted.push(key)
    else result.updated.push(key)
    tx.set(key, desired[key])
  })
  const apps = new Set<string>(JSON.parse((await redis.get(APPS_KEY)) ?? '[]') as string[])
  const appsChanged = !apps.has(owner)
  apps.add(owner)
  const owned = canonicalJson(Object.fromEntries(keys.map((k) => [k, sha(desired[k])])))
  if (result.created.length + result.updated.length + result.drifted.length === 0 && !appsChanged && ownedRaw === owned) {
    tx.discard()
    return result
  }
  tx.set(ownedKey(owner), owned)
  tx.set(APPS_KEY, canonicalJson([...apps].sort()))
  await tx.exec()
  return result
}

/** Every rbac2 document, read for the OPAL feed and the plan. Missing keys read as empty. */
export async function readV2Keys(redis: Redis): Promise<{
  apps: string[]
  roles: Record<string, Record<string, string[]>>
  groups: Record<string, Record<string, string[]>>
  orgRoles: Record<string, Record<string, string[]>>
  everyOrg: Record<string, Record<string, string[]>>
  routeMap: Record<string, { rules: RouteRule[] }>
}> {
  const apps = JSON.parse((await redis.get(APPS_KEY)) ?? '[]') as string[]
  const kinds = ['roles', 'groups', 'org_roles', 'every_org', 'route_map'] as const
  const keys = apps.flatMap((a) => kinds.map((k) => `rbac2:${k}:${a}`))
  const values = keys.length ? await redis.mget(...keys) : []
  const at = (app: string, kind: (typeof kinds)[number]) => {
    const raw = values[apps.indexOf(app) * kinds.length + kinds.indexOf(kind)]
    return raw ? JSON.parse(raw) : null
  }
  const out = { apps, roles: {} as Record<string, Record<string, string[]>>, groups: {} as Record<string, Record<string, string[]>>, orgRoles: {} as Record<string, Record<string, string[]>>, everyOrg: {} as Record<string, Record<string, string[]>>, routeMap: {} as Record<string, { rules: RouteRule[] }> }
  for (const app of apps) {
    const roles = at(app, 'roles')
    if (roles) out.roles[app] = roles
    const groups = at(app, 'groups') as Record<string, Record<string, string[]>> | null
    // A group name belongs to one owner; a second owner's definition of it is ignored (first wins).
    for (const [g, def] of Object.entries(groups ?? {})) if (!out.groups[g]) out.groups[g] = def
    const orgRoles = at(app, 'org_roles')
    if (orgRoles) out.orgRoles[app] = orgRoles
    const everyOrg = at(app, 'every_org')
    if (everyOrg) out.everyOrg[app] = everyOrg
    const routeMap = at(app, 'route_map')
    if (routeMap) out.routeMap[app] = routeMap
  }
  return out
}
