import type { Redis } from 'ioredis'
import { createHash } from 'crypto'
import { canonicalJson } from './hash.js'
import type { RouteRule } from '../services/redis-rbac.repository.js'
import { GENERATED_ROUTE_MAP } from '../policy/route-map.generated.js'
import { DOCS_ROW } from '../policy/route-map.js'
import { JINBE, ROLES, STAFF_ROLES, everyOrgDefinitions, orgRoleDefinitions, roleDefinitions, roleProblems, staffGroups } from '../policy/roles.js'

/**
 * What jinbe OWNS in the RBAC store, exactly as code defines it (authz-v2-design §3.5). Every
 * bootstrap run converges these and nothing else; the API refuses writes to them (409
 * `defined_in_code`). Replaced, never merged — so a rename in code lands on every install.
 *
 *   rbac:roles:jinbe                 the staff roles, super_admin generated
 *   rbac:org_roles:jinbe             jinbe's org roles
 *   rbac:every_org:jinbe             what each staff role carries into every org
 *   rbac:route_map:jinbe             generated from the route declarations (+ /docs with swagger)
 *   rbac:groups[<staff group>]       { jinbe: [<role>] } for each staff group and super_admins
 *   rbac:groups:meta[<staff group>]  system: true, the role's label
 *   rbac:services ∋ jinbe, rbac:services:meta[jinbe] system: true
 *   rbac:owned:jinbe                 what jinbe last wrote, per slot (sha256) — the drift check
 */

/** One place jinbe writes: a whole key, or one field of a hash. */
export type Slot = { key: string; field?: string }

export const slotName = (s: Slot) => (s.field ? `${s.key}#${s.field}` : s.key)
export const OWNED_KEY = (owner: string) => `rbac:owned:${owner}`

const sha = (s: string) => createHash('sha256').update(s).digest('hex')

/** jinbe's slots and their contents. Throws when the roles are unsound (the boot check). */
export function jinbeOwned(opts: { docs: boolean }): Array<{ slot: Slot; value: string }> {
  const problems = roleProblems()
  if (problems.length > 0) throw new Error(`The roles in code are unsound: ${problems.join('; ')}`)
  const rules: RouteRule[] = [...GENERATED_ROUTE_MAP, ...(opts.docs ? [DOCS_ROW] : [])]
  const out: Array<{ slot: Slot; value: string }> = [
    { slot: { key: `rbac:roles:${JINBE}` }, value: canonicalJson(roleDefinitions()) },
    { slot: { key: `rbac:org_roles:${JINBE}` }, value: canonicalJson(orgRoleDefinitions()) },
    { slot: { key: `rbac:every_org:${JINBE}` }, value: canonicalJson(everyOrgDefinitions()) },
    { slot: { key: `rbac:route_map:${JINBE}` }, value: canonicalJson({ rules }) },
    { slot: { key: 'rbac:services:meta', field: JINBE }, value: canonicalJson({ system: true, description: 'jinbe itself: its roles and route map are code' }) },
  ]
  const groups = staffGroups()
  for (const role of STAFF_ROLES) {
    const { group, label } = ROLES[role]
    out.push({ slot: { key: 'rbac:groups', field: group }, value: canonicalJson(groups[group]) })
    out.push({ slot: { key: 'rbac:groups:meta', field: group }, value: canonicalJson({ system: true, description: label }) })
  }
  return out
}

export interface ConvergeResult {
  /** Slots rewritten because code changed them since the last write (an upgrade). */
  updated: string[]
  /** Slots rewritten because somebody changed them outside jinbe (alerted: rbac.owned_drift). */
  drifted: string[]
  /** Slots written for the first time. */
  created: string[]
}

type Reader = Pick<Redis, 'get' | 'hget' | 'sismember' | 'multi'>

async function read(redis: Reader, s: Slot): Promise<string | null> {
  return s.field ? redis.hget(s.key, s.field) : redis.get(s.key)
}

/**
 * Converges one owner's slots on `desired`: unchanged ones are left alone, the rest replaced in ONE
 * MULTI with the owned record, so a reader never sees half a model. A slot whose stored value is not
 * what the owner last wrote is DRIFT (written by hand): reported so the caller alerts, and rewritten
 * anyway (D5: converge and alert; refusing readiness on prod comes one quiet release later).
 */
export async function convergeOwned(redis: Reader, owner: string, desired: ReadonlyArray<{ slot: Slot; value: string }>, service?: string): Promise<ConvergeResult> {
  const ownedRaw = await redis.get(OWNED_KEY(owner))
  let lastWritten: Record<string, string> = {}
  try {
    lastWritten = ownedRaw ? (JSON.parse(ownedRaw) as Record<string, string>) : {}
  } catch {
    lastWritten = {}
  }
  const result: ConvergeResult = { updated: [], drifted: [], created: [] }
  const tx = redis.multi()
  for (const { slot, value } of desired) {
    const name = slotName(slot)
    const current = await read(redis, slot)
    if (current === value) continue
    if (current === null || current === undefined) result.created.push(name)
    else if (lastWritten[name] && sha(current) !== lastWritten[name]) result.drifted.push(name)
    else result.updated.push(name)
    if (slot.field) tx.hset(slot.key, slot.field, value)
    else tx.set(slot.key, value)
  }
  const registered = service ? (await redis.sismember('rbac:services', service)) === 1 : true
  if (!registered) tx.sadd('rbac:services', service!)
  const owned = canonicalJson(Object.fromEntries(desired.map(({ slot, value }) => [slotName(slot), sha(value)])))
  if (result.created.length + result.updated.length + result.drifted.length === 0 && registered && ownedRaw === owned) {
    tx.discard()
    return result
  }
  tx.set(OWNED_KEY(owner), owned)
  await tx.exec()
  return result
}
