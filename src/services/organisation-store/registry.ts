import { randomUUID } from 'node:crypto'
import { SwrCache } from '../../cache/swr.js'
import { getRedisClient } from '../redis-client.service.js'
import { withRedisLock } from '../redis-lock.js'
import {
  OrganisationNotFoundError,
  OrganisationStoreUnavailableError,
  type Organisation,
  type OrganisationChange,
  type OrganisationDeployment,
} from './types.js'

/**
 * The organisation registry of the `kratos` store: what an organisation IS, in Redis, beside the
 * rest of the model this service already keeps there (groups, org grants, the admin roster).
 *
 *   rbac:organisations             id → {id, name, tenant, attributes}   tenant is the slug, attributes the settings
 *   rbac:organisation_deployments  id → {application: enabled}           the entitlements
 *
 * Who BELONGS to an organisation is not here: that is on the identity, the one place every service
 * that reads an identity already looks. Tens of records, read whole or by id; nothing to join.
 */

const REGISTRY = 'rbac:organisations'
const DEPLOYMENTS = 'rbac:organisation_deployments'

function redis() {
  return getRedisClient()
}

/**
 * Both hashes are read whole on hot paths (names on /me, the home screens, every org picker), so
 * each is held as one entry in the shared cache (namespaces org.registry / org.deployments) and
 * dropped on every write here, on every replica. Tens of records: one entry each.
 */
const MINUTE = 60_000
const registryCache = new SwrCache<Record<string, string>>({ namespace: 'org.registry', freshMs: MINUTE, staleMs: 10 * MINUTE, l1Max: 1 })
const deploymentsCache = new SwrCache<Record<string, string>>({ namespace: 'org.deployments', freshMs: MINUTE, staleMs: 10 * MINUTE, l1Max: 1 })

const registryHash = () => registryCache.get('all', async () => (await redis().hgetall(REGISTRY)) ?? {})
const deploymentsHash = () => deploymentsCache.get('all', async () => (await redis().hgetall(DEPLOYMENTS)) ?? {})

function dropRegistry() {
  void registryCache.invalidate()
}
function dropDeployments() {
  void deploymentsCache.invalidate()
}

/** Never an empty answer for a store that did not answer: "cannot tell" is not "none". */
async function guarded<T>(what: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (failure) {
    if (failure instanceof OrganisationNotFoundError) throw failure
    throw new OrganisationStoreUnavailableError(`The organisation registry could not ${what}: ${String(failure)}`)
  }
}

function parse(raw: string | null | undefined): Organisation | null {
  if (!raw) return null
  try {
    const o = JSON.parse(raw) as Partial<Organisation>
    if (typeof o.id !== 'string' || typeof o.name !== 'string' || typeof o.tenant !== 'string') return null
    return { id: o.id, name: o.name, tenant: o.tenant, attributes: o.attributes && typeof o.attributes === 'object' ? o.attributes : {} }
  } catch {
    return null
  }
}

function parseDeployments(raw: string | null | undefined): Record<string, boolean> {
  if (!raw) return {}
  try {
    const parsed = JSON.parse(raw) as unknown
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
    return Object.fromEntries(Object.entries(parsed).filter((e): e is [string, boolean] => typeof e[1] === 'boolean'))
  } catch {
    return {}
  }
}

const byTenantThenName = (a: Organisation, b: Organisation) => a.tenant.localeCompare(b.tenant) || a.name.localeCompare(b.name)

export function allOrganisations(): Promise<Organisation[]> {
  return guarded('be read', async () => {
    const raw = await registryHash()
    return Object.values(raw)
      .map(parse)
      .filter((o): o is Organisation => o !== null)
      .sort(byTenantThenName)
  })
}

/** The named organisations, in the order asked, skipping any not held. */
export function organisationsById(ids: readonly string[]): Promise<Organisation[]> {
  if (ids.length === 0) return Promise.resolve([])
  return guarded('be read', async () => {
    const raw = await registryHash()
    return ids.map((id) => parse(raw[id])).filter((o): o is Organisation => o !== null)
  })
}

export async function organisationHeld(id: string): Promise<boolean> {
  return guarded('be read', async () => id in (await registryHash()))
}

export function createOrganisation(input: {
  name: string
  tenant: string
  attributes?: Readonly<Record<string, unknown>>
}): Promise<Organisation> {
  const record: Organisation = { id: randomUUID(), name: input.name, tenant: input.tenant, attributes: input.attributes ?? {} }
  return guarded('be written', async () => {
    await redis().hset(REGISTRY, record.id, JSON.stringify(record))
    dropRegistry()
    return record
  })
}

/** Insert or replace a record under the id the source already had (imports, restores). */
export function putOrganisation(record: Organisation): Promise<void> {
  return guarded('be written', async () => {
    await redis().hset(REGISTRY, record.id, JSON.stringify(record))
    dropRegistry()
  })
}

export function updateOrganisation(id: string, change: OrganisationChange): Promise<Organisation> {
  return guarded('be written', () =>
    withRedisLock(`org-registry:${id}`, async () => {
      const current = parse(await redis().hget(REGISTRY, id))
      if (!current) throw new OrganisationNotFoundError(id)
      const next: Organisation = {
        id,
        name: change.name ?? current.name,
        tenant: change.tenant ?? current.tenant,
        attributes: change.attributes ?? current.attributes,
      }
      await redis().hset(REGISTRY, id, JSON.stringify(next))
      dropRegistry()
      return next
    }),
  )
}

/** Remove the record and its entitlements. Whether anybody still belongs is the caller's check. */
export function deleteOrganisation(id: string): Promise<void> {
  return guarded('be written', async () => {
    const removed = await redis().hdel(REGISTRY, id)
    await redis().hdel(DEPLOYMENTS, id)
    dropRegistry()
    dropDeployments()
    if (removed === 0) throw new OrganisationNotFoundError(id)
  })
}

export function deploymentsOf(id: string): Promise<OrganisationDeployment[]> {
  return guarded('be read', async () =>
    Object.entries(parseDeployments((await deploymentsHash())[id]))
      .map(([application, enabled]) => ({ application, enabled }))
      .sort((a, b) => a.application.localeCompare(b.application)),
  )
}

/** Replace an organisation's deployments: they describe a whole set, and merging would keep removals. */
export function setDeployments(id: string, deployments: readonly OrganisationDeployment[]): Promise<void> {
  return guarded('be written', async () => {
    if (deployments.length === 0) await redis().hdel(DEPLOYMENTS, id)
    else await redis().hset(DEPLOYMENTS, id, JSON.stringify(Object.fromEntries(deployments.map((d) => [d.application, d.enabled]))))
    dropDeployments()
  })
}

/** Only what is ON, for the engine: a deployment turned off must not keep deciding. */
export function allEntitlements(): Promise<Map<string, string[]>> {
  return guarded('be read', async () => {
    const held = new Map<string, string[]>()
    const raw = await deploymentsHash()
    for (const id of Object.keys(raw).sort()) {
      const on = Object.entries(parseDeployments(raw[id]))
        .filter(([, enabled]) => enabled)
        .map(([application]) => application)
        .sort()
      if (on.length > 0) held.set(id, on)
    }
    return held
  })
}
