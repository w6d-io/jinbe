import { getRedisClient } from '../services/redis-client.service.js'
import { kratosService } from '../services/kratos.service.js'
import { allOrganisations } from '../services/organisation-store.js'
import { auditEventService } from '../services/audit-event.service.js'
import { rbacOwnedDrift } from '../telemetry/metrics.js'
import { env } from '../config/env.js'
import { convergeOwned, jinbeOwnedKeys, readV2Keys, type ConvergeResult } from './store.js'
import { buildDataV2, type IdentityFacts } from './dataset.js'
import type { DataV2 } from './resolve.js'
import { JINBE } from './roles.js'
import { AUTHZ_ACTIVE_KEY, parseModel, type AuthzModel } from './model.js'

/** The I/O around the pure v2 model: Redis, the identity directory, the organisation registry. */

interface Logger {
  info(obj: object, msg?: string): void
  warn(obj: object, msg?: string): void
}

/**
 * Converges jinbe's code-owned rbac2 keys (every bootstrap run, no-op boots included, like the staff
 * roles). A hand edit is rewritten and alerted: audit `rbac.owned_drift` (high) and
 * jinbe_rbac_owned_drift_total.
 */
export async function convergeJinbeV2(logger: Logger): Promise<ConvergeResult> {
  const result = await convergeOwned(getRedisClient(), JINBE, jinbeOwnedKeys({ docs: env.ENABLE_SWAGGER }))
  for (const key of result.drifted) {
    rbacOwnedDrift.labels(key).inc()
    auditEventService.emit({
      category: 'rbac', kind: 'security', verb: 'update', target: key,
      result: 'applied', reason: 'rbac.owned_drift', severity: 'high',
      actor: { email: 'system', type: 'system' }, source: 'bootstrap',
    }).catch(() => {})
  }
  if (result.drifted.length) logger.warn({ drifted: result.drifted }, 'authz v2: code-owned keys were edited outside jinbe — converged back')
  if (result.created.length || result.updated.length) {
    logger.info({ created: result.created, updated: result.updated }, 'authz v2: code-owned keys written (not active until the switch)')
  }
  return result
}

/** The identities as data.v2 reads them (one directory walk). */
export async function identityFacts(): Promise<Map<string, IdentityFacts>> {
  const bindings = await kratosService.getAllIdentitiesWithBindings()
  const out = new Map<string, IdentityFacts>()
  for (const [email, b] of bindings) {
    const organizations = [...b.organizations]
    if (b.primaryOrganization && !organizations.includes(b.primaryOrganization)) organizations.push(b.primaryOrganization)
    out.set(email, { groups: b.groups, organizations, organizationRoles: b.organizationRoles })
  }
  return out
}

export async function knownOrganisations(): Promise<string[]> {
  return (await allOrganisations()).map((o) => o.id)
}

/** data.v2 as OPAL publishes it. Throws when any source fails: the feed answers 503, never a partial model. */
export async function loadDataV2(): Promise<DataV2> {
  const [keys, identities, orgs] = await Promise.all([readV2Keys(getRedisClient()), identityFacts(), knownOrganisations()])
  return buildDataV2(keys, identities, orgs)
}

export async function readAuthzActive(): Promise<AuthzModel> {
  return parseModel(await getRedisClient().get(AUTHZ_ACTIVE_KEY)) ?? 'v1'
}
