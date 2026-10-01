import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { rbacService } from '../services/rbac.service.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { orgGrantsRepository } from '../services/org-grants.repository.js'
import { siteLoginStore } from '../sites/login-store.js'
import { getSecondFactorGroups } from '../second-factor/settings.js'
import { buildOpalDatasourceEntries, opalRolesDataset, opalRouteMapsDataset } from '../services/opal-datasource.js'
import { requireOpalClient } from '../middleware/require-opal-client.js'
import { serviceUnavailableResponseSchema } from '../schemas/response-schemas.js'
import { opalDatasourceRequests, opalDatasourceDuration, opalDatasourceLastSuccess } from '../telemetry/metrics.js'
import { mirrorOpalFetch } from '../home/runtime.js'
import { apiClientsDataset } from '../services/api-clients.js'
import { open } from '../policy/route-access.js'
import { bindingsWithLowercaseKeys, rosterForPolicy } from '../services/email-spellings.js'
import { loadDataV2, readAuthzActive } from '../authz-v2/service.js'

// =============================================================================
// OPAL Data Routes — called by the OPAL server/client only, guarded by the OPAL client token
// =============================================================================

export async function rbacOpalRoutes(fastify: FastifyInstance) {
  fastify.addHook('onRequest', requireOpalClient)
  fastify.addHook('onResponse', recordDatasourceFetch)

  // Bindings: user → groups + org membership (from Kratos) AND group → service → roles (from Redis),
  // i.e. the whole of data.bindings in one document. Routed through the service so the shape can't drift
  // from the tested getBindingsFromKratos().
  //
  // `groups` MUST travel here, not in an entry of its own at /bindings/groups: OPAL writes each entry
  // with its own PUT and OPA's PUT replaces the subtree, so a PUT on /bindings wiped data.bindings.groups
  // until the child PUT landed — every group-derived role (super_admin included) denied for that window,
  // every refresh, and for a whole refresh period whenever the groups fetch failed.
  fastify.get('/bindings', {
    ...open('machine'),
    schema: {
      description:
        'OPAL data source: all of data.bindings — user → groups + org membership (Kratos) and group → ' +
        'service → roles (`groups`, Redis). 503 when either cannot be read, so OPAL keeps the bindings OPA ' +
        'already holds instead of replacing them with an empty or partial set.',
      tags: ['rbac'],
      // No 200 schema: the dataset is keyed by email — let it pass through unserialized.
      response: { 503: serviceUnavailableResponseSchema },
    },
  }, async (request, reply) => {
    try {
      const [bindings, groups] = await Promise.all([rbacService.getBindingsFromKratos(), redisRbacRepository.getGroups()])
      // Each address also under its lowercase key: the roster is lowercased (email-spellings.ts).
      return reply.send({ ...bindingsWithLowercaseKeys(bindings), groups })
    } catch (err) {
      // 503, never an empty or partial dataset. OPAL skips an entry whose fetch fails and leaves what OPA
      // already holds at /bindings (opal_client/data/updater.py `_store_fetched_update`); an empty
      // 200 would REPLACE it and deny everybody, super_admin included, until the next fetch — and a
      // 200 without `groups` would do the same to every group-derived role.
      // With no previous data OPA still has none at /bindings, and the policy denies on that.
      request.log.error({ err }, 'bindings: Kratos or the group store unavailable — answering 503 so OPAL keeps the last good data')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Identity bindings or groups could not be read. Keep the last good data and retry.',
      })
    }
  })

  // Groups: group → service → roles. No longer in the manifest (it travels inside /bindings); kept for an
  // OPAL client still polling the manifest it pulled before, which writes the same groups right after
  // /bindings. 503 on a store error, like every data source.
  fastify.get('/opal/groups', {
    ...open('machine'),
    schema: {
      description:
        'OPAL data source (older manifests only — now part of /bindings): group → service → roles. 503 when ' +
        'the store cannot be read, so OPAL keeps the groups OPA already holds.',
      tags: ['rbac'],
      response: { 503: serviceUnavailableResponseSchema },
    },
  }, async (request, reply) => {
    try {
      return reply.send(await redisRbacRepository.getGroups())
    } catch (err) {
      request.log.error({ err }, 'groups: store unavailable — answering 503 so OPAL keeps the last good data')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Groups could not be read. Keep the last good data and retry.',
      })
    }
  })

  // Org → service map: { organizationId: [serviceName, …] } (feeds data.org_service_map).
  // Values are service bundles (arrays). Legacy scalar values in Redis are
  // normalized to single-element arrays by the repository before serving.
  fastify.get('/opal/org_service_map', open('machine'), async (_request, reply) => {
    const map = await redisRbacRepository.getOrgServiceMap()
    return reply.send(map)
  })

  // Org → admin roster: { organizationId: [email, …] } (feeds data.org_admin_map). Every spelling of
  // each entry (as stored, lowercased, as the identity spells it) while the policy compares addresses
  // exactly; the identities are best effort — without them the stored and lowercase spellings still go.
  fastify.get('/opal/org_admin_map', open('machine'), async (request, reply) => {
    const stored = await redisRbacRepository.getOrgAdminMapAsStored()
    let addresses: string[] = []
    try {
      addresses = Object.keys((await rbacService.getBindingsFromKratos()).group_membership)
    } catch (err) {
      request.log.warn({ err: (err as Error).message }, 'org_admin_map: identities unavailable — publishing stored and lowercase spellings only')
    }
    return reply.send(rosterForPolicy(stored, addresses))
  })

  // Org grants: { organizationId: { email: [group, …] } } (feeds data.org_grants). 503 on a store
  // error, never an empty or partial map — same rule as /bindings: OPAL then keeps what OPA holds,
  // where an empty 200 would silently take every org grant away.
  fastify.get('/opal/org_grants', {
    ...open('machine'),
    schema: {
      description:
        'OPAL data source: groups handed out per org by its admins (data.org_grants). 503 when the store ' +
        'cannot be read, so OPAL keeps the org grants OPA already holds.',
      tags: ['rbac'],
      // No 200 schema: keyed by org id and email — let it pass through unserialized.
      response: { 503: serviceUnavailableResponseSchema },
    },
  }, async (request, reply) => {
    try {
      return reply.send(await orgGrantsRepository.getAll())
    } catch (err) {
      request.log.error({ err }, 'org_grants: store unavailable — answering 503 so OPAL keeps the last good data')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Org grants could not be read. Keep the last good data and retry.',
      })
    }
  })

  // Per-site 2FA: { site: {min_aal, scope, routes, clients} } (feeds data.site_login). Empty when no
  // site asks for a second factor; 503 on a store error — an empty 200 would silently drop every
  // site's 2FA bar until the next fetch.
  fastify.get('/opal/site_login', {
    ...open('machine'),
    schema: {
      description:
        'OPAL data source: per-site sign-in strength (data.site_login). 503 when the store cannot be read, ' +
        'so OPAL keeps the 2FA requirements OPA already holds.',
      tags: ['rbac'],
      response: { 503: serviceUnavailableResponseSchema },
    },
  }, async (request, reply) => {
    try {
      return reply.send(await siteLoginStore.getAll())
    } catch (err) {
      request.log.error({ err }, 'site_login: store unavailable — answering 503 so OPAL keeps the last good data')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Site login settings could not be read. Keep the last good data and retry.',
      })
    }
  })

  // Org API keys: { client_id: {org, scopes, expires_at?} } (feeds data.api_clients) — what the policy
  // needs to decide a machine caller on a site. 503 when Hydra cannot be read: an empty 200 would
  // replace what OPA holds and cut every integration off until the next fetch.
  fastify.get('/opal/api_clients', {
    ...open('machine'),
    schema: {
      description:
        'OPAL data source: org API keys (Hydra client_credentials clients) by client_id — organization, registered ' +
        'scopes, expiry (data.api_clients). 503 when Hydra cannot be read, so OPAL keeps the last good data.',
      tags: ['rbac'],
      response: { 503: serviceUnavailableResponseSchema },
    },
  }, async (request, reply) => {
    try {
      return reply.send(await apiClientsDataset())
    } catch (err) {
      request.log.error({ err: (err as Error).message }, 'api_clients: Hydra unavailable — answering 503 so OPAL keeps the last good data')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'API clients could not be read from the OAuth2 server. Keep the last good data and retry.',
      })
    }
  })

  // Platform 2FA: { groups: [...] } — every group switched to "Members must use 2FA" (feeds
  // data.second_factor; second-factor/settings.ts), read fresh so a new group is in it. 503 on a store
  // error — an empty 200 would silently let every privileged account sign in without a second factor.
  fastify.get('/opal/second_factor', {
    ...open('machine'),
    schema: {
      description:
        'OPAL data source: groups switched to "Members must use 2FA" (data.second_factor). 503 when the store ' +
        'cannot be read, so OPAL keeps the requirement OPA already holds.',
      tags: ['rbac'],
      response: { 503: serviceUnavailableResponseSchema },
    },
  }, async (request, reply) => {
    try {
      return reply.send({ groups: await getSecondFactorGroups({ fresh: true }) })
    } catch (err) {
      request.log.error({ err }, 'second_factor: store unavailable — answering 503 so OPAL keeps the last good data')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'The second-factor requirement could not be read. Keep the last good data and retry.',
      })
    }
  })

  // Roles of every service plus "global": { <svc>: roles } (feeds data.roles). No try/catch: a read
  // error answers 500 and OPAL keeps what OPA holds — this entry replaces the whole subtree.
  fastify.get('/opal/roles', open('machine'), async (_request, reply) => {
    return reply.send(await opalRolesDataset())
  })

  // Route map of every service that has one: { <svc>: {rules} } (feeds data.route_map). Same rule.
  fastify.get('/opal/route_maps', open('machine'), async (_request, reply) => {
    return reply.send(await opalRouteMapsDataset())
  })

  // Roles per service. No longer in the manifest; kept for an OPAL client still polling the entries
  // of the manifest it pulled before the aggregate entries shipped.
  fastify.get('/opal/roles/:service', open('machine'), async (request, reply) => {
    const { service } = request.params as { service: string }
    const roles = await redisRbacRepository.getRoles(service)
    return reply.send(roles || {})
  })

  // Route map per service (same: kept for clients on an older manifest)
  fastify.get('/opal/route_map/:service', open('machine'), async (request, reply) => {
    const { service } = request.params as { service: string }
    const routeMap = await redisRbacRepository.getRouteMap(service)
    return reply.send(routeMap || { rules: [] })
  })

  // authz v2 (authz-v2-design §3.2): ALL of data.v2 in one document, so OPA never holds half a model.
  // In the manifest only with RBAC_V2_PUBLISH; nothing decides on it until the router does.
  fastify.get('/opal/v2', {
    ...open('machine'),
    schema: {
      description:
        'OPAL data source (authz v2): all of data.v2 — roles, groups, memberships, org roles and assignments, ' +
        'the every-org map, org entitlements, route maps and the catalogue. 503 when any source cannot be read, ' +
        'so OPAL keeps the last good copy.',
      tags: ['rbac'],
      response: { 503: serviceUnavailableResponseSchema },
    },
  }, async (request, reply) => {
    try {
      return reply.send(await loadDataV2())
    } catch (err) {
      request.log.error({ err: (err as Error).message }, 'v2: a source is unavailable — answering 503 so OPAL keeps the last good data')
      return reply.status(503).send({ error: 'Service Unavailable', message: 'The v2 model could not be read. Keep the last good data and retry.' })
    }
  })

  // Which model decides (data.authz.active): the router in opal-policies reads it. 503 on a store error,
  // so OPAL keeps the value OPA holds instead of falling back to a default mid-incident.
  fastify.get('/opal/authz', {
    ...open('machine'),
    schema: {
      description: 'OPAL data source (authz v2): which authorization model is active, {"active":"v1"|"v2"} (data.authz).',
      tags: ['rbac'],
      response: { 503: serviceUnavailableResponseSchema },
    },
  }, async (request, reply) => {
    try {
      return reply.send({ active: await readAuthzActive() })
    } catch (err) {
      request.log.error({ err: (err as Error).message }, 'authz: store unavailable — answering 503 so OPAL keeps the last good data')
      return reply.status(503).send({ error: 'Service Unavailable', message: 'The active model could not be read. Keep the last good data and retry.' })
    }
  })

  // OPAL datasource config (tells OPAL what to fetch)
  // Only reached once the caller proved it holds the OPAL client token the entries carry.
  fastify.get('/opal-datasource', open('machine'), async (_request, reply) => {
    return reply.send({ entries: await buildOpalDatasourceEntries() })
  })
}

/**
 * Per-entry fetch metrics. The entry is the datasource path (`bindings`, `opal/roles/kuma`) once the
 * caller proved it is the OPAL client; a refused or failed call is filed under the route pattern, so
 * an arbitrary path cannot mint a new series.
 */
async function recordDatasourceFetch(request: FastifyRequest, reply: FastifyReply) {
  const status = reply.statusCode
  const path = status < 400 ? request.url.split('?')[0] : (request.routeOptions?.url ?? 'unknown')
  const entry = path.replace(/^.*\/admin\/rbac\/(develop\/)?/, '')
  const statusClass = status >= 500 ? '5xx' : status >= 400 ? '4xx' : status >= 300 ? '3xx' : '2xx'
  opalDatasourceRequests.labels(entry, statusClass).inc()
  opalDatasourceDuration.labels(entry).observe(reply.elapsedTime / 1000)
  if (status < 300) {
    opalDatasourceLastSuccess.labels(entry).set(Date.now() / 1000)
    // The manifest is read once, when a client connects: it is not data, and counting it made the Home
    // call policy sync stale for as long as the client had been up.
    if (entry !== 'opal-datasource') mirrorOpalFetch(entry)
  }
}
