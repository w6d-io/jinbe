import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { rbacService } from '../services/rbac.service.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { orgGrantsRepository } from '../services/org-grants.repository.js'
import { siteLoginStore } from '../sites/login-store.js'
import { env } from '../config/env.js'
import { requireOpalClient } from '../middleware/require-opal-client.js'
import { serviceUnavailableResponseSchema } from '../schemas/response-schemas.js'
import { opalDatasourceRequests, opalDatasourceDuration, opalDatasourceLastSuccess } from '../telemetry/metrics.js'

// =============================================================================
// OPAL Data Routes — called by the OPAL server/client only, guarded by the OPAL client token
// =============================================================================

export async function rbacOpalRoutes(fastify: FastifyInstance) {
  fastify.addHook('onRequest', requireOpalClient)
  fastify.addHook('onResponse', recordDatasourceFetch)

  // Bindings: user → groups + org membership (from Kratos). Routed through the
  // service so the shape can't drift from the tested getBindingsFromKratos().
  fastify.get('/bindings', {
    schema: {
      description:
        'OPAL data source: user → groups + org membership, read from Kratos. 503 when Kratos cannot be ' +
        'read, so OPAL keeps the bindings OPA already holds instead of replacing them with an empty set.',
      tags: ['rbac'],
      // No 200 schema: the dataset is keyed by email — let it pass through unserialized.
      response: { 503: serviceUnavailableResponseSchema },
    },
  }, async (request, reply) => {
    try {
      const bindings = await rbacService.getBindingsFromKratos()
      return reply.send(bindings)
    } catch (err) {
      // 503, never an empty dataset. OPAL skips an entry whose fetch fails and leaves what OPA
      // already holds at /bindings (opal_client/data/updater.py `_store_fetched_update`); an empty
      // 200 would REPLACE it and deny everybody, super_admin included, until the next fetch.
      // With no previous data OPA still has none at /bindings, and the policy denies on that.
      request.log.error({ err }, 'bindings: Kratos unavailable — answering 503 so OPAL keeps the last good data')
      return reply.status(503).send({
        error: 'Service Unavailable',
        message: 'Identity bindings could not be read from Kratos. Keep the last good data and retry.',
      })
    }
  })

  // Groups: group → service → roles
  fastify.get('/opal/groups', async (_request, reply) => {
    const groups = await redisRbacRepository.getGroups()
    return reply.send(groups)
  })

  // Org → service map: { organizationId: [serviceName, …] } (feeds data.org_service_map).
  // Values are service bundles (arrays). Legacy scalar values in Redis are
  // normalized to single-element arrays by the repository before serving.
  fastify.get('/opal/org_service_map', async (_request, reply) => {
    const map = await redisRbacRepository.getOrgServiceMap()
    return reply.send(map)
  })

  // Org → admin roster: { organizationId: [email, …] } (feeds data.org_admin_map).
  fastify.get('/opal/org_admin_map', async (_request, reply) => {
    const map = await redisRbacRepository.getOrgAdminMap()
    return reply.send(map)
  })

  // Org grants: { organizationId: { email: [group, …] } } (feeds data.org_grants). 503 on a store
  // error, never an empty or partial map — same rule as /bindings: OPAL then keeps what OPA holds,
  // where an empty 200 would silently take every org grant away.
  fastify.get('/opal/org_grants', {
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

  // Roles per service
  fastify.get('/opal/roles/:service', async (request, reply) => {
    const { service } = request.params as { service: string }
    const roles = await redisRbacRepository.getRoles(service)
    return reply.send(roles || {})
  })

  // Route map per service
  fastify.get('/opal/route_map/:service', async (request, reply) => {
    const { service } = request.params as { service: string }
    const routeMap = await redisRbacRepository.getRouteMap(service)
    return reply.send(routeMap || { rules: [] })
  })

  // OPAL datasource config (tells OPAL what to fetch)
  fastify.get('/opal-datasource', async (_request, reply) => {
    const services = await redisRbacRepository.getServices()
    const jinbeUrl = env.JINBE_INTERNAL_URL || 'http://jinbe:8080'

    const entries = [
      { url: `${jinbeUrl}/api/admin/rbac/bindings`, topics: ['policy_data'], dst_path: '/bindings' },
      { url: `${jinbeUrl}/api/admin/rbac/opal/groups`, topics: ['policy_data'], dst_path: '/bindings/groups' },
      // Global roles are always part of OPA's dataset, even though "global"
      // is not listed in the services registry — they hold the platform-wide
      // wildcard ("*") used by the super_admin role and the rego super_admin
      // detector relies on data.roles.global being populated.
      { url: `${jinbeUrl}/api/admin/rbac/opal/roles/global`, topics: ['policy_data'], dst_path: '/roles/global' },
      // Org → service map (data.org_service_map): the delegation rego resolves
      // which service a target org's RBAC lives under from this.
      { url: `${jinbeUrl}/api/admin/rbac/opal/org_service_map`, topics: ['policy_data'], dst_path: '/org_service_map' },
      // Org → admin roster (data.org_admin_map): per-org list of admin emails;
      // manageable_orgs + the org-mgmt allow clause resolve org admins from it.
      { url: `${jinbeUrl}/api/admin/rbac/opal/org_admin_map`, topics: ['policy_data'], dst_path: '/org_admin_map' },
      // Org grants (data.org_grants): groups an org admin handed out in THEIR org; the org layer
      // counts them only on that org's routes.
      { url: `${jinbeUrl}/api/admin/rbac/opal/org_grants`, topics: ['policy_data'], dst_path: '/org_grants' },
      // Per-site 2FA (data.site_login): the bar each Site sets, published with its permissions.
      { url: `${jinbeUrl}/api/admin/rbac/opal/site_login`, topics: ['policy_data'], dst_path: '/site_login' },
    ]

    for (const svc of services) {
      entries.push({ url: `${jinbeUrl}/api/admin/rbac/opal/roles/${svc}`, topics: ['policy_data'], dst_path: `/roles/${svc}` })
      const routeMap = await redisRbacRepository.getRouteMap(svc)
      if (routeMap) {
        entries.push({ url: `${jinbeUrl}/api/admin/rbac/opal/route_map/${svc}`, topics: ['policy_data'], dst_path: `/route_map/${svc}` })
      }
    }

    // The client sends this on every data fetch; only reached once it proved it holds the token.
    const auth = { config: { headers: { Authorization: `Bearer ${env.OPAL_CLIENT_TOKEN}` } } }
    return reply.send({ entries: entries.map((entry) => ({ ...entry, ...auth })) })
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
  if (status < 300) opalDatasourceLastSuccess.labels(entry).set(Date.now() / 1000)
}
