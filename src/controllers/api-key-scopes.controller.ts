import type { FastifyReply, FastifyRequest } from 'fastify'
import { env } from '../config/index.js'
import { scopeCatalog } from '../services/api-key-scopes.js'
import { getApiKeyPolicy, setApiKeyPolicy } from '../services/api-key-policy.js'
import { AuthzUnavailableError } from '../authz/opa.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { apiKeyPolicySchema } from '../schemas/api-key.schema.js'

type OrgRequest = FastifyRequest<{ Params: { organizationId: string } }>

function policyUnavailable(reply: FastifyReply) {
  return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: 'Unable to read what you hold in this organization. Please try again later.' })
}

function notEnabled(reply: FastifyReply) {
  return reply.status(404).send({ error: 'Not Found', message: 'Personal API keys are not enabled on this deployment.' })
}

/** The per-org scope catalog and the org's personal-key policy. Guarded with every key route. */
export class ApiKeyScopesController {
  async catalog(request: OrgRequest, reply: FastifyReply) {
    try {
      return reply.send({ scopes: await scopeCatalog(request.params.organizationId, request.userContext?.email ?? '') })
    } catch (err) {
      if (err instanceof AuthzUnavailableError) return policyUnavailable(reply)
      throw err
    }
  }

  async getPolicy(request: OrgRequest, reply: FastifyReply) {
    if (!env.DELEGATED_TOKENS_ENABLED) return notEnabled(reply)
    return reply.send(await getApiKeyPolicy(request.params.organizationId))
  }

  async setPolicy(request: OrgRequest, reply: FastifyReply) {
    if (!env.DELEGATED_TOKENS_ENABLED) return notEnabled(reply)
    const { organizationId } = request.params
    const next = apiKeyPolicySchema.parse(request.body)
    const before = await getApiKeyPolicy(organizationId)
    const saved = await setApiKeyPolicy(organizationId, next)
    if (before.personal_keys !== saved.personal_keys) {
      auditEventService
        .emit({
          type: 'api_key.policy_changed',
          actor: auditActor(request),
          target: { type: 'organization', id: organizationId },
          details: { organizationId, personal_keys: saved.personal_keys, before: before.personal_keys },
          source: 'jinbe-api',
        })
        .catch(() => {})
    }
    return reply.send(saved)
  }
}

export const apiKeyScopesController = new ApiKeyScopesController()
