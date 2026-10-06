import type { FastifyReply, FastifyRequest } from 'fastify'
import { mcpGate } from '../mcp/settings.js'
import { getApiKeyPolicy, setApiKeyPolicy } from '../services/api-key-policy.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { apiKeyPolicySchema } from '../schemas/api-key.schema.js'

type OrgRequest = FastifyRequest<{ Params: { organizationId: string } }>

/** The org's personal-key policy exists only while MCP is on (mcp/settings.ts): 404 otherwise, as /api/me/api-keys. */
async function notEnabled(reply: FastifyReply): Promise<FastifyReply | null> {
  const gate = await mcpGate()
  if (gate.on) return null
  if (gate.off === 'unavailable') return reply.status(503).send({ error: 'settings_unavailable', message: 'The AI assistant settings cannot be read right now.' })
  return reply.status(404).send({ error: 'Not Found', message: 'Personal API keys are not enabled on this deployment.' })
}

/** The org's personal-key policy (deprecated). Guarded with every key route. */
export class ApiKeyScopesController {
  async getPolicy(request: OrgRequest, reply: FastifyReply) {
    const off = await notEnabled(reply)
    if (off) return off
    return reply.send(await getApiKeyPolicy(request.params.organizationId))
  }

  async setPolicy(request: OrgRequest, reply: FastifyReply) {
    const off = await notEnabled(reply)
    if (off) return off
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
