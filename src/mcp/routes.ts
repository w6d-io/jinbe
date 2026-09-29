import type { FastifyInstance } from 'fastify'
import { requireAdmin, requireRecentMfa, requireSuperAdmin } from '../middleware/require-admin.js'
import { auditEventService } from '../services/audit-event.service.js'
import { delegatedTokenService } from '../services/delegated-token.service.js'
import { auditActor } from '../utils/audit-actor.js'
import { rights } from '../authz/opa.js'
import { defaultMcpSettings, deploymentServerUrl, effectiveServerUrl, getMcpSettings, groupAllowed, mcpCeiling, mcpGate, setMcpSettings, validateMcpSettings } from './settings.js'

const problemSchema = {
  type: 'object',
  properties: {
    error: { type: 'string' },
    message: { type: 'string' },
    problems: { type: 'array', items: { type: 'object', properties: { field: { type: 'string' }, message: { type: 'string' } } } },
  },
}

const settingsSchema = {
  type: 'object',
  properties: {
    enabled: { type: 'boolean' },
    serverUrl: { type: ['string', 'null'] },
    personalKeys: { type: 'object', properties: { maxDays: { type: 'integer' } } },
    allowedGroups: { anyOf: [{ type: 'string', enum: ['all'] }, { type: 'array', items: { type: 'string' } }] },
  },
}

const CEILING_NOTE =
  'DELEGATED_TOKENS_ENABLED is false on this deployment: MCP stays off whatever is saved here, until the deployment turns it on.'

/**
 * The setting (settings.ts).
 *   GET /api/admin/settings/mcp — admin
 *   PUT /api/admin/settings/mcp — super_admin + a recent second factor: who may act through an AI
 *       assistant, and for how long a key lives, is an access change.
 */
export async function mcpSettingsRoutes(fastify: FastifyInstance) {
  // With no saved address the deployment's (MCP_PUBLIC_URL) is shown in its place, so the console's
  // field holds the real address; saving it unchanged stores none, and the setting keeps following
  // the deployment.
  const view = async () => {
    const settings = await getMcpSettings()
    const ceiling = mcpCeiling()
    return {
      settings: { ...settings, serverUrl: effectiveServerUrl(settings) },
      defaults: { ...defaultMcpSettings(), serverUrl: deploymentServerUrl() },
      ceiling: { enabled: ceiling, note: ceiling ? null : CEILING_NOTE },
      effective: ceiling && settings.enabled,
    }
  }

  fastify.get('/mcp', {
    preHandler: requireAdmin,
    schema: {
      description:
        'The AI assistants (MCP) setting, the deployment ceiling (DELEGATED_TOKENS_ENABLED) and whether MCP is effectively ' +
        'on (ceiling AND switch).',
      tags: ['mcp'],
      response: {
        200: {
          type: 'object',
          properties: {
            settings: settingsSchema,
            defaults: settingsSchema,
            ceiling: { type: 'object', properties: { enabled: { type: 'boolean' }, note: { type: ['string', 'null'] } } },
            effective: { type: 'boolean' },
          },
        },
      },
    },
  }, view)

  fastify.put('/mcp', {
    preHandler: [requireSuperAdmin, requireRecentMfa],
    schema: {
      description:
        'Replace the AI assistants (MCP) setting. Turning it off refuses delegated tokens and personal-key exchange at ' +
        'once on this replica and within 5 seconds everywhere (keys stay stored, unusable); turning it on restores them. ' +
        'It can never lift the deployment ceiling: with DELEGATED_TOKENS_ENABLED=false the value is saved but MCP stays ' +
        'off (see `ceiling` and `effective`). Requires super_admin + a second factor proven within 15 minutes.',
      tags: ['mcp'],
      body: {
        type: 'object',
        required: ['enabled'],
        additionalProperties: false,
        properties: settingsSchema.properties,
      },
      response: { 400: problemSchema },
    },
  }, async (request, reply) => {
    const checked = validateMcpSettings(request.body)
    if (!checked.ok) {
      return reply.status(400).send({ error: 'invalid_settings', message: checked.problems.map((p) => `${p.field}: ${p.message}`).join('; '), problems: checked.problems })
    }
    if (checked.value.serverUrl !== null && checked.value.serverUrl === deploymentServerUrl()) checked.value.serverUrl = null
    const before = await getMcpSettings()
    const saved = await setMcpSettings(checked.value)
    // Cached tokens are re-gated on every call anyway; dropping them also re-reads what each still holds.
    if (before.enabled !== saved.enabled) delegatedTokenService.clearCache()
    const a = auditActor(request)
    auditEventService.emit({
      category: 'rbac', kind: 'change', verb: 'update', target: 'mcp',
      result: 'applied', severity: 'high', v1Event: 'config.mcp.changed',
      actor: { email: a.email ?? null, ip: a.ip, name: a.name, ua: a.ua, sessionId: a.sessionId },
      requestId: a.requestId,
      details: { before, after: saved, ceiling: mcpCeiling() },
    }).catch(() => {})
    return view()
  })
}

/**
 * GET /api/mcp/status — for any signed-in person (kuma Connections): is MCP on, where is the server,
 * how long may a new personal key live, and whether THEIR groups may use it (`allowed`; null when off
 * or when that cannot be told right now). `off` says why not: 'deployment' (the env ceiling) or
 * 'administrator' (the switch). Registered beside mcpRoutes, outside its actor-only hook; /api/mcp is
 * on the session gate's bypass list for auth-mcp, so the session is checked here.
 */
export async function mcpStatusRoutes(fastify: FastifyInstance) {
  fastify.get('/status', {
    schema: {
      description: 'Whether AI assistants (MCP) are on, the MCP server address, and why not when off. Any signed-in person.',
      tags: ['mcp'],
      response: {
        200: {
          type: 'object',
          properties: {
            enabled: { type: 'boolean' },
            serverUrl: { type: ['string', 'null'] },
            off: { type: ['string', 'null'], enum: ['deployment', 'administrator', null] },
            personalKeys: { type: ['object', 'null'], properties: { maxDays: { type: 'integer' } } },
            allowed: { type: ['boolean', 'null'], description: 'Whether your groups may use MCP (allowedGroups); null when MCP is off or it cannot be told' },
          },
        },
        401: problemSchema,
        503: problemSchema,
      },
    },
  }, async (request, reply) => {
    const uc = request.userContext
    if (!uc || uc.email === 'unknown') return reply.status(401).send({ error: 'Unauthorized', code: 'authentication_required', message: 'Sign in first.' })
    reply.header('cache-control', 'private, max-age=5')
    const gate = await mcpGate()
    if (gate.off === 'unavailable') return reply.status(503).send({ error: 'settings_unavailable', message: 'The AI assistant settings cannot be read right now.' })
    if (gate.off === 'deployment') return { enabled: false, serverUrl: null, off: 'deployment', personalKeys: null, allowed: null }
    let allowed: boolean | null = null
    if (gate.on) {
      try {
        allowed = groupAllowed(gate.settings, (await rights(uc.email)).groups)
      } catch {
        allowed = null
      }
    }
    return {
      enabled: gate.on,
      serverUrl: effectiveServerUrl(gate.settings!),
      off: gate.on ? null : 'administrator',
      personalKeys: gate.settings!.personalKeys,
      allowed,
    }
  })
}
