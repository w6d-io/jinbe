import { FastifyInstance } from 'fastify'
import { requireAdmin, requireSuperAdmin } from '../middleware/require-admin.js'
import {
  kratosConfigService,
  KratosConfigError,
  KNOWN_METHODS,
  type AuthMethod,
  type MethodPatch,
} from '../services/kratos-config.service.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { auditEventService } from '../services/audit-event.service.js'
import { auditActor } from '../utils/audit-actor.js'

/**
 * Kratos authentication method toggles.
 *
 * GET /api/admin/auth/methods — current state per method (admin)
 * PUT /api/admin/auth/methods — patch enabled flags (super_admin)
 *
 * Writes patch the mounted kratos.yml; Kratos hot-reloads it, and the login
 * UI renders methods dynamically from the flow — so a toggle is live on the
 * next flow with no restart anywhere. Desired state is mirrored to the
 * rbac:config Redis hash so it survives a config-file redeploy.
 */
export async function authConfigRoutes(fastify: FastifyInstance) {
  const methodStateSchema = {
    type: 'object',
    properties: {
      enabled: { type: 'boolean' },
      configured: { type: 'boolean' },
      passwordlessEnabled: { type: 'boolean' },
    },
  }
  const methodsResponseSchema = {
    type: 'object',
    properties: Object.fromEntries(KNOWN_METHODS.map((m) => [m, methodStateSchema])),
  }

  fastify.get(
    '/methods',
    {
      preHandler: requireAdmin,
      schema: {
        description:
          'Current Kratos self-service auth method state (enabled/configured per method) and the self-registration switch, read from kratos.yml.',
        tags: ['auth-config'],
        response: {
          200: {
            type: 'object',
            properties: {
              methods: methodsResponseSchema,
              registration: { type: 'object', properties: { enabled: { type: 'boolean' } } },
            },
          },
        },
      },
    },
    async (_request, reply) => {
      if (!kratosConfigService.enabled()) return notConfigured(reply)
      try {
        const [methods, registrationEnabled] = await Promise.all([
          kratosConfigService.getMethods(),
          kratosConfigService.getRegistrationEnabled(),
        ])
        return { methods, registration: { enabled: registrationEnabled } }
      } catch (err) {
        return sendConfigError(reply, err)
      }
    }
  )

  fastify.put(
    '/methods',
    {
      preHandler: requireSuperAdmin,
      schema: {
        description:
          'Toggle Kratos self-service auth methods and self-registration. Partial patch; Kratos hot-reloads (no restart). ' +
          'webauthn/passkey/oidc can only be enabled when their config block already exists in kratos.yml. ' +
          'registration.enabled=false makes account creation admin-only (kuma Users → create + invite).',
        tags: ['auth-config'],
        body: {
          type: 'object',
          additionalProperties: false,
          properties: {
            ...Object.fromEntries(
              KNOWN_METHODS.map((m) => [
                m,
                {
                  type: 'object',
                  additionalProperties: false,
                  properties: {
                    enabled: { type: 'boolean' },
                    passwordlessEnabled: { type: 'boolean' },
                  },
                },
              ])
            ),
            registration: {
              type: 'object',
              additionalProperties: false,
              properties: { enabled: { type: 'boolean' } },
            },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              methods: methodsResponseSchema,
              registration: { type: 'object', properties: { enabled: { type: 'boolean' } } },
            },
          },
        },
      },
    },
    async (request, reply) => {
      if (!kratosConfigService.enabled()) return notConfigured(reply)
      const { registration, ...methodPatch } = (request.body ?? {}) as Partial<Record<AuthMethod, MethodPatch>> & {
        registration?: { enabled?: boolean }
      }
      if (Object.keys(methodPatch).length === 0 && typeof registration?.enabled !== 'boolean') {
        return reply.status(400).send({ error: 'Bad Request', message: 'Empty patch — provide at least one method or registration.' })
      }
      try {
        const methods = Object.keys(methodPatch).length > 0
          ? await kratosConfigService.setMethods(methodPatch)
          : await kratosConfigService.getMethods()
        const registrationEnabled = typeof registration?.enabled === 'boolean'
          ? await kratosConfigService.setRegistrationEnabled(registration.enabled)
          : await kratosConfigService.getRegistrationEnabled()
        // Mirror desired state so a redeployed kratos.yml can be re-patched.
        await redisRbacRepository
          .setConfig('auth_methods', JSON.stringify({ methods, registration: { enabled: registrationEnabled } }))
          .catch(() => {})
        // Auth-surface change: high-severity audit, same shape as bundle ops.
        const a = auditActor(request)
        auditEventService.emit({
          category: 'rbac', kind: 'change', verb: 'update', target: 'auth-methods',
          result: 'applied', severity: 'high',
          actor: { email: a.email ?? null, ip: a.ip, name: a.name, ua: a.ua, sessionId: a.sessionId },
          requestId: a.requestId,
          details: { patch: request.body as Record<string, unknown> },
        }).catch(() => {})
        return { methods, registration: { enabled: registrationEnabled } }
      } catch (err) {
        return sendConfigError(reply, err)
      }
    }
  )
}

function notConfigured(reply: import('fastify').FastifyReply) {
  return reply.status(501).send({
    error: 'Not Implemented',
    code: 'kratos_config_disabled',
    message: 'KRATOS_CONFIG_PATH is not configured — auth method management is unavailable on this deployment.',
  })
}

function sendConfigError(reply: import('fastify').FastifyReply, err: unknown) {
  if (err instanceof KratosConfigError) {
    return reply.status(err.statusCode).send({ error: err.name, message: err.message })
  }
  throw err
}
