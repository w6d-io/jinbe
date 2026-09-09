// routes/whoami.routes.ts
import { FastifyInstance, FastifyRequest } from 'fastify'
import { rbacResolverService } from '../services/rbac-resolver.service.js'
import { kratosService } from '../services/kratos.service.js'
import { env } from '../config/env.js'

/**
 * GET /whoami
 * Returns the email and RBAC info (groups, roles, permissions) of the current user.
 *
 * Flow:
 * 1. Extract email from validated Kratos session (ory_kratos_session cookie)
 *    or fallback to proxy headers (via identity-extractor middleware)
 * 2. Resolve RBAC directly from Kratos (groups) + Git (roles/permissions)
 * 3. Return combined identity + RBAC information
 *
 * Note: This is a public endpoint - no authentication required.
 * If no valid session, returns null email with empty RBAC arrays.
 */
export async function whoamiRoutes(fastify: FastifyInstance) {
  fastify.get(
    '/whoami',
    {
      schema: {
        description:
          'Return the current user identity (from Kratos session) and RBAC info (groups, roles, permissions) from OPAL',
        tags: ['auth'],
        response: {
          200: {
            type: 'object',
            properties: {
              authenticated: { type: 'boolean' },
              email: { type: ['string', 'null'] },
              name: { type: ['string', 'null'], description: 'User display name' },
              picture: { type: ['string', 'null'], description: 'User avatar URL' },
              identity_id: { type: ['string', 'null'] },
              session_id: { type: ['string', 'null'] },
              error: { type: ['string', 'null'] },
              groups: { type: 'array', items: { type: 'string' } },
              roles: { type: 'array', items: { type: 'string' } },
              permissions: { type: 'array', items: { type: 'string' } },
              // Where the rules are enforced from. Answered here rather than configured again in
              // the console: the deployment states it once, and two places that can disagree about
              // whether an editor works is one place too many.
              rules_source: { type: 'string', enum: ['service', 'gitops'] },
            },
          },
        },
      },
    },
    async (request: FastifyRequest, reply) => {
      const validatedSession = request.validatedSession
      const userContext = request.userContext

      // Determine if user is authenticated
      const authenticated = !!(
        validatedSession ||
        (userContext && userContext.email !== 'unknown')
      )

      // Get email from validated session first, then userContext, then headers
      const email =
        validatedSession?.email ||
        (userContext?.email !== 'unknown' ? userContext?.email : null) ||
        null

      // Get identity/session IDs if available
      const identityId = validatedSession?.identityId || userContext?.id || null
      const sessionId = validatedSession?.sessionId || userContext?.sessionId || null

      // Get name and picture from validated session
      const name = validatedSession?.name || userContext?.name || null
      const picture = validatedSession?.picture || null

      // Default empty RBAC info
      let groups: string[] = []
      let roles: string[] = []
      let permissions: string[] = []

      // DEV MODE: Return admin RBAC info matching requireAdmin bypass
      if (env.DEV_BYPASS_AUTH && env.NODE_ENV === 'development') {
        groups = ['super_admins', 'admins']
        roles = ['super_admin', 'admin']
        permissions = ['*']
      } else if (email) {
        // Resolve RBAC directly from Kratos + Git
        try {
          const rbacInfo = await rbacResolverService.resolveUserRbac(email, env.APP_NAME)
          groups = rbacInfo.groups
          roles = rbacInfo.roles
          permissions = rbacInfo.permissions
        } catch (error) {
          // Log error but don't fail the request
          request.log.error({ error, email }, 'Failed to resolve RBAC info')
        }
      }

      // WS6: best-effort session extension. Keep active users logged in by
      // pushing the Kratos session expiry out on each whoami. Fire-and-forget —
      // Kratos throttles via session.earliest_possible_extend, and a failed
      // extend must NEVER break whoami, so we do not await and swallow errors.
      if (validatedSession?.sessionId) {
        kratosService
          .extendSession(validatedSession.sessionId)
          .catch((err) =>
            request.log.warn(
              { err, sessionId: validatedSession.sessionId },
              'session extend failed'
            )
          )
      }

      return reply.send({
        authenticated,
        email,
        name,
        picture,
        identity_id: identityId,
        session_id: sessionId,
        error: request.sessionError || null,
        groups,
        roles,
        permissions,
        rules_source: env.RULES_SOURCE,
      })
    }
  )
}
