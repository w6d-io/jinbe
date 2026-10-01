import type { FastifyReply, FastifyRequest } from 'fastify'
import { enforcing } from '../../policy/declared-routes.js'
import { PERMISSIONS, PLATFORM_PERMISSIONS, grants } from '../../policy/catalog.js'

/**
 * Header-driven stand-ins for the guards the route-access hook attaches, for tests that mount one
 * plugin and drive it over HTTP without OPA:
 *
 *   vi.mock('…/middleware/require-permission.js', async () => (await import('…/helpers/permission-stand-ins.js')).permissionStandIn())
 *   vi.mock('…/middleware/require-admin.js', async () => (await import('…/helpers/permission-stand-ins.js')).adminStandIn())
 *
 * A permission passes when it is a `:read` (the plugins used to be mounted with no read gate in
 * isolation), when `x-test-write` is set and `writeCovers` accepts it, or when `x-test-perms`
 * (comma-separated, exact names; `all` is a test shorthand for every catalogue permission — what
 * super_admin holds) grants it. The step-up passes on `x-test-mfa`.
 */
export interface StandInOptions {
  /** Which permissions `x-test-write` stands for (default: every one). */
  writeCovers?: (permission: string) => boolean
  /** Whether a `:read` passes with no header (default true). */
  readsOpen?: boolean
  /** When set, a `:read` passes on this header instead (e.g. `x-test-admin`). */
  readHeader?: string
}

export function passes(request: FastifyRequest, permission: string, opts: StandInOptions = {}): boolean {
  if (permission.endsWith(':read') && (opts.readHeader ? Boolean(request.headers[opts.readHeader]) : (opts.readsOpen ?? true))) return true
  if (request.headers['x-test-write'] && (opts.writeCovers?.(permission) ?? true)) return true
  return grants(heldBy(request), permission)
}

/** The permissions `x-test-perms` names (`all` = every catalogue permission). */
export function heldBy(request: FastifyRequest): string[] {
  const named = String(request.headers['x-test-perms'] ?? '').split(',').map((s) => s.trim()).filter(Boolean)
  return named.flatMap((p) => (p === 'all' ? PERMISSIONS : [p]))
}

export function permissionStandIn(opts: StandInOptions = {}) {
  const refuse = (reply: FastifyReply, permission: string) =>
    reply.status(403).send({ error: 'Forbidden', message: `This needs ${permission}.` })
  return {
    requirePermission: (permission: string) =>
      enforcing(async (request: FastifyRequest, reply: FastifyReply) => {
        if (!passes(request, permission, opts)) return refuse(reply, permission)
      }, permission),
    demandPermissions: async (request: FastifyRequest, reply: FastifyReply, required: readonly string[]) => {
      const missing = required.find((p) => !passes(request, p, opts))
      if (missing) { refuse(reply, missing); return false }
      return true
    },
    callerRights: async (request: FastifyRequest) => ({
      email: request.userContext?.email ?? 'x@test',
      groups: [],
      roles: [],
      permissions: heldBy(request),
    }),
  }
}

export function adminStandIn(opts: { onStepUp?: (request: FastifyRequest) => void; stepUpOpen?: boolean } = {}) {
  return {
    devRights: () => ({ groups: ['super_admins'], roles: ['super_admin'], permissions: [...PLATFORM_PERMISSIONS] }),
    requireRecentMfa: async (request: FastifyRequest, reply: FastifyReply) => {
      opts.onStepUp?.(request)
      if (!opts.stepUpOpen && !request.headers['x-test-mfa']) return reply.status(422).send({ error: 'reauth_required', message: 'mfa' })
    },
  }
}
