import type { FastifyRequest } from 'fastify'
import { rights } from '../../authz/opa.js'
import { allows } from '../../services/user-permissions.js'
import { kratosService } from '../../services/kratos.service.js'

/**
 * Who the user actors of an audit page are, for the screen: `{ <identity id>: { email, name } }`,
 * null for an identity that no longer exists.
 *
 * Resolved when read, never stored: the events keep only the pseudonymous id (no PII in the trail),
 * and a deleted account falls back to that id. Only for a caller who could look each person up
 * anyway (`users:read`, what GET /admin/users/:id asks): an org admin reading their org's events is
 * not shown the address of a platform admin who acted in it. One Kratos call per 100 ids, through the
 * shared identity cache. Anything that cannot be read leaves the directory out; the page still works.
 */

const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
/** More distinct actors than a page shows; a bound, not a target. */
const MAX_IDS = 250

export type ActorDirectory = Record<string, { email: string | null; name: string | null } | null>

type WithActor = { actor?: { type?: string; id?: string | null } | null }

/** The distinct user identity ids among these events, then these extra ids (a facet's values). */
export function userActorIds(events: readonly WithActor[], extra: readonly string[] = []): string[] {
  const ids = new Set<string>()
  for (const e of events) if (e.actor?.type === 'user' && e.actor.id && ID.test(e.actor.id)) ids.add(e.actor.id.toLowerCase())
  for (const id of extra) if (ID.test(id)) ids.add(id.toLowerCase())
  return [...ids].slice(0, MAX_IDS)
}

function nameOf(traits: Record<string, unknown> | undefined): string | null {
  const n = traits?.name
  if (typeof n === 'string') return n || null
  if (n && typeof n === 'object') {
    const { first, last } = n as { first?: unknown; last?: unknown }
    const full = [first, last].filter((x): x is string => typeof x === 'string' && !!x).join(' ')
    return full || null
  }
  return null
}

/** The directory for these ids, or undefined when the caller may not see it or it cannot be read. */
export async function actorDirectory(request: FastifyRequest, ids: readonly string[]): Promise<ActorDirectory | undefined> {
  if (ids.length === 0) return undefined
  const email = request.userContext?.email
  if (!email || email === 'unknown') return undefined
  try {
    const held = request.rbacInfo?.email === email ? request.rbacInfo : { email, ...(await rights(email)) }
    if (!allows(held.permissions, 'users:read')) return undefined
    const found = await kratosService.getIdentitiesByIds(ids)
    const out: ActorDirectory = {}
    for (const id of ids) {
      const identity = found.get(id)
      const traits = identity?.traits as Record<string, unknown> | undefined
      out[id] = identity ? { email: typeof traits?.email === 'string' ? traits.email : null, name: nameOf(traits) } : null
    }
    return out
  } catch (err) {
    request.log.warn({ err: (err as Error).message }, '[audit] actor names could not be read; ids shown instead')
    return undefined
  }
}
