import type { FastifyReply, FastifyRequest } from 'fastify'
import { isCatalogPermission, setGrantsModel } from '../policy/catalog.js'
import { platformNameOf } from './catalogue.js'

/**
 * The model adapter (authz-v2-design §3.2): which authorization model jinbe's own code follows, v1
 * (today's) or v2. Both exist side by side until the cleanup wave; the switch is ONE Redis key,
 * `rbac:authz_active`, which OPAL also publishes as data.authz.active so the gateway's router and
 * this process flip together.
 *
 * Read on boot and every few seconds after (startActiveModelWatch). Unknown, absent or unreadable
 * means "keep what we have", starting from v1: a Redis blip must never flip the model.
 *
 * What follows the switch here:
 *   - `catalog.grants` (every guard's "does the caller hold P"): v2 is the exact name, read on a
 *     platform route, never `*`, never an alias (installV2Grants below);
 *   - routes declared `model: 'v1'` (retired by v2) or `model: 'v2'` (new in v2) answer 404 outside
 *     their model (onlyInModel);
 *   - the org gates and the grant service (middleware/platform-holder.ts, rbac-escalation-guard.ts,
 *     require-manageable-org.ts) ask `isV2()`.
 */

export type AuthzModel = 'v1' | 'v2'

export const AUTHZ_ACTIVE_KEY = 'rbac:authz_active'

let active: AuthzModel = 'v1'

export function activeModel(): AuthzModel {
  return active
}

export function isV2(): boolean {
  return active === 'v2'
}

/**
 * v2's grants for a requirement written with a v1 name (routes keep their v1 declarations until the
 * cleanup): its platform name, held exactly. An org permission has no platform reading, so it is
 * never held this way — an org route is decided by the org clause alone. A site's own permission
 * (outside the catalogue) is matched as written.
 */
export function v2Grants(held: readonly string[], required: string): boolean {
  const name = isCatalogPermission(required) ? platformNameOf(required) : required
  return name !== null && name !== '*' && held.includes(name)
}

/** Sets the model and what follows it in-process. Test seam too. */
export function setActiveModel(model: AuthzModel): void {
  active = model
  setGrantsModel(model === 'v2' ? v2Grants : null)
}

export function parseModel(raw: string | null | undefined): AuthzModel | null {
  return raw === 'v1' || raw === 'v2' ? raw : null
}

/** Reads the switch once; keeps the current model when the value is absent, unknown or unreadable. */
export async function refreshActiveModel(read: () => Promise<string | null>): Promise<AuthzModel> {
  try {
    const next = parseModel(await read())
    if (next && next !== active) setActiveModel(next)
  } catch {
    /* keep the current model */
  }
  return active
}

let watch: ReturnType<typeof setInterval> | null = null

export function startActiveModelWatch(read: () => Promise<string | null>, everyMs = 5_000): void {
  if (watch) return
  void refreshActiveModel(read)
  watch = setInterval(() => void refreshActiveModel(read), everyMs)
  watch.unref?.()
}

export function stopActiveModelWatch(): void {
  if (watch) clearInterval(watch)
  watch = null
}

/** The preHandler of a route that exists in one model only: 404 in the other. */
export function onlyInModel(model: AuthzModel) {
  return async function onlyInModel(_request: FastifyRequest, reply: FastifyReply) {
    if (active === model) return
    return reply.status(404).send({
      error: 'Not Found',
      code: model === 'v1' ? 'route_retired' : 'route_not_active',
      message: model === 'v1'
        ? 'This route belongs to the previous authorization model and is retired.'
        : 'This route belongs to the next authorization model, which is not active yet.',
    })
  }
}
