import * as sources from '../sources.js'
import { holds } from '../../authz/opa.js'
import { allows } from '../../services/user-permissions.js'
import type { QuickActionId, QuickActions } from '../types.js'
import { ok, probe, src, type ModuleDef } from './common.js'

/**
 * Which quick actions to offer (home-data §3.5 actions): the same permission each action's own route
 * checks, read off the caller's OPA-resolved permissions. A hint for what to draw — the route still
 * decides. Per caller, never cached.
 */

type Item = QuickActions['items'][number]

export const actionsModule: ModuleDef<QuickActions> = {
  name: 'actions',
  tier: 'direct',
  freshMs: 0,
  timeoutMs: 200,
  async compute(ctx) {
    const { scope } = ctx
    const p = scope.permissions
    const orgAdmin = scope.orgs.length > 0
    const kubeOff = sources.kubeMode() === 'off'
    const gate = (id: QuickActionId, allowed: boolean, extra: Partial<Item> = {}): Item =>
      allowed ? { id, enabled: true, ...extra } : { id, enabled: false, reason: 'no_permission' }

    let review: Item = gate('review_requests', scope.canApply)
    let srcs = {}
    if (scope.canApply) {
      const pending = await probe(() => sources.pendingRequests(), 150)
      srcs = { sites: src(pending.ok ? 'ok' : pending.state) }
      // Four-eyes: your own requests are not yours to decide.
      const count = pending.ok ? pending.value.filter((r) => r.requestedBy.toLowerCase() !== scope.email.toLowerCase()).length : 0
      review = count === 0
        ? { id: 'review_requests', enabled: false, reason: 'nothing_to_do', count: 0 }
        : scope.stepUpFresh
          ? { id: 'review_requests', enabled: true, count }
          : { id: 'review_requests', enabled: true, reason: 'mfa_required', count }
    }

    const items: Item[] = [
      review,
      gate('new_site', holds(p, 'admin:write')),
      gate('invite_user', allows(p, 'users:create') || orgAdmin),
      gate('grant_access', holds(p, 'admin:write') || orgAdmin),
      gate('check_access', holds(p, 'admin:read')),
      gate('find_user', allows(p, 'users:read')),
      gate('open_audit', scope.platform || holds(p, 'audit:read') || orgAdmin),
      gate('start_recert', holds(p, 'admin:read')),
      gate('org_api_key', orgAdmin),
      gate('revoke_sessions', allows(p, 'sessions:revoke')),
      gate('send_recovery', allows(p, 'users:recovery')),
      holds(p, 'admin:read') && kubeOff ? { id: 'open_gateway', enabled: false, reason: 'not_deployed' } : gate('open_gateway', holds(p, 'admin:read')),
    ]
    return ok({ items }, srcs)
  },
}
