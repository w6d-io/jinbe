import type { AccessDecisions } from '../types.js'
import { CONNECT, src, unavailable, type ModuleDef } from './common.js'

/**
 * Gateway decisions by site (home-data §3.5 access). Not deployed until the policy proxy writes its
 * decision line (OBS-1.4): per-site allow/deny cannot be read from any source today — Oathkeeper's
 * lines carry no host or site. Shipped as `not_deployed` so the Home says so instead of hiding it.
 *
 * TODO(HOME-later): the degraded totals-only view from Oathkeeper's `granted` field
 * (`source:'oathkeeper-log'`), then the full view once decision lines reach Loki.
 */
export const accessModule: ModuleDef<AccessDecisions> = {
  name: 'access',
  tier: 'inline',
  freshMs: 60_000,
  timeoutMs: 150,
  windowed: true,
  async compute() {
    return unavailable('not_deployed', { decisions: src('not_deployed', CONNECT.decisions) }, CONNECT.decisions)
  },
}
