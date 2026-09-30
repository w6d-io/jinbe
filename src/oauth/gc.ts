import type { FastifyBaseLogger } from 'fastify'
import { Gauge } from 'prom-client'
import { getRedisClient } from '../services/redis-client.service.js'
import { hydraService, HydraApiError, type HydraOAuth2Client } from '../services/hydra.service.js'
import { hydraFlows, type HydraConsentSession } from '../services/hydra-flows.service.js'
import { forgetApiKeyUse } from '../services/api-key-last-used.js'
import { delegatedTokenService } from '../services/delegated-token.service.js'
import { oauthIssuer } from './issuer.js'
import { oauthAudit } from './audit.js'
import { DCR_OWNER, MCP_CLIENT_KIND } from './register.js'
import { mcpSessions } from './connections.js'

/**
 * Garbage collection of MCP client registrations (leader only, every 10 minutes):
 *   - unconsented and older than 1 h: nothing can still be in flight (Hydra's login/consent request
 *     lives 15–30 min), so it goes;
 *   - bound to a person who has no sign-in with it any more (disconnected, revoked, expired): it goes;
 *   - a sign-in past its absolute end (`grant_expires_at`): revoked (tokens with it), then the client.
 * Counts are exported as jinbe_mcp_oauth_clients{state}.
 */

export const mcpOAuthClients = new Gauge({
  name: 'jinbe_mcp_oauth_clients',
  help: 'MCP OAuth client registrations by state (unconsented, bound) after the last sweep, and deleted by it',
  labelNames: ['state'] as const,
})

const HOUR = 3600_000
const TICK_MS = 10 * 60_000
const LEADER_KEY = 'jinbe:oauth-gc:leader'

export interface SweepResult { unconsented: number; bound: number; deleted: number; expired: number }

const ageOf = (c: HydraOAuth2Client, now: number) => now - (Date.parse(String(c.metadata?.registered_at ?? c.created_at ?? '')) || now)

async function remove(clientId: string): Promise<boolean> {
  try {
    await hydraService.deleteClient(clientId)
  } catch (err) {
    if (!(err instanceof HydraApiError && err.statusCode === 404)) throw err
  }
  forgetApiKeyUse(clientId)
  delegatedTokenService.forgetClient(clientId)
  return true
}

export async function sweepMcpClients(now: number = Date.now()): Promise<SweepResult> {
  const clients = (await hydraService.listAllClients(500, 10, DCR_OWNER)).filter((c) => c.metadata?.kind === MCP_CLIENT_KIND)
  const sessionsOf = new Map<string, HydraConsentSession[]>()
  const out: SweepResult = { unconsented: 0, bound: 0, deleted: 0, expired: 0 }

  for (const c of clients) {
    const subject = typeof c.metadata?.bound_subject === 'string' ? c.metadata.bound_subject : ''
    if (!subject) {
      if (ageOf(c, now) > HOUR) out.deleted += Number(await remove(c.client_id))
      else out.unconsented++
      continue
    }
    if (!sessionsOf.has(subject)) sessionsOf.set(subject, mcpSessions(await hydraFlows.listConsentSessions(subject)))
    const session = sessionsOf.get(subject)!.find((s) => s.consent_request?.client.client_id === c.client_id)
    if (!session) {
      // Consent is written a moment after binding: leave a just-bound client alone.
      if (ageOf(c, now) > HOUR) out.deleted += Number(await remove(c.client_id))
      else out.bound++
      continue
    }
    const end = Date.parse(String(session.session?.access_token?.grant_expires_at ?? ''))
    if (!(end > now)) {
      await hydraFlows.revokeConsentSessions(subject, c.client_id)
      await remove(c.client_id)
      oauthAudit('mcp.oauth.grant_expired', { actor: { id: subject, email: null, type: 'system' }, targetId: c.client_id, details: { client_name: c.client_name ?? null, via: 'sweep' } })
      out.expired++
      out.deleted++
      continue
    }
    out.bound++
  }
  mcpOAuthClients.set({ state: 'unconsented' }, out.unconsented)
  mcpOAuthClients.set({ state: 'bound' }, out.bound)
  mcpOAuthClients.set({ state: 'deleted_last_sweep' }, out.deleted)
  return out
}

let timer: NodeJS.Timeout | null = null

async function tick(log: FastifyBaseLogger): Promise<void> {
  if (!oauthIssuer()) return
  const leader = await getRedisClient().set(LEADER_KEY, process.pid.toString(), 'PX', TICK_MS - 30_000, 'NX').catch(() => null)
  if (leader !== 'OK') return
  const r = await sweepMcpClients()
  if (r.deleted > 0) log.info(r, '[oauth] swept MCP client registrations')
}

/** Started once the bootstrap marker is seen. Unref'd: it never holds the process open. */
export function startOAuthBackground(log: FastifyBaseLogger): void {
  if (timer) return
  const run = () => void tick(log).catch((err) => log.warn({ err: (err as Error).message }, '[oauth] client sweep failed'))
  setTimeout(run, 60_000).unref()
  timer = setInterval(run, TICK_MS)
  timer.unref()
}
