import { hydraFlows, type HydraConsentSession } from '../services/hydra-flows.service.js'
import { HydraApiError, hydraService } from '../services/hydra.service.js'
import { delegatedTokenService } from '../services/delegated-token.service.js'
import { forgetApiKeyUse, lastUsedOf } from '../services/api-key-last-used.js'
import { isGrantableScope } from '../services/authorization-resolution.js'
import { getMcpSettings } from '../mcp/settings.js'
import { componentLogger } from '../telemetry/logger.js'
import { isMcpClient, redirectHost } from './flow.js'
import { oauthStepUpUntil } from './step-up-window.js'
import { laterProof, oauthProofKey, refreshedOAuthProof } from './step-up-proof.js'
import { getRedisClient } from '../services/redis-client.service.js'

/**
 * A person's MCP sign-ins ("Signed-in apps" in kuma Connections): Hydra's consent sessions of
 * `mcp_oauth` clients, and their revocation — one app, or all of them (sign out everywhere).
 *
 * Revoking a consent session revokes every access and refresh token it issued, at Hydra, at once;
 * jinbe's cached answers go on every replica (forgetClient); auth-mcp's positive cache (≤ 30 s) is the
 * worst case. A registration bound to that person goes too: nobody else may use it, and its person
 * has just disconnected it.
 */

export interface McpConnection {
  client_id: string
  client_name: string
  redirect_host: string | null
  granted_at: string | null
  grant_expires_at: string | null
  scope_mode: 'all' | 'chosen'
  scopes: string[]
  step_up_actions: boolean
  step_up_until: string | null
  last_used_at: string | null
}

const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null)

/** The newest consent session per MCP client (a client signed in twice shows once). */
export function mcpSessions(sessions: readonly HydraConsentSession[]): HydraConsentSession[] {
  const byClient = new Map<string, HydraConsentSession>()
  for (const s of sessions) {
    const client = s.consent_request?.client
    if (!client || !isMcpClient(client)) continue
    const prev = byClient.get(client.client_id)
    const at = (x: HydraConsentSession) => Date.parse(str(x.session?.access_token?.granted_at) ?? x.handled_at ?? '') || 0
    if (!prev || at(s) > at(prev)) byClient.set(client.client_id, s)
  }
  return [...byClient.values()]
}

export async function listConnections(subject: string): Promise<McpConnection[]> {
  const sessions = mcpSessions(await hydraFlows.listConsentSessions(subject))
  const settings = await getMcpSettings().catch(() => null)
  const used = await lastUsedOf(sessions.map((s) => s.consent_request!.client.client_id))
  const refreshed = await Promise.all(sessions.map((s) => refreshedOAuthProof(subject, s.consent_request!.client.client_id)))
  return sessions.map((s, i): McpConnection => {
    const client = s.consent_request!.client
    const ext = s.session?.access_token ?? {}
    const mode: McpConnection['scope_mode'] = ext.scope_mode === 'chosen' ? 'chosen' : 'all'
    const stepUpActions = ext.step_up_actions === true
    const grantExpiresAt = str(ext.grant_expires_at)
    const until = settings ? oauthStepUpUntil(settings, { stepUpActions, stepUpAt: laterProof(str(ext.second_factor_at), refreshed[i]), grantExpiresAt }) : null
    return {
      client_id: client.client_id,
      client_name: client.client_name || 'MCP client',
      redirect_host: redirectHost(client),
      granted_at: str(ext.granted_at) ?? str(s.handled_at),
      grant_expires_at: grantExpiresAt,
      scope_mode: mode,
      scopes: mode === 'all' ? [] : (s.grant_scope ?? []).filter(isGrantableScope).sort(),
      step_up_actions: stepUpActions,
      step_up_until: until,
      last_used_at: used.get(client.client_id) ?? null,
    }
  }).sort((a, b) => (b.granted_at ?? '').localeCompare(a.granted_at ?? ''))
}

/**
 * Ends one sign-in of `subject` with `clientId`: the consent and its tokens, jinbe's caches, and the
 * registration when it is bound to that person. False when the person has no MCP sign-in with it.
 */
export async function revokeConnection(subject: string, clientId: string): Promise<boolean> {
  let client
  try {
    client = await hydraService.getClient(clientId)
  } catch (err) {
    if (err instanceof HydraApiError && err.statusCode === 404) return false
    throw err
  }
  if (!isMcpClient(client)) return false
  const hasSession = mcpSessions(await hydraFlows.listConsentSessions(subject)).some((s) => s.consent_request?.client.client_id === clientId)
  const boundToSubject = client.metadata?.bound_subject === subject
  if (!hasSession && !boundToSubject) return false
  await hydraFlows.revokeConsentSessions(subject, clientId)
  // A refreshed step-up proof goes with the sign-in (it would expire with it anyway).
  try { void getRedisClient().del(oauthProofKey(subject, clientId)).catch(() => {}) } catch { /* no Redis: it expires */ }
  delegatedTokenService.forgetClient(clientId)
  if (boundToSubject) {
    await hydraService.deleteClient(clientId).catch((err) => {
      if (!(err instanceof HydraApiError && err.statusCode === 404)) throw err
    })
    forgetApiKeyUse(clientId)
  }
  return true
}

/** Every MCP sign-in of `subject` (sign out everywhere, a second-factor reset); the clients ended. */
export async function revokeAllConnections(subject: string): Promise<string[]> {
  const ids = mcpSessions(await hydraFlows.listConsentSessions(subject)).map((s) => s.consent_request!.client.client_id)
  const done: string[] = []
  for (const id of ids) {
    if (await revokeConnection(subject, id)) done.push(id)
  }
  return done
}

/**
 * The same, for the callers that must not fail on it (revoking a person's sessions must still
 * succeed when Hydra is down): logged, and an empty list.
 */
export async function revokeAllConnectionsQuietly(subject: string): Promise<string[]> {
  try {
    return await revokeAllConnections(subject)
  } catch (err) {
    componentLogger('oauth').warn({ reason: (err as Error).message, subject }, 'could not revoke MCP sign-ins')
    return []
  }
}
