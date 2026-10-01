import { randomBytes } from 'node:crypto'
import { getRedisClient } from '../services/redis-client.service.js'
import { hydraService, HydraApiError, type HydraOAuth2Client } from '../services/hydra.service.js'
import { hydraFlows } from '../services/hydra-flows.service.js'
import { delegatedTokenService } from '../services/delegated-token.service.js'
import { isPersonal } from '../services/api-key.service.js'
import { KEY_STEP_UP_MAX_AGE_MS } from '../middleware/delegated-step-up.js'
import { mcpGate, type McpSettings } from '../mcp/settings.js'
import { componentLogger } from '../telemetry/logger.js'
import { oauthAudit } from './audit.js'
import { mcpSessions } from './connections.js'
import { oauthStepUpUntil } from './step-up-window.js'
import { oauthProofKey } from './step-up-proof.js'
import { FlowError, authOriginOrFail, visitorSession } from './flow.js'

/**
 * "The assistant asks to refresh the second factor" (owner-approved, 2026-10-01).
 *
 * A credential acting for a person (a personal key, or an MCP browser sign-in) whose protected-actions
 * proof is too old asks for a link for ITSELF:
 *
 *   POST /api/me/mcp/step-up-requests            (the delegated caller)   → {url, expiresAt}
 *        a single-use link to login-ui /oauth2/step-up?req=<id>, 10 minutes, bound to the holder and
 *        the calling client
 *   GET  /api/public/oauth2/step-up?req=          (login-ui, the visitor's cookies) → what it refreshes
 *   POST /api/public/oauth2/step-up {req}         (login-ui, cookies + Origin)
 *        the visitor's session must be the holder's, with a second factor proven in the last 2 minutes
 *        (else: where to prove it); then the credential gets a fresh proof —
 *          · a sign-in: a proof time kept in Redis per (person, client), read by token-info, which wins
 *            when newer than the consent stamp; protected actions then last protectedActionsHours from
 *            it, never past the sign-in;
 *          · a personal key: its step_up_at, rewritten.
 *        Only for a credential that was given protected actions (consent tick, key option), and never
 *        while the administrator has protected actions off.
 *
 * Nothing changes until the person completes it; the completion is audited (mcp.step_up.refreshed).
 */

export const STEP_UP_REQUEST_TTL_S = 600
/** The second factor behind a refresh is this recent, at most. */
export const STEP_UP_REFRESH_MAX_AGE_MS = 2 * 60_000
/** Requests a minute window per (person, client) — a stuck assistant must not mint links forever. */
export const STEP_UP_REQUESTS_PER_WINDOW = 5
const REQUEST_WINDOW_S = 600

const reqKey = (id: string) => `jinbe:stepup-req:${id}`

interface StoredRequest { subject: string; clientId: string; kind: 'oauth' | 'personal'; createdAt: string }

export class StepUpRefusal extends Error {
  constructor(public readonly status: 403 | 404 | 409 | 429 | 503, public readonly code: string, message: string, public readonly retryAfter?: number) {
    super(message)
    this.name = 'StepUpRefusal'
  }
}

const NOT_ALLOWED: Record<'oauth' | 'personal', string> = {
  oauth: 'Protected actions were not allowed when this assistant was connected. Reconnect it and tick "Allow protected actions".',
  personal: 'This personal key was created without protected actions. Create a new key that allows them.',
}

/** MCP on and protected actions not switched off by the administrator. */
async function protectedActionsOn(): Promise<McpSettings> {
  const gate = await mcpGate()
  if (gate.off === 'unavailable') throw new StepUpRefusal(503, 'unavailable', 'The AI assistant settings cannot be read right now.')
  if (!gate.on) throw new StepUpRefusal(403, 'mcp_disabled', 'AI assistants are turned off by an administrator.')
  if (gate.settings.oauth.protectedActions === 'off') {
    throw new StepUpRefusal(403, 'protected_actions_off', 'Protected actions through AI assistants are turned off by an administrator.')
  }
  return gate.settings
}

export interface RequestingCredential {
  subject: string
  clientId: string
  kind: 'oauth' | 'personal'
  /** The credential's own protected-actions switch (consent tick or key option). */
  stepUpActions: boolean
}

/** A link for the calling credential. */
export async function createStepUpRequest(c: RequestingCredential, now: number = Date.now()): Promise<{ url: string; expiresAt: string }> {
  const origin = authOriginOrFail()
  await protectedActionsOn()
  if (!c.stepUpActions) throw new StepUpRefusal(409, 'protected_actions_not_allowed', NOT_ALLOWED[c.kind])
  const redis = getRedisClient()
  const id = randomBytes(24).toString('base64url')
  try {
    const budget = `jinbe:stepup-req-count:${c.subject}:${c.clientId}`
    const n = await redis.incr(budget)
    if (n === 1) await redis.expire(budget, REQUEST_WINDOW_S)
    if (n > STEP_UP_REQUESTS_PER_WINDOW) {
      const ttl = await redis.ttl(budget)
      throw new StepUpRefusal(429, 'rate_limited', 'Too many second-factor requests. Use the last link you were given, or try again later.', ttl > 0 ? ttl : REQUEST_WINDOW_S)
    }
    const stored: StoredRequest = { subject: c.subject, clientId: c.clientId, kind: c.kind, createdAt: new Date(now).toISOString() }
    await redis.set(reqKey(id), JSON.stringify(stored), 'EX', STEP_UP_REQUEST_TTL_S)
  } catch (err) {
    if (err instanceof StepUpRefusal) throw err
    componentLogger('oauth').warn({ reason: (err as Error).message }, 'step-up request store unavailable')
    throw new StepUpRefusal(503, 'unavailable', 'Second-factor requests are unavailable right now.')
  }
  return { url: `${origin}/oauth2/step-up?req=${id}`, expiresAt: new Date(now + STEP_UP_REQUEST_TTL_S * 1000).toISOString() }
}

async function readRequest(id: string): Promise<StoredRequest> {
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(id)) throw new StepUpRefusal(404, 'request_unknown', 'This link has expired or was already used. Ask your assistant for a new one.')
  let raw: string | null
  try {
    raw = await getRedisClient().get(reqKey(id))
  } catch {
    throw new StepUpRefusal(503, 'unavailable', 'Second-factor requests are unavailable right now.')
  }
  if (!raw) throw new StepUpRefusal(404, 'request_unknown', 'This link has expired or was already used. Ask your assistant for a new one.')
  return JSON.parse(raw) as StoredRequest
}

/** The credential as it stands now: its name, and whether it may take a fresh proof. */
interface Target { kind: 'oauth' | 'personal'; client: HydraOAuth2Client; clientName: string; endsAt: number }

async function target(r: StoredRequest, now: number): Promise<Target> {
  let client: HydraOAuth2Client
  try {
    client = await hydraService.getClient(r.clientId)
  } catch (err) {
    if (err instanceof HydraApiError && err.statusCode === 404) throw new StepUpRefusal(409, 'credential_gone', 'This assistant is no longer connected.')
    throw new StepUpRefusal(503, 'unavailable', 'Signing in is unavailable right now. Try again later.')
  }
  const meta = (client.metadata ?? {}) as Record<string, unknown>
  const clientName = client.client_name || (r.kind === 'oauth' ? 'MCP client' : 'Personal key')
  if (r.kind === 'personal') {
    const endsAt = typeof meta.expires_at === 'string' ? Date.parse(meta.expires_at) : NaN
    if (!isPersonal(client) || meta.subject !== r.subject || !(endsAt > now)) throw new StepUpRefusal(409, 'credential_gone', 'This personal key no longer exists or has expired.')
    if (meta.step_up_actions === false) throw new StepUpRefusal(409, 'protected_actions_not_allowed', NOT_ALLOWED.personal)
    return { kind: 'personal', client, clientName, endsAt }
  }
  if (meta.kind !== 'mcp_oauth') throw new StepUpRefusal(409, 'credential_gone', 'This assistant is no longer connected.')
  let sessions
  try {
    sessions = mcpSessions(await hydraFlows.listConsentSessions(r.subject))
  } catch {
    throw new StepUpRefusal(503, 'unavailable', 'Signing in is unavailable right now. Try again later.')
  }
  const ext = sessions.find((s) => s.consent_request?.client.client_id === r.clientId)?.session?.access_token ?? null
  const endsAt = ext && typeof ext.grant_expires_at === 'string' ? Date.parse(ext.grant_expires_at) : NaN
  if (!ext || !(endsAt > now)) throw new StepUpRefusal(409, 'credential_gone', 'This assistant is no longer signed in. Reconnect it.')
  if (ext.step_up_actions !== true) throw new StepUpRefusal(409, 'protected_actions_not_allowed', NOT_ALLOWED.oauth)
  return { kind: 'oauth', client, clientName, endsAt }
}

export interface StepUpContext { cookie: string | undefined; ip: string | null; ua: string | null; requestId: string | null; now?: number }

export type StepUpAnswer =
  /** `hours`: how long protected actions last after the new proof (the admin's window for a sign-in, 30 days for a key). */
  | { action: 'show'; kind: 'oauth' | 'personal'; client_id: string; client_name: string; expiresAt: string; hours: number }
  | { action: 'redirect'; to: string }
  | { action: 'done'; kind: 'oauth' | 'personal'; client_id: string; client_name: string; step_up_at: string; step_up_until: string | null }

async function holderSession(r: StoredRequest, cookie: string | undefined) {
  const session = await visitorSession(cookie)
  if (!session) throw new FlowError(401, 'unauthenticated', 'Sign in first.')
  if (session.identityId !== r.subject) throw new FlowError(403, 'wrong_account', 'This link belongs to another account.')
  return session
}

/** What the page shows before the person confirms (consumes nothing). */
export async function describeStepUpRequest(id: string, ctx: StepUpContext): Promise<StepUpAnswer> {
  const now = ctx.now ?? Date.now()
  authOriginOrFail()
  const r = await readRequest(id)
  await holderSession(r, ctx.cookie)
  const settings = await protectedActionsOn()
  const t = await target(r, now)
  const hours = t.kind === 'oauth' ? settings.oauth.protectedActionsHours : KEY_STEP_UP_MAX_AGE_MS / 3600_000
  return { action: 'show', kind: t.kind, client_id: r.clientId, client_name: t.clientName, expiresAt: new Date(Date.parse(r.createdAt) + STEP_UP_REQUEST_TTL_S * 1000).toISOString(), hours }
}

/** The person completes the link: a fresh proof for that credential. */
export async function completeStepUpRequest(id: string, ctx: StepUpContext): Promise<StepUpAnswer> {
  const now = ctx.now ?? Date.now()
  const origin = authOriginOrFail()
  const r = await readRequest(id)
  const session = await holderSession(r, ctx.cookie)
  const settings = await protectedActionsOn()
  const proven = session.aal === 'aal2' && session.secondFactorAt ? session.secondFactorAt.getTime() : NaN
  if (!(now - proven <= STEP_UP_REFRESH_MAX_AGE_MS)) {
    const back = `${origin}/oauth2/step-up?req=${encodeURIComponent(id)}`
    return { action: 'redirect', to: `${origin}/self-service/login/browser?${new URLSearchParams({ aal: 'aal2', refresh: 'true', return_to: back }).toString()}` }
  }
  const t = await target(r, now)

  // Single use: whoever deletes it first completes it.
  let claimed: number
  try {
    claimed = await getRedisClient().del(reqKey(id))
  } catch {
    throw new StepUpRefusal(503, 'unavailable', 'Second-factor requests are unavailable right now.')
  }
  if (claimed !== 1) throw new StepUpRefusal(404, 'request_unknown', 'This link has expired or was already used. Ask your assistant for a new one.')

  const at = new Date(proven).toISOString()
  let until: string | null
  try {
    if (t.kind === 'oauth') {
      const ttl = Math.max(1, Math.ceil((t.endsAt - now) / 1000))
      await getRedisClient().set(oauthProofKey(r.subject, r.clientId), at, 'EX', ttl)
      until = oauthStepUpUntil(settings, { stepUpActions: true, stepUpAt: at, grantExpiresAt: t.endsAt })
    } else {
      const op = 'step_up_at' in (t.client.metadata ?? {}) ? 'replace' : 'add'
      await hydraFlows.patchClient(r.clientId, [{ op, path: '/metadata/step_up_at', value: at }])
      until = new Date(Math.min(proven + KEY_STEP_UP_MAX_AGE_MS, t.endsAt)).toISOString()
    }
  } catch (err) {
    componentLogger('oauth').warn({ reason: (err as Error).message, kind: t.kind }, 'could not record a refreshed second factor')
    throw new StepUpRefusal(503, 'unavailable', 'The second factor could not be recorded. Ask your assistant for a new link.')
  }
  // Cached answers about this credential's tokens go on every replica: the next call sees the proof.
  delegatedTokenService.forgetClient(r.clientId)
  oauthAudit('mcp.step_up.refreshed', {
    actor: { id: session.identityId, email: session.email, ip: ctx.ip, ua: ctx.ua, sessionId: session.sessionId, requestId: ctx.requestId },
    targetId: r.clientId,
    details: { kind: t.kind, client_name: t.clientName, step_up_at: at, step_up_until: until },
  })
  return { action: 'done', kind: t.kind, client_id: r.clientId, client_name: t.clientName, step_up_at: at, step_up_until: until }
}
