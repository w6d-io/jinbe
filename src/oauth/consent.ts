import { env } from '../config/index.js'
import { hydraFlows, type HydraConsentRequest } from '../services/hydra-flows.service.js'
import { HydraApiError, hydraService } from '../services/hydra.service.js'
import { platformScopes, scopeGroup } from '../services/platform-scopes.js'
import { isGrantableScope } from '../services/authorization-resolution.js'
import { secondFactorIsFresh } from '../services/step-up.js'
import type { ValidatedSession } from '../services/kratos-session.service.js'
import { specOf } from '../policy/catalog.js'
import { KEY_STEP_UP_PERMISSIONS } from '../middleware/delegated-step-up.js'
import type { McpSettings } from '../mcp/settings.js'
import { oauthGate } from './issuer.js'
import { oauthAudit } from './audit.js'
import { MCP_SCOPE, OFFLINE_SCOPE } from './metadata.js'
import {
  FlowError, REFUSAL_DESCRIPTION, REFUSAL_OAUTH_ERROR, authOriginOrFail, gateRefusal, hydraFailure, isMcpClient,
  redirectHost, requestProblem, visitorSession, type FlowAnswer, type RefusalReason,
} from './flow.js'

/**
 * The Hydra consent provider for MCP clients — what login-ui's /oauth2/consent shows and posts.
 *
 *   GET  /api/public/oauth2/consent?consent_challenge=   the screen: the (unverified) client, the
 *        account, the permissions asked that the person holds, whether protected actions are offered
 *   POST /api/public/oauth2/consent                      allow (all my permissions | a chosen subset,
 *        protected actions or not) or deny
 *
 * Both re-check everything the login checked (the challenge is the visitor's, MCP and browser sign-in
 * on, their groups, the resource) — the challenge could be replayed later, or by someone else. Scopes
 * are re-intersected here: what the client asked, what the person holds now and what they ticked; a
 * forged scope in /oauth2/auth is dropped. The first consent binds a registration to its person.
 *
 * The grant stamps into the token (`session.access_token`, introspection `ext`) what jinbe reads on
 * every call (delegated-token.service.ts): kind 'oauth', the scope mode, the consent-time second
 * factor and whether protected actions were allowed, and the sign-in's absolute end (≤ 30 days).
 */

export interface ConsentCatalogEntry {
  scope: string
  group: string
  label: string
  sensitivity: string
  protected: boolean
}

export interface ConsentScreen {
  action: 'show'
  client: { client_id: string; name: string; name_verified: false; redirect_host: string | null; registered_at: string | null }
  account: { email: string; subject: string }
  requested: string[]
  offline_access: boolean
  catalog: ConsentCatalogEntry[]
  protectedActions: { offered: boolean; until: string | null; permissions: string[] }
  grantExpiresAt: string
}

export interface ConsentDecision {
  consent_challenge: string
  decision: 'allow' | 'deny'
  mode?: 'all' | 'chosen'
  scopes?: string[]
  protected_actions?: boolean
}

export interface ConsentContext {
  cookie: string | undefined
  ip: string | null
  ua: string | null
  requestId: string | null
  now?: number
}

type Inspected =
  | { refused: RefusalReason; req: HydraConsentRequest; session: ValidatedSession }
  | { refused?: undefined; req: HydraConsentRequest; session: ValidatedSession; settings: McpSettings; screen: Omit<ConsentScreen, 'action'> }

const HOUR = 3600_000
const DAY = 24 * HOUR

async function inspect(challenge: string, ctx: ConsentContext): Promise<Inspected> {
  authOriginOrFail()
  const now = ctx.now ?? Date.now()
  const session = await visitorSession(ctx.cookie)
  if (!session) throw new FlowError(401, 'unauthenticated', 'Sign in first.')
  let req: HydraConsentRequest
  try {
    req = await hydraFlows.getConsentRequest(challenge)
  } catch (err) {
    hydraFailure(err)
  }
  // Not yours: never shown, never accepted — whatever the requester holds.
  if (req.subject !== session.identityId) throw new FlowError(403, 'wrong_account', 'This sign-in request belongs to another account.')
  if (!isMcpClient(req.client)) return { refused: 'not_mcp_client', req, session }
  const problem = requestProblem(req.request_url, env.DELEGATED_TOKEN_AUDIENCE, { pkce: false })
  if (problem) return { refused: problem, req, session }
  const gate = await oauthGate()
  const off = await gateRefusal(gate, session.email)
  if (off || !gate.on) return { refused: off ?? 'oauth_disabled', req, session }
  const bound = req.client.metadata?.bound_subject
  if (typeof bound === 'string' && bound && bound !== session.identityId) return { refused: 'client_bound_elsewhere', req, session }

  let held: Set<string>
  try {
    held = new Set(await platformScopes(session.email))
  } catch (err) {
    hydraFailure(err)
  }
  const asked = [...new Set((req.requested_scope ?? []).filter((s) => isGrantableScope(s) && s !== MCP_SCOPE && s !== OFFLINE_SCOPE))]
  const catalog = asked.filter((s) => held.has(s)).sort().map((scope): ConsentCatalogEntry => {
    const spec = specOf(scope)
    return { scope, group: scopeGroup(scope), label: spec?.label ?? scope, sensitivity: spec?.sensitivity ?? 'medium', protected: KEY_STEP_UP_PERMISSIONS.has(scope) }
  })
  const o = gate.settings.oauth
  const grantExpiresAt = now + o.maxDays * DAY
  const protectedPermissions = catalog.filter((c) => c.protected).map((c) => c.scope)
  const offered = o.protectedActions === 'window'
    && protectedPermissions.length > 0
    && secondFactorIsFresh({ aal: session.aal, secondFactorAt: session.secondFactorAt, authVia: 'session' }, now)
  const until = offered ? Math.min(session.secondFactorAt!.getTime() + o.protectedActionsHours * HOUR, grantExpiresAt) : null
  const registered = req.client.metadata?.registered_at

  return {
    req,
    session,
    settings: gate.settings,
    screen: {
      client: {
        client_id: req.client.client_id,
        name: req.client.client_name || 'MCP client',
        name_verified: false,
        redirect_host: redirectHost(req.client),
        registered_at: typeof registered === 'string' ? registered : null,
      },
      account: { email: session.email, subject: session.identityId },
      requested: asked.sort(),
      offline_access: (req.requested_scope ?? []).includes(OFFLINE_SCOPE),
      catalog,
      protectedActions: { offered, until: until === null ? null : new Date(until).toISOString(), permissions: offered ? protectedPermissions : [] },
      grantExpiresAt: new Date(grantExpiresAt).toISOString(),
    },
  }
}

async function refuse(challenge: string, i: { req: HydraConsentRequest; session: ValidatedSession }, reason: RefusalReason, ctx: ConsentContext): Promise<FlowAnswer> {
  oauthAudit('mcp.oauth.login_refused', {
    actor: { id: i.session.identityId, email: i.session.email, ip: ctx.ip, ua: ctx.ua, requestId: ctx.requestId },
    targetId: i.req.client?.client_id ?? 'unknown',
    result: 'denied',
    reason,
    details: { reason, stage: 'consent', client_name: i.req.client?.client_name ?? null },
  })
  try {
    const to = (await hydraFlows.rejectConsent(challenge, { error: REFUSAL_OAUTH_ERROR[reason], error_description: REFUSAL_DESCRIPTION[reason] })).redirect_to
    return { action: 'refused', reason, to }
  } catch (err) {
    hydraFailure(err)
  }
}

export async function consentScreen(challenge: string, ctx: ConsentContext): Promise<ConsentScreen | FlowAnswer> {
  const i = await inspect(challenge, ctx)
  if (i.refused) return refuse(challenge, i, i.refused, ctx)
  return { action: 'show', ...i.screen }
}

/**
 * Binds a registration to the person consenting, once: a JSON Patch `test` makes two first consents
 * race safely. False when somebody else holds it.
 */
async function bindClient(clientId: string, metadata: Record<string, unknown> | undefined, subject: string): Promise<boolean> {
  if (metadata?.bound_subject === subject) return true
  const patch = metadata && 'bound_subject' in metadata
    ? [{ op: 'test', path: '/metadata/bound_subject', value: null }, { op: 'replace', path: '/metadata/bound_subject', value: subject }]
    : [{ op: 'add', path: '/metadata/bound_subject', value: subject }]
  try {
    await hydraFlows.patchClient(clientId, patch)
    return true
  } catch (err) {
    if (!(err instanceof HydraApiError) || ![400, 409, 422].includes(err.statusCode)) hydraFailure(err)
    const now = (await hydraService.getClient(clientId).catch(hydraFailure)).metadata?.bound_subject
    return now === subject
  }
}

export async function decideConsent(d: ConsentDecision, ctx: ConsentContext): Promise<FlowAnswer> {
  const now = ctx.now ?? Date.now()
  const i = await inspect(d.consent_challenge, ctx)
  if (i.refused) return refuse(d.consent_challenge, i, i.refused, ctx)
  const { req, session, screen } = i
  const actor = { id: session.identityId, email: session.email, ip: ctx.ip, ua: ctx.ua, requestId: ctx.requestId }

  if (d.decision === 'deny') {
    oauthAudit('mcp.oauth.consent_denied', { actor, targetId: req.client.client_id, result: 'denied', details: { client_name: screen.client.name } })
    try {
      return { action: 'redirect', to: (await hydraFlows.rejectConsent(d.consent_challenge, { error: 'access_denied', error_description: 'The user denied access.' })).redirect_to }
    } catch (err) {
      hydraFailure(err)
    }
  }

  const offerable = new Set(screen.catalog.map((c) => c.scope))
  const mode = d.mode ?? 'all'
  const permissions = mode === 'all' ? [...offerable] : [...new Set(d.scopes ?? [])].filter((s) => offerable.has(s))
  if (mode === 'chosen' && permissions.length === 0) throw new FlowError(400, 'no_scopes', 'Choose at least one permission you hold.')
  const stepUp = d.protected_actions === true
  if (stepUp && !screen.protectedActions.offered) {
    throw new FlowError(400, 'protected_actions_unavailable', 'Protected actions cannot be allowed for this sign-in. Sign in again with a fresh second factor.')
  }

  if (!(await bindClient(req.client.client_id, req.client.metadata, session.identityId))) {
    return refuse(d.consent_challenge, i, 'client_bound_elsewhere', ctx)
  }

  const grantScope = [MCP_SCOPE, ...(screen.offline_access ? [OFFLINE_SCOPE] : []), ...permissions.sort()]
  let to: string
  try {
    to = (await hydraFlows.acceptConsent(d.consent_challenge, {
      grant_scope: grantScope,
      grant_access_token_audience: [env.DELEGATED_TOKEN_AUDIENCE],
      remember: false,
      session: {
        access_token: {
          kind: 'oauth',
          scope_mode: mode,
          second_factor_at: session.secondFactorAt?.toISOString() ?? null,
          step_up_actions: stepUp,
          granted_at: new Date(now).toISOString(),
          grant_expires_at: screen.grantExpiresAt,
        },
        id_token: {},
      },
    })).redirect_to
  } catch (err) {
    hydraFailure(err)
  }
  oauthAudit('mcp.oauth.consent_granted', {
    actor,
    targetId: req.client.client_id,
    details: { client_name: screen.client.name, scope_mode: mode, scopes: mode === 'all' ? null : permissions.length, step_up_actions: stepUp, grant_expires_at: screen.grantExpiresAt },
  })
  return { action: 'redirect', to }
}
