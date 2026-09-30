import { env } from '../config/index.js'
import { hydraFlows, type HydraLoginRequest } from '../services/hydra-flows.service.js'
import { kratosService } from '../services/kratos.service.js'
import { secondFactorIsFresh } from '../services/step-up.js'
import { oauthGate } from './issuer.js'
import { oauthAudit } from './audit.js'
import {
  FlowError, REFUSAL_DESCRIPTION, REFUSAL_OAUTH_ERROR, authOriginOrFail, gateRefusal, hydraFailure, isMcpClient,
  requestProblem, visitorSession, type FlowAnswer, type RefusalReason,
} from './flow.js'

/**
 * The Hydra login provider for MCP clients — `GET /api/public/oauth2/login?login_challenge=`, asked
 * server-side by login-ui (/oauth2/login) with the visitor's Kratos cookies. Answers where to send
 * the browser next:
 *
 *   an MCP client only, PKCE S256, no foreign `resource`       else refused (Hydra reject)
 *   MCP on, browser sign-in on                                 else refused
 *   a Kratos session                                           else Kratos login, back here
 *   the person's groups may use MCP                            else refused
 *   aal2 with a second factor proven in the last 15 minutes    else enrolment / aal2 / aal2 refresh
 *   → Hydra login accept: subject = identity, remember: false (Kratos is the SSO, and Hydra's session
 *     must not outlive it), acr aal2, amr = the session's methods, the proof time in the context.
 *
 * Every refusal is audited (`mcp.oauth.login_refused`) and rejected at Hydra, whose redirect goes back
 * to the application with the OAuth error.
 */

export interface LoginContext {
  cookie: string | undefined
  ip: string | null
  ua: string | null
  requestId: string | null
  now?: number
}

async function refuse(challenge: string, req: HydraLoginRequest, reason: RefusalReason, ctx: LoginContext, who?: { id: string; email: string }): Promise<FlowAnswer> {
  oauthAudit('mcp.oauth.login_refused', {
    actor: { id: who?.id ?? null, email: who?.email ?? null, ip: ctx.ip, ua: ctx.ua, requestId: ctx.requestId },
    targetId: req.client?.client_id ?? 'unknown',
    result: 'denied',
    reason,
    details: { reason, client_name: req.client?.client_name ?? null },
  })
  let to: string
  try {
    to = (await hydraFlows.rejectLogin(challenge, { error: REFUSAL_OAUTH_ERROR[reason], error_description: REFUSAL_DESCRIPTION[reason] })).redirect_to
  } catch (err) {
    hydraFailure(err)
  }
  return { action: 'refused', reason, to }
}

export async function loginStep(challenge: string, ctx: LoginContext): Promise<FlowAnswer> {
  const origin = authOriginOrFail()
  let req: HydraLoginRequest
  try {
    req = await hydraFlows.getLoginRequest(challenge)
  } catch (err) {
    hydraFailure(err)
  }

  if (!isMcpClient(req.client)) return refuse(challenge, req, 'not_mcp_client', ctx)
  const problem = requestProblem(req.request_url, env.DELEGATED_TOKEN_AUDIENCE, { pkce: true })
  if (problem) return refuse(challenge, req, problem, ctx)
  const gate = await oauthGate()
  const off = await gateRefusal(gate)
  if (off) return refuse(challenge, req, off, ctx)

  const back = `${origin}/oauth2/login?login_challenge=${encodeURIComponent(challenge)}`
  const kratosLogin = (extra: Record<string, string> = {}) =>
    `${origin}/self-service/login/browser?${new URLSearchParams({ ...extra, return_to: back }).toString()}`

  const session = await visitorSession(ctx.cookie)
  if (!session) return { action: 'redirect', to: kratosLogin() }
  const who = { id: session.identityId, email: session.email }
  if (req.skip && req.subject && req.subject !== session.identityId) return refuse(challenge, req, 'wrong_account', ctx, who)

  const groups = await gateRefusal(gate, session.email)
  if (groups) return refuse(challenge, req, groups, ctx, who)

  if (session.aal !== 'aal2') {
    let enrolled: boolean
    try {
      enrolled = (await kratosService.mfaMethodsOf(session.identityId)).length > 0
    } catch {
      throw new FlowError(503, 'unavailable', 'Your second factors cannot be read right now.')
    }
    if (!enrolled) {
      return { action: 'redirect', to: `${origin}/two-step?${new URLSearchParams({ return_to: back, must_enrol: '1' }).toString()}` }
    }
    return { action: 'redirect', to: kratosLogin({ aal: 'aal2' }) }
  }
  if (!secondFactorIsFresh({ aal: session.aal, secondFactorAt: session.secondFactorAt, authVia: 'session' }, ctx.now)) {
    return { action: 'redirect', to: kratosLogin({ aal: 'aal2', refresh: 'true' }) }
  }

  try {
    const accepted = await hydraFlows.acceptLogin(challenge, {
      subject: session.identityId,
      remember: false,
      acr: 'aal2',
      amr: session.methods ?? [],
      context: { second_factor_at: session.secondFactorAt!.toISOString(), kratos_session_id: session.sessionId, aal: 'aal2' },
    })
    return { action: 'redirect', to: accepted.redirect_to }
  } catch (err) {
    hydraFailure(err)
  }
}
