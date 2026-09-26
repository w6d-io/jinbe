import { env } from '../config/index.js'
import { kratosService } from './kratos.service.js'
import { getRedisClient } from './redis-client.service.js'

/**
 * Emails somebody a one-click sign-in link — for the user who cannot get in.
 *
 * MECHANISM: Kratos account recovery with the `link` method, started for the identity's address, so
 * Kratos' own courier sends the mail. jinbe has no mailer, and must not hold the link: an admin
 * recovery link (`POST /admin/recovery/link`) comes back to US, and anything jinbe holds it could
 * leak. The mail says "recover access to your account by clicking the following link"; opening it in
 * any browser signs the user in (session method `link_recovery`) and lands them on the settings page,
 * where they may add a passkey or a second factor, then continue.
 *
 * NOT THE `code` METHOD, on purpose. A recovery code belongs to the flow it was issued in, and the
 * mail carries the bare code — no link, no flow — so a user who did not start that flow has nowhere
 * to type it. Sending one would report success and leave them exactly as stuck. When Kratos offers
 * recovery by code only, this refuses (`LoginLinkUnavailableError`) and says what to configure.
 */

export const LOGIN_LINK_LIMIT = 3
export const LOGIN_LINK_WINDOW_S = 15 * 60

export class LoginLinkUnavailableError extends Error {}
export class LoginLinkReturnToRefusedError extends Error {}
export class LoginLinkRateLimitedError extends Error {
  constructor(public readonly retryAfterSeconds: number) {
    super('Too many sign-in links for this user')
  }
}
export class LoginLinkNoAddressError extends Error {}

interface RecoveryFlow {
  id: string
  expires_at?: string
  ui?: { nodes?: Array<{ group?: string }> }
}

/**
 * Counts one link for this user, refusing past the limit. Per TARGET, not per caller: the harm is a
 * mailbox flooded with sign-in links, whoever presses the button.
 *
 * An unreachable counter refuses rather than waving the request through — the thrown error becomes a
 * 5xx. A limit nobody can verify is not a limit.
 */
async function countAgainstLimit(identityId: string): Promise<void> {
  const redis = getRedisClient()
  const key = `jinbe:login-link:${identityId}`
  const count = await redis.incr(key)
  if (count === 1) await redis.expire(key, LOGIN_LINK_WINDOW_S)
  if (count > LOGIN_LINK_LIMIT) {
    const ttl = await redis.ttl(key)
    throw new LoginLinkRateLimitedError(ttl > 0 ? ttl : LOGIN_LINK_WINDOW_S)
  }
}

/** Whether `return_to` is an absolute http(s) address. Which ones are allowed is Kratos' to say. */
export function acceptableReturnTo(value: string): boolean {
  if (value.length > 2048) return false
  try {
    const url = new URL(value)
    return (url.protocol === 'https:' || url.protocol === 'http:') && !url.username && !url.password
  } catch {
    return false
  }
}

/**
 * Sends the link. Returns when it expires at the latest — the recovery flow's end; Kratos'
 * `selfservice.methods.link.config.lifespan` can make the link itself expire sooner.
 *
 * Throws the identity lookup's own error for an unknown user (a `KratosApiError` 404), before any
 * link is counted.
 */
export async function sendLoginLink(identityId: string, returnTo?: string): Promise<{ expiresAt: string | null }> {
  const identity = await kratosService.getIdentity(identityId)
  const address = identity.traits?.email
  if (typeof address !== 'string' || !address) throw new LoginLinkNoAddressError('The user has no email address')

  await countAgainstLimit(identityId)

  const publicUrl = env.KRATOS_PUBLIC_URL
  const init = new URL(`${publicUrl}/self-service/recovery/api`)
  if (returnTo) init.searchParams.set('return_to', returnTo)
  const started = await fetch(init, { headers: { Accept: 'application/json' } })
  if (started.status === 400 && returnTo) {
    // Kratos checks `return_to` against `selfservice.allowed_return_urls` — the one list that decides.
    throw new LoginLinkReturnToRefusedError('return_to is not an allowed return address')
  }
  if (!started.ok) throw new Error(`Kratos refused to start a recovery flow: ${started.status}`)
  const flow = (await started.json()) as RecoveryFlow

  const offersLink = (flow.ui?.nodes ?? []).some((n) => n.group === 'link')
  if (!offersLink) {
    throw new LoginLinkUnavailableError(
      'Kratos recovers accounts by code only; a code mailed outside a flow the user holds cannot be used. ' +
      'Set selfservice.flows.recovery.use: link (with selfservice.methods.link.enabled: true).',
    )
  }

  const submitted = await fetch(`${publicUrl}/self-service/recovery?flow=${encodeURIComponent(flow.id)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ email: address, method: 'link' }),
  })
  if (!submitted.ok) throw new Error(`Kratos refused to send the recovery link: ${submitted.status}`)

  return { expiresAt: flow.expires_at ?? null }
}
