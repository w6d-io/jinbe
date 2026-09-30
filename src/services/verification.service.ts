import { env } from '../config/index.js'
import type { KratosIdentity } from '../schemas/admin.schema.js'
import { getRedisClient } from './redis-client.service.js'

/**
 * Sends somebody the link that verifies one of their addresses — for the user whose first mail was
 * lost, and after an administrator changed their address (email-change.service.ts).
 *
 * MECHANISM: a Kratos self-service verification flow with the `link` method, submitted for the
 * address, so Kratos' own courier sends the mail and the link never passes through jinbe. Not the
 * `code` method: the mail would carry a bare code belonging to a flow the user does not hold (the
 * trap login-link.service.ts documents). When Kratos verifies by code only, this refuses
 * (`VerificationUnavailableError`) and says what to configure.
 *
 * Limited per TARGET (a mailbox flooded with links, whoever presses the button) and per CALLER (one
 * key or console sweeping the directory). An unreachable counter refuses: a limit nobody can verify
 * is not a limit.
 */

export const VERIFY_TARGET_LIMIT = 3
export const VERIFY_TARGET_WINDOW_S = 15 * 60
export const VERIFY_CALLER_LIMIT = 30
export const VERIFY_CALLER_WINDOW_S = 3600

export class VerificationUnavailableError extends Error {}
export class AlreadyVerifiedError extends Error {}
export class UnknownAddressError extends Error {}
export class VerificationRateLimitedError extends Error {
  constructor(public readonly retryAfterSeconds: number, public readonly scope: 'target' | 'caller') {
    super('Too many verification links')
  }
}

interface VerificationFlow {
  id: string
  ui?: { nodes?: Array<{ group?: string }> }
}

const normalise = (a: string) => a.trim().toLowerCase()

/**
 * The unverified address to send to: the one asked for (it must be the identity's, and unverified),
 * else the unverified one matching the sign-in address, else the first unverified one.
 */
export function unverifiedAddress(identity: KratosIdentity, wanted?: string): string {
  const addresses = (identity.verifiable_addresses ?? []).filter((a) => a.via === 'email' || a.via === undefined)
  if (wanted) {
    const found = addresses.find((a) => normalise(a.value) === normalise(wanted))
    if (!found) throw new UnknownAddressError('This address is not one of the user\'s')
    if (found.verified) throw new AlreadyVerifiedError('This address is already verified')
    return found.value
  }
  const pending = addresses.filter((a) => !a.verified)
  if (pending.length === 0) throw new AlreadyVerifiedError('Every address of this user is verified')
  const primary = typeof identity.traits?.email === 'string' ? normalise(identity.traits.email) : null
  return (pending.find((a) => normalise(a.value) === primary) ?? pending[0]).value
}

async function count(key: string, limit: number, windowS: number, scope: 'target' | 'caller'): Promise<void> {
  const redis = getRedisClient()
  const n = await redis.incr(key)
  if (n === 1) await redis.expire(key, windowS)
  if (n > limit) {
    const ttl = await redis.ttl(key)
    throw new VerificationRateLimitedError(ttl > 0 ? ttl : windowS, scope)
  }
}

/** Counts one link against the caller's and the target's budgets, refusing past either. */
export async function countVerificationLink(identityId: string, callerId: string): Promise<void> {
  await count(`jinbe:verify-link:caller:${callerId}`, VERIFY_CALLER_LIMIT, VERIFY_CALLER_WINDOW_S, 'caller')
  await count(`jinbe:verify-link:target:${identityId}`, VERIFY_TARGET_LIMIT, VERIFY_TARGET_WINDOW_S, 'target')
}

/** Asks Kratos to mail a verification link to `address`. Counts nothing: the caller decides. */
export async function sendVerificationLink(address: string): Promise<void> {
  const publicUrl = env.KRATOS_PUBLIC_URL
  const started = await fetch(`${publicUrl}/self-service/verification/api`, { headers: { Accept: 'application/json' } })
  if (!started.ok) throw new Error(`Kratos refused to start a verification flow: ${started.status}`)
  const flow = (await started.json()) as VerificationFlow

  const offersLink = (flow.ui?.nodes ?? []).some((n) => n.group === 'link')
  if (!offersLink) {
    throw new VerificationUnavailableError(
      'Kratos verifies addresses by code only; a code mailed outside a flow the user holds cannot be used. ' +
      'Set selfservice.flows.verification.use: link (with selfservice.methods.link.enabled: true).',
    )
  }

  const submitted = await fetch(`${publicUrl}/self-service/verification?flow=${encodeURIComponent(flow.id)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ email: address, method: 'link' }),
  })
  if (!submitted.ok) throw new Error(`Kratos refused to send the verification link: ${submitted.status}`)
}
