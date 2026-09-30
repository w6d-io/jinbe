import { KratosApiError, kratosService, type MfaMethod } from './kratos.service.js'
import { revokeAllConnectionsQuietly } from '../oauth/connections.js'

/**
 * Removing somebody's two-step sign-in — for the user who lost their authenticator app or key.
 *
 * MECHANISM: the Kratos admin API, one `DELETE /admin/identities/{id}/credentials/{type}` per
 * enrolled second factor (totp, webauthn, lookup_secret — verified against Kratos v26.2.0's
 * identity handler). For `webauthn` Kratos removes the security keys and keeps the passwordless
 * ones: a passkey is a first factor, and taking it away would lock the person out another way.
 *
 * What comes after: with no factor left, Kratos' `highest_available` level is aal1, so a sign-in
 * link (link recovery, an aal1 session) opens their settings instead of asking for the factor they
 * no longer have, and the two-step gate has them enrol a new one if their role requires it.
 */

export class NoSecondFactorError extends Error {}

/** A removal that stopped part-way: what was removed before it did, so the trail can say so. */
export class SecondFactorResetError extends Error {
  constructor(message: string, public readonly removed: MfaMethod[], public readonly cause?: unknown) {
    super(message)
  }
}

/** The second factors an identity has enrolled, as the console lists them before removing. */
export async function secondFactorsOf(identityId: string): Promise<{ methods: MfaMethod[]; email: string | null }> {
  const identity = await kratosService.getIdentityWithSecondFactors(identityId)
  const email = typeof identity.traits?.email === 'string' && identity.traits.email ? identity.traits.email : null
  return { methods: kratosService.mfaMethods(identity.credentials), email }
}

/**
 * Removes every enrolled second factor, then (by default) ends every session: a session already at
 * aal2 would otherwise outlive the factor that proved it. Returns what was removed.
 *
 * Throws the lookup's own error for an unknown identity (a `KratosApiError` 404), and
 * `NoSecondFactorError` when there is nothing to remove.
 */
export async function resetSecondFactors(
  identityId: string,
  methods: readonly MfaMethod[],
  { revokeSessions = true }: { revokeSessions?: boolean } = {},
): Promise<{ removed: MfaMethod[]; sessionsRevoked: boolean }> {
  if (methods.length === 0) throw new NoSecondFactorError('The user has no second factor')

  const removed: MfaMethod[] = []
  for (const method of methods) {
    try {
      await kratosService.deleteSecondFactor(identityId, method)
    } catch (err) {
      // Gone since it was read (the user removed it, or another admin did): the outcome is the same.
      if (!(err instanceof KratosApiError && err.statusCode === 404)) {
        throw new SecondFactorResetError(`Kratos refused to remove ${method}`, removed, err)
      }
    }
    removed.push(method)
  }

  if (revokeSessions) {
    try {
      await kratosService.revokeAllIdentitySessions(identityId)
    } catch (err) {
      throw new SecondFactorResetError('The factors were removed, but the sessions could not be ended', removed, err)
    }
    // The AI apps signed in with a browser stood on the factors just removed: they go with the sessions.
    await revokeAllConnectionsQuietly(identityId)
  }
  return { removed, sessionsRevoked: revokeSessions }
}
