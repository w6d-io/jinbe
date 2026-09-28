import { createHash } from 'crypto'
import { env } from '../config/index.js'
import { getRedisClient } from '../services/redis-client.service.js'
import type { CaptchaFlow } from './settings.js'

/**
 * Tokens the sign-in gate already checked with the provider. A bot-check token is single-use at the
 * provider, and the gate spends it on the submit that sends the code; when the same token then comes
 * back in the Kratos guard hook (the code entered, the sign-up completed), the hook finds it here
 * instead of asking the provider again. Keyed on the token's hash, for one flow, for a few minutes,
 * and good for one hook answer. Redis down: nothing is remembered and the hook asks the provider.
 */

const key = (token: string) => `sip:verified:${createHash('sha256').update(token).digest('hex')}`

export async function rememberVerified(token: string, flow: CaptchaFlow): Promise<void> {
  try {
    await getRedisClient().set(key(token), flow, 'EX', env.SIGN_IN_GATE_VERIFIED_TTL_S)
  } catch {
    // The hook will ask the provider, which refuses a spent token: the person solves the check again.
  }
}

/** Whether the gate verified this token for this flow; a hit is used up. */
export async function takeVerified(token: string | null | undefined, flow: CaptchaFlow): Promise<boolean> {
  if (!token) return false
  try {
    const redis = getRedisClient()
    const k = key(token)
    if ((await redis.get(k)) !== flow) return false
    await redis.del(k)
    return true
  } catch {
    return false
  }
}
