import { getRedisClient } from '../services/redis-client.service.js'

/**
 * A sign-in's refreshed second factor (step-up-refresh.ts): one Redis key per (person, client),
 * holding the proof time (ISO), living until the sign-in ends. delegated-token.service.ts reads it and
 * takes it over the consent stamp when newer.
 */
export const oauthProofKey = (subject: string, clientId: string) => `jinbe:oauth-stepup:${subject}:${clientId}`

/** The refreshed proof time, or null — unreadable counts as none (the consent stamp stands). */
export async function refreshedOAuthProof(subject: string, clientId: string): Promise<string | null> {
  try {
    const v = await getRedisClient().get(oauthProofKey(subject, clientId))
    return v && Number.isFinite(Date.parse(v)) ? v : null
  } catch {
    return null
  }
}

/** The later of two proof times (ISO), either possibly absent. */
export function laterProof(a: string | null | undefined, b: string | null | undefined): string | undefined {
  const ta = a ? Date.parse(a) : NaN
  const tb = b ? Date.parse(b) : NaN
  if (!Number.isFinite(ta)) return Number.isFinite(tb) ? (b as string) : undefined
  if (!Number.isFinite(tb)) return a as string
  return tb > ta ? (b as string) : (a as string)
}
