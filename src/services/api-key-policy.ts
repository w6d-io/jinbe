import { getRedisClient } from './redis-client.service.js'
import type { ApiKeyPolicy } from '../schemas/api-key.schema.js'

/**
 * An organization's policy on API keys its members create for themselves.
 *
 *   rbac:org_api_key_policy → Hash: { organizationId: JSON({ personal_keys: 'allowed' | 'forbidden' }) }
 *
 * Default `allowed` (owner decision: personal keys allowed, 30 days at most; an org admin may forbid
 * them). Read at creation AND on every call a personal key makes, so forbidding them stops the keys
 * already out there, not only new ones.
 */

const KEY = 'rbac:org_api_key_policy'
export const DEFAULT_API_KEY_POLICY: ApiKeyPolicy = { personal_keys: 'allowed' }

export async function getApiKeyPolicy(organizationId: string): Promise<ApiKeyPolicy> {
  const raw = await getRedisClient().hget(KEY, organizationId)
  if (raw === null) return DEFAULT_API_KEY_POLICY
  try {
    const parsed = JSON.parse(raw) as Partial<ApiKeyPolicy>
    // Anything unreadable is the stricter answer: a policy somebody set cannot silently fall open.
    return { personal_keys: parsed.personal_keys === 'allowed' ? 'allowed' : 'forbidden' }
  } catch {
    return { personal_keys: 'forbidden' }
  }
}

export async function setApiKeyPolicy(organizationId: string, policy: ApiKeyPolicy): Promise<ApiKeyPolicy> {
  await getRedisClient().hset(KEY, organizationId, JSON.stringify(policy))
  return policy
}
