import { hydraService, type HydraOAuth2Client } from './hydra.service.js'
import { opalPublisher } from './opal-publisher.js'
import type { ApiClientRecord } from './authorization-resolution.js'
import { expandScopes, loadKeyModel, type KeyModel } from './api-key-scopes.js'

/**
 * data.api_clients — what the policy needs to decide a MACHINE caller on a site: the organization an
 * org API key belongs to, the permissions its scopes stand for today (its permissions, site roles and
 * groups expanded: api-key-scopes.ts), and its expiry. Keyed by client_id, which the gateway passes
 * as `input.client_id` (Oathkeeper oauth2_introspection → .Extra.client_id).
 *
 * Hydra is the source (metadata.organization_id, set by jinbe on every key); jinbe keeps no copy. A
 * personal key is left out: it acts as its user, through jinbe's delegated path, never as a machine
 * of its org. A client without an organization is left out too — the policy then grants it nothing.
 *
 * Read on every OPAL fetch, so it is kept for a few seconds; every create or revoke drops it and asks
 * OPAL to refetch at once, and every RBAC change drops it (rbacService.invalidateBundle).
 */

const TTL_MS = 10_000
let cached: { at: number; value: Record<string, ApiClientRecord> } | null = null

function recordOf(client: HydraOAuth2Client, model: KeyModel): ApiClientRecord | null {
  const meta = (client.metadata ?? {}) as Record<string, unknown>
  if (meta.kind === 'personal') return null
  const org = meta.organization_id
  if (typeof org !== 'string' || org === '') return null
  return {
    org,
    scopes: expandScopes(model, org, (client.scope ?? '').split(' ').filter(Boolean)),
    ...(typeof meta.expires_at === 'string' ? { expires_at: meta.expires_at } : {}),
  }
}

/** The dataset. Throws when Hydra or Redis cannot be read — the route answers 503 so OPAL keeps what it has. */
export async function apiClientsDataset(now = Date.now()): Promise<Record<string, ApiClientRecord>> {
  if (cached && now - cached.at < TTL_MS) return cached.value
  const out: Record<string, ApiClientRecord> = {}
  const [clients, model] = await Promise.all([hydraService.listAllClients(), loadKeyModel()])
  for (const client of clients) {
    const record = recordOf(client, model)
    if (record) out[client.client_id] = record
  }
  cached = { at: now, value: out }
  return out
}

/** A key was created or revoked: drop the dataset and have OPA refetch it. */
export function apiClientsChanged(reason: string): void {
  cached = null
  opalPublisher.schedule(reason)
}

/** Drops the dataset (an RBAC change: the expansion may differ); also the tests' seam. */
export function resetApiClients(): void {
  cached = null
}
