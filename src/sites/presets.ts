import type { Gate, Handler } from './schemas.js'

/**
 * The gate presets kuma's editor offers (kuma src/lib/sites/presets.ts — keep the two copies equal):
 * the handlers each answer to "who may come in", "who may pass" and "what the service gets" renders
 * to. A gate whose handlers are exactly none of them was hand-built (or built by a tool), and the
 * site check asks a person to confirm it.
 */

export type WhoPreset = 'signed-in' | 'signed-in-or-tokens' | 'people-and-org-keys' | 'tokens' | 'machines' | 'anyone' | 'optional'
export type PassPreset = 'policy' | 'everyone' | 'nobody'
export type GetsPreset = 'identity' | 'nothing' | 'enrich'

/** Kratos session tokens, read from their own header so `Authorization` stays free for OAuth2 tokens. */
export const SESSION_TOKEN: Handler = {
  handler: 'bearer_token',
  config: { token_from: { header: 'X-Session-Token' }, forward_http_headers: ['X-Session-Token'] },
}

export const WHO: Record<WhoPreset, Handler[]> = {
  'signed-in': [{ handler: 'cookie_session' }],
  'signed-in-or-tokens': [{ handler: 'cookie_session' }, SESSION_TOKEN, { handler: 'oauth2_introspection' }],
  // Organizations: the org's people (session) and its API keys (OAuth2 client credentials).
  'people-and-org-keys': [{ handler: 'cookie_session' }, { handler: 'oauth2_introspection' }],
  tokens: [{ handler: 'oauth2_introspection' }, SESSION_TOKEN],
  machines: [{ handler: 'oauth2_introspection' }],
  anyone: [{ handler: 'noop' }],
  optional: [{ handler: 'cookie_session' }, { handler: 'anonymous' }],
}

export const PASS: Record<PassPreset, Gate['authorizer']> = {
  policy: 'policy',
  everyone: { handler: 'allow' },
  nobody: { handler: 'deny' },
}

export const GETS: Record<GetsPreset, Handler[]> = {
  identity: [{ handler: 'header' }],
  nothing: [{ handler: 'noop' }],
  enrich: [{ handler: 'hydrator' }, { handler: 'header' }],
}

export const WHO_LABEL: Record<WhoPreset, string> = {
  'signed-in': 'Signed-in people (session cookie)',
  'signed-in-or-tokens': 'Signed-in people or API tokens',
  'people-and-org-keys': "Organization members and their organization's API keys",
  tokens: 'API tokens only (OAuth2 or session token)',
  machines: 'Machines only (OAuth2 tokens)',
  anyone: 'Anyone',
  optional: 'Optional sign-in',
}

/**
 * The ready-made gate of a site with organizations on (wave 2, owner decision 2026-10-06): the org's
 * people and its API keys come in, the policy decides — on an org row, only in the route's own org,
 * a key only for its own org — and the service gets the identity plus X-Org-Id, X-Org-Roles and
 * X-Client-Id from the decision (render.ts forwards them on every policy gate of such a site). Errors
 * as an API. kuma's and the MCP templates use exactly this.
 */
export const ORG_GATE_ID = 'organization'
export const ORG_GATE: Gate = {
  id: ORG_GATE_ID,
  label: 'Organization members and API keys',
  authenticators: WHO['people-and-org-keys'],
  authorizer: PASS.policy,
  mutators: GETS.identity,
  errors: 'api',
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)

function find<K extends string, V>(table: Record<K, V>, value: V): K | 'custom' {
  return (Object.keys(table) as K[]).find((k) => same(table[k], value)) ?? 'custom'
}

export const whoOf = (gate: Pick<Gate, 'authenticators'>) => find(WHO, gate.authenticators)
export const passOf = (gate: Pick<Gate, 'authorizer'>) => find(PASS, gate.authorizer)
export const getsOf = (gate: Pick<Gate, 'mutators'>) => find(GETS, gate.mutators)

/**
 * A bearer_token authenticator reading the default place — `Authorization: Bearer` — rather than its
 * own header. It claims every bearer token, OAuth2 access tokens included, and refuses the ones Kratos
 * does not know: an oauth2_introspection after it never gets to answer.
 */
export function isBareBearer(h: Handler): boolean {
  if (h.handler !== 'bearer_token') return false
  const from = (h.config as { token_from?: Record<string, unknown> } | undefined)?.token_from
  if (!from || typeof from !== 'object') return true
  const header = typeof from.header === 'string' ? from.header.toLowerCase() : undefined
  return !header && !from.query_parameter && !from.cookie ? true : header === 'authorization'
}
