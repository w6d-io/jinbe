import { env } from '../config/env.js'

/**
 * Asks the OPA that enforces (the opal-client sidecar) one rule, with its bearer token.
 *
 * Only ever with the token: that OPA refuses anonymous data reads and ad-hoc queries (control S3/S4),
 * and nothing here falls back to an unauthenticated call or to a local guess. Unconfigured → 503,
 * unanswered → 502; a caller turns either into a refusal, never into an allow.
 */

/** OPA is not configured on this deployment (OPA_URL / OPA_TOKEN unset). */
export class OpaUnavailableError extends Error {
  statusCode = 503
}

/** OPA was asked and did not answer usably. The message never carries the token. */
export class OpaQueryError extends Error {
  statusCode = 502
}

const OPA_TIMEOUT_MS = 5000

/** Whether OPA_URL and OPA_TOKEN are both set. */
export function opaConfigured(): boolean {
  return Boolean(env.OPA_URL && env.OPA_TOKEN)
}

/** `POST /v1/data/<rule>` with `{ input }`; `rule` is a data path such as `rbac/delegation/can_grant`. */
export async function queryOpa<T>(rule: string, input: Record<string, unknown>): Promise<T | undefined> {
  const { OPA_URL: url, OPA_TOKEN: token } = env
  if (!url || !token) {
    throw new OpaUnavailableError('OPA is not configured on this deployment: set OPA_URL and OPA_TOKEN (the OPA bearer token).')
  }

  const name = rule.replaceAll('/', '.')
  let res: Response
  try {
    res = await fetch(`${url.replace(/\/$/, '')}/v1/data/${rule}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ input }),
      signal: AbortSignal.timeout(OPA_TIMEOUT_MS),
    })
  } catch (err) {
    throw new OpaQueryError(`OPA is unreachable (${(err as Error).name}).`)
  }
  if (!res.ok) throw new OpaQueryError(`OPA refused the query for ${name} (HTTP ${res.status}).`)
  return ((await res.json()) as { result?: T }).result
}

/**
 * An ad-hoc query (`POST /v1/query`), for what `with` must decide: the same rules on data that is not
 * OPA's (the site's verify asks the policy about a synthetic caller holding one group). Returns the
 * first result's `x` binding. Same token, timeout and error classes as `queryOpa`.
 */
export async function queryOpaAdhoc<T>(query: string, input: Record<string, unknown>): Promise<T | undefined> {
  const { OPA_URL: url, OPA_TOKEN: token } = env
  if (!url || !token) {
    throw new OpaUnavailableError('OPA is not configured on this deployment: set OPA_URL and OPA_TOKEN (the OPA bearer token).')
  }
  let res: Response
  try {
    res = await fetch(`${url.replace(/\/$/, '')}/v1/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ query, input }),
      signal: AbortSignal.timeout(OPA_TIMEOUT_MS),
    })
  } catch (err) {
    throw new OpaQueryError(`OPA is unreachable (${(err as Error).name}).`)
  }
  if (!res.ok) throw new OpaQueryError(`OPA refused the ad-hoc query (HTTP ${res.status}).`)
  return ((await res.json()) as { result?: Array<{ x?: T }> }).result?.[0]?.x
}
