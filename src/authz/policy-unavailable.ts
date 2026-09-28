/**
 * The `error` of every 503 that means "OPA could not be asked" (unconfigured, unreachable, or no
 * answer), as sites/mine.ts has always sent it: a client tells a policy outage from any other
 * unavailability without reading the message. A leaf module, so tests that mock authz/opa.js keep it.
 */
export const POLICY_UNAVAILABLE = 'policy_unavailable'
