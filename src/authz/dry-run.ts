/**
 * A request object the explainer builds to run a route's real guards WITHOUT effects
 * (POST /api/admin/rbac/explain-route). Guards run unchanged; the few effects a guard has are
 * skipped for it: the refusal audit (denyAudit) and the delegated write budget. Set only on an object
 * jinbe built itself — never read off anything a client sends.
 */
export const DRY_RUN = Symbol.for('jinbe.dryRun')

export function isDryRun(request: unknown): boolean {
  return typeof request === 'object' && request !== null && (request as Record<symbol, unknown>)[DRY_RUN] === true
}
