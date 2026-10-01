import type { McpSettings } from '../mcp/settings.js'

/**
 * Until when an MCP sign-in may do protected actions (owner decision D1, 2026-09-30): only when the
 * person ticked them at consent, for `oauth.protectedActionsHours` (12 h) after the second factor they
 * proved for that sign-in, never past the sign-in itself, and never with the window set 'off'.
 * One clock: jinbe's step-up gate, token-info (`step_up_until`, read by auth-mcp) and kuma's list all
 * read it from here. Null: no protected actions.
 */
export function oauthStepUpUntil(
  settings: McpSettings,
  g: { stepUpActions: boolean; stepUpAt: string | null | undefined; grantExpiresAt: string | number | null | undefined },
): string | null {
  if (!g.stepUpActions || settings.oauth.protectedActions !== 'window' || !g.stepUpAt) return null
  const at = Date.parse(g.stepUpAt)
  if (!Number.isFinite(at)) return null
  const end = typeof g.grantExpiresAt === 'number' ? g.grantExpiresAt : g.grantExpiresAt ? Date.parse(g.grantExpiresAt) : Infinity
  const until = Math.min(at + settings.oauth.protectedActionsHours * 3600_000, Number.isFinite(end) ? end : Infinity)
  return Number.isFinite(until) ? new Date(until).toISOString() : null
}
