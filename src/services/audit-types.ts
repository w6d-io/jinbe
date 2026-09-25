import type { AuditEventType } from '../audit/v1/catalog.js'

/**
 * The legacy (Redis stream) audit event shapes, shared by the writer (audit-event.service), the
 * reader (audit-query) and the audit/v1 legacy map.
 */

// ─── Rich event schema ───────────────────────────────────────────────────────

export type AuditCategory = 'auth' | 'access' | 'rbac' | 'policy' | 'service' | 'route' | 'secret' | 'system'
export type AuditResult   = 'ok' | 'applied' | 'denied' | 'failed' | 'error'
// Coarse grouping used for fan-out gating + UI facets. `security` is reserved
// for explicitly security-flagged emits (kept in the fan-out predicate even
// though it is not a default derived value).
export type AuditKind     = 'change' | 'access' | 'auth' | 'system' | 'security'
// Server-authoritative severity. Maps to UI semantic tokens (info/warn/err);
// `high` is the security-critical tier surfaced via ?risk=high.
export type AuditSeverity = 'info' | 'warn' | 'high'
export type AuditFlag     = 'opened_to_public' | 'auth_disabled' | 'grants_super_admin' | 'wildcard_permission'

export interface AuditActor {
  id?:       string | null    // the immutable identity; an address changes hands, this does not
  email:     string | null    // email, "system", or null (unauthenticated)
  name?:     string | null
  ip?:       string | null
  ua?:       string | null    // User-Agent (truncated)
  sessionId?: string | null
}

/**
 * Loosely-typed actor as threaded from a request through service mutations
 * (A4/P2-5). Superset of the old `{email, ip}` builder — carries name/ua/
 * sessionId for the audit trail and `requestId` for cross-event correlation.
 */
export interface AuditActorInput {
  id?:        string | null
  email?:     string | null
  name?:      string | null
  ip?:        string | null
  ua?:        string | null
  sessionId?: string | null
  requestId?: string | null
}

/**
 * Compact before→after diff envelope. Structural only — values are never
 * serialized here: `added`/`removed` are allow-listed identifiers (service:role,
 * method:path, group names …); `changedKeys` are field names (secret-looking
 * names are redacted); `flags` are computed posture signals; `summary` is
 * plain-language.
 */
export interface AuditChanges {
  resource:     string
  id?:          string
  added?:       string[]
  removed?:     string[]
  changedKeys?: string[]
  flags?:       AuditFlag[]
  summary?:     string
}

export interface AuditEvent {
  category:  AuditCategory
  kind?:     AuditKind
  verb:      string           // allow, deny, login, logout, create, update, delete, assign, sync, expire, mfa, commit
  target:    string           // human-readable: "GET /api/clusters", "group:finance", "user:alice@example.com"
  result:    AuditResult
  actor:     AuditActor
  service?:  string           // RBAC service name if applicable
  reason?:   string           // denial/error reason
  method?:   string           // HTTP method (access events)
  path?:     string           // HTTP path (access events)
  statusCode?: number
  responseTimeMs?: number
  source?:   string           // 'jinbe-api' | 'kratos-webhook' | 'opal' | 'bootstrap'
  // ── Enrichment (A1) ──
  requestId?:  string | null
  changes?:    AuditChanges   // before→after diff (redacted at write time)
  details?:    Record<string, unknown>  // free-form (redacted by key at write time)
  targetId?:   string         // structured target id (e.g. Kratos uuid) for filtering
  targetType?: string         // 'user' | 'group' | 'service' | 'access_rule' | …
  mfa?:        string         // second-factor method/state (auth events)
  severity?:   AuditSeverity  // computed at emit if omitted
  v1Event?:    AuditEventType // audit/v1 catalog key, when the legacy map would have to guess
}

// ─── Legacy compat type (callers still using old schema get auto-upgraded) ──

export interface LegacyAuditEvent {
  type: string
  actor?: { id?: string | null; email?: string | null; ip?: string | null; name?: string | null; ua?: string | null; sessionId?: string | null; requestId?: string | null }
  target?: { type?: string; id?: string; service?: string; services?: string[] }
  details?: Record<string, unknown>
  changes?: AuditChanges
  requestId?: string | null
  source?: string
  severity?: AuditSeverity
  v1Event?: AuditEventType
}

// [P2-1] Fold out-of-enum legacy categories into the canonical taxonomy so
// they are filterable + iconed rather than 400ing the route schema.
const CATEGORY_FOLD: Record<string, AuditCategory> = {
  roles: 'rbac',
  api_key: 'secret',
  user: 'access',
  organization_user: 'access',
}

export function foldCategory(cat: string): AuditCategory {
  return (CATEGORY_FOLD[cat] ?? cat) as AuditCategory
}
