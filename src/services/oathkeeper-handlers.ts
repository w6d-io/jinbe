import { env } from '../config/env.js'

/**
 * Oathkeeper handler catalog
 * ---------------------------
 * A static, plain-language description of the gateway (Oathkeeper) handlers this
 * platform supports, plus which of them are actually ENABLED in the running
 * gateway (from env).
 *
 * The gateway processes every request through a pipeline of handlers:
 *   authenticators → authorizer → mutators → error handlers
 * Each handler has its own config shape. This catalog carries a `fields`
 * descriptor per handler so an admin UI can render a guided form (plain labels +
 * help) instead of asking a non-technical operator to hand-write raw config.
 *
 * Two concerns are kept separate on purpose:
 *  - The CATALOG is the full set of handlers we know how to describe.
 *  - The ENABLED set (from env) is what the gateway will actually accept. jinbe
 *    validates rules against the enabled set fail-closed (see rbac.service), and
 *    only enabled handlers are ever offered to the UI (getEnabledHandlers).
 */

/** The kind of pipeline stage a handler belongs to. */
export type HandlerKind = 'authenticator' | 'authorizer' | 'mutator' | 'error'

/** The input control a field should render as in a guided form. */
export type FieldType = 'string' | 'url' | 'bool' | 'textarea' | 'kv' | 'list' | 'json'

/**
 * One configurable field of a handler, described for a guided UI.
 * `type` picks the control; `help`/`placeholder`/`label` are plain-language and
 * may be shown verbatim to non-technical admins.
 */
export interface FieldDescriptor {
  key: string
  label: string
  type: FieldType
  required?: boolean
  placeholder?: string
  help?: string
}

/**
 * A handler as offered to the UI. This is the exact shape returned by
 * GET /admin/rbac/oathkeeper/handlers — no `kind` (grouping conveys it).
 */
export interface HandlerDescriptor {
  handler: string
  label: string
  description: string
  /** Whether the handler accepts free-form config beyond the guided fields. */
  hasFreeformConfig: boolean
  fields: FieldDescriptor[]
}

/** The four grouped lists returned by the handlers endpoint. */
export interface EnabledHandlers {
  authenticators: HandlerDescriptor[]
  authorizers: HandlerDescriptor[]
  mutators: HandlerDescriptor[]
  errorHandlers: HandlerDescriptor[]
}

/** Internal catalog entry — a descriptor tagged with its pipeline kind. */
type CatalogEntry = HandlerDescriptor & { kind: HandlerKind }

// ─────────────────────────────────────────────────────────────
// Catalog — the descriptor for each handler we know how to configure.
// Text is plain-language on purpose: an admin who is not an Ory expert may read
// it. Ory handler names / config keys live in `handler`/`fields[].key`.
// ─────────────────────────────────────────────────────────────

const CATALOG: CatalogEntry[] = [
  // ── Authenticators — "who is this request from?" ──────────────────────────
  {
    kind: 'authenticator',
    handler: 'cookie_session',
    label: 'Signed-in session',
    description:
      'Recognizes a user by their sign-in session cookie. Use this for anything a logged-in person should reach.',
    hasFreeformConfig: true,
    fields: [
      {
        key: 'check_session_url',
        label: 'Session check address',
        type: 'url',
        help: 'The internal address the gateway asks to confirm the session cookie is valid.',
        placeholder: 'http://kratos-public/sessions/whoami',
      },
      {
        key: 'preserve_path',
        label: 'Keep original path when checking',
        type: 'bool',
        help: 'Leave on unless the session service expects the check on its own path.',
      },
      {
        key: 'subject_from',
        label: 'Where to read the user id',
        type: 'string',
        help: 'Field in the session response that identifies the user. Usually left at the default.',
        placeholder: 'identity.id',
      },
      {
        key: 'extra_from',
        label: 'Where to read extra user info',
        type: 'string',
        help: 'Field in the session response carrying extra attributes passed on to the service.',
        placeholder: 'identity.traits',
      },
      {
        key: 'only',
        label: 'Only these cookies count',
        type: 'list',
        help: 'Restrict which cookie names are treated as a session. Leave empty to accept the default.',
      },
    ],
  },
  {
    kind: 'authenticator',
    handler: 'noop',
    label: 'No sign-in required',
    description:
      'Skips the sign-in check entirely — every request is treated as anonymous. Use only for genuinely public endpoints.',
    hasFreeformConfig: false,
    fields: [],
  },

  // ── Authorizers — "is this request allowed?" ──────────────────────────────
  {
    kind: 'authorizer',
    handler: 'allow',
    label: 'Allow everyone',
    description: 'Permits every request that got this far. No permission check.',
    hasFreeformConfig: false,
    fields: [],
  },
  {
    kind: 'authorizer',
    handler: 'deny',
    label: 'Block everyone',
    description: 'Rejects every request. Use to fully close off a path.',
    hasFreeformConfig: false,
    fields: [],
  },
  {
    kind: 'authorizer',
    handler: 'remote_json',
    label: 'Check permissions',
    description:
      'Asks the permission service (OPA) whether this user may perform this action. This is the standard protected setup.',
    hasFreeformConfig: true,
    fields: [
      {
        key: 'remote',
        label: 'Permission service address',
        type: 'url',
        required: true,
        help: 'The internal address the gateway asks for an allow/deny decision.',
        placeholder: 'http://opa-authz-proxy:8080/v1/data/rbac/allow',
      },
      {
        key: 'payload',
        label: 'Decision request body',
        type: 'textarea',
        help: 'The JSON template sent to the permission service. Advanced — leave as generated unless you know the decision schema.',
      },
      {
        key: 'forward_response_headers_to_upstream',
        label: 'Headers to forward from the decision',
        type: 'list',
        help: 'Any response headers from the permission service to pass on to the service.',
      },
    ],
  },

  // ── Mutators — "what does the service receive?" ───────────────────────────
  {
    kind: 'mutator',
    handler: 'noop',
    label: 'Pass through unchanged',
    description: 'Sends the request to the service as-is, adding nothing.',
    hasFreeformConfig: false,
    fields: [],
  },
  {
    kind: 'mutator',
    handler: 'header',
    label: 'Add identity headers',
    description:
      'Adds headers (e.g. the signed-in user id/email) so the service knows who is calling. Standard for protected services.',
    hasFreeformConfig: true,
    fields: [
      {
        key: 'headers',
        label: 'Headers to add',
        type: 'kv',
        required: true,
        help: 'Header name → value. Values may reference the authenticated user (templated).',
      },
    ],
  },

  // ── Error handlers — "what does the user see when denied?" ────────────────
  {
    kind: 'error',
    handler: 'redirect',
    label: 'Send to a page',
    description:
      'On an error (e.g. not signed in), send the browser to another page — typically the login screen.',
    hasFreeformConfig: true,
    fields: [
      {
        key: 'to',
        label: 'Where to send the user',
        type: 'url',
        required: true,
        help: 'The page the browser is redirected to, e.g. the sign-in screen.',
        placeholder: 'https://app.example.com/login',
      },
      {
        key: 'return_to_query_param',
        label: 'Return-path parameter',
        type: 'string',
        help: 'Query parameter used to remember where the user was headed, so they return there after signing in.',
        placeholder: 'return_to',
      },
      {
        key: 'when',
        label: 'When to apply',
        type: 'json',
        help: 'Advanced — conditions (request types / errors) that trigger this redirect. Leave empty to always apply.',
      },
    ],
  },
  {
    kind: 'error',
    handler: 'json',
    label: 'Return an error message',
    description:
      'On an error, return a JSON error response — suitable for APIs and machine callers rather than browsers.',
    hasFreeformConfig: true,
    fields: [
      {
        key: 'verbose',
        label: 'Include error details',
        type: 'bool',
        help: 'Return a fuller error body. Handy while debugging; usually off in production.',
      },
    ],
  },
]

// ─────────────────────────────────────────────────────────────
// Enabled-set resolution (read from env at call time)
// ─────────────────────────────────────────────────────────────

/** The env-configured enabled handler names for a given kind. */
export function getEnabledHandlerNames(kind: HandlerKind): string[] {
  switch (kind) {
    case 'authenticator':
      return env.OATHKEEPER_ENABLED_AUTHENTICATORS
    case 'authorizer':
      return env.OATHKEEPER_ENABLED_AUTHORIZERS
    case 'mutator':
      return env.OATHKEEPER_ENABLED_MUTATORS
    case 'error':
      return env.OATHKEEPER_ENABLED_ERROR_HANDLERS
  }
}

/**
 * Whether a handler of the given kind is enabled in the running gateway.
 * This is the authoritative fail-closed check: a name absent from the env set
 * is rejected regardless of whether the catalog can describe it.
 */
export function isHandlerEnabled(kind: HandlerKind, name: string): boolean {
  return getEnabledHandlerNames(kind).includes(name)
}

/** Strip the internal `kind` tag before emitting to the UI. */
function toDescriptor(entry: CatalogEntry): HandlerDescriptor {
  return {
    handler: entry.handler,
    label: entry.label,
    description: entry.description,
    hasFreeformConfig: entry.hasFreeformConfig,
    fields: entry.fields,
  }
}

function enabledOfKind(kind: HandlerKind): HandlerDescriptor[] {
  const enabled = getEnabledHandlerNames(kind)
  return CATALOG.filter((e) => e.kind === kind && enabled.includes(e.handler)).map(toDescriptor)
}

/**
 * The catalog filtered by the env enabled sets, grouped as the API contract.
 * Only handlers that are BOTH enabled in the gateway AND describable in the
 * catalog are returned — these are what the UI may offer.
 */
export function getEnabledHandlers(): EnabledHandlers {
  return {
    authenticators: enabledOfKind('authenticator'),
    authorizers: enabledOfKind('authorizer'),
    mutators: enabledOfKind('mutator'),
    errorHandlers: enabledOfKind('error'),
  }
}
