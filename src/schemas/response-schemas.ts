/**
 * Centralized JSON schemas for API responses
 * Eliminates duplication across route files
 */

// ===================
// Common Schemas
// ===================

export const notFoundResponseSchema = {
    type: 'object',
    properties: {
        message: { type: 'string' },
    },
}

export const messageResponseSchema = {
    type: 'object',
    properties: {
        message: { type: 'string' },
    },
}

export const unauthorizedResponseSchema = {
    type: 'object',
    properties: {
        error: { type: 'string', example: 'Unauthorized' },
        // authentication_required = no credential presented;
        // session_invalid = a credential WAS presented but rejected
        // (expired/revoked cookie, bad SA token) — clients should force
        // re-auth via login?refresh=true to regenerate the session.
        code: { type: 'string', example: 'authentication_required' },
        message: {
            type: 'string',
            example: 'Valid authentication required. Please provide a valid ory_kratos_session cookie.',
        },
    },
}

export const badRequestResponseSchema = {
    type: 'object',
    properties: {
        error: { type: 'string', example: 'Bad Request' },
        message: { type: 'string' },
    },
}

/**
 * What a 403 for a missing permission adds (services/permission-refusal.ts): the permission, or the
 * ones missing from a grant, the groups whose roles give it, and who to ask. kuma and auth-mcp render
 * `grantedBy` and `hint`. Group names only — never their members.
 */
export const permissionRefusalProperties = {
    permission: { type: 'string', example: 'users:reset_second_factor' },
    missing: { type: 'array', items: { type: 'string' }, example: ['users:reset_second_factor'] },
    missingByScope: { type: 'object', additionalProperties: { type: 'array', items: { type: 'string' } } },
    grantedBy: { type: 'array', items: { type: 'string' }, example: ['staff-security', 'super_admins'] },
    hint: { type: 'string', example: 'Ask an administrator to add you to one of: staff-security, super_admins.' },
} as const

export const forbiddenResponseSchema = {
    type: 'object',
    properties: {
        error: { type: 'string', example: 'Forbidden' },
        message: { type: 'string' },
        // What the client can act on. A delegated caller's refusal: `insufficient_scope` with
        // `scope_missing:<permission>`, or `delegation_refused` with `delegation_ineligible:<why>`. A
        // missing permission: `permission_required`; the escalation guard: `grant_exceeds_own`,
        // `staff_group_super_admin_only`, `self_escalation`, `grants_everything`. An org route OPA
        // refused: `needs_2fa` / `step_up_unavailable` (with `stepUp`), `route_not_published`, or
        // `permission_required`, with OPA's reason in `reason`.
        code: { type: 'string', example: 'insufficient_scope' },
        reason: { type: 'string', example: 'scope_missing:users:recovery' },
        ...permissionRefusalProperties,
        stepUp: { type: 'object', properties: { requiredAal: { type: 'string', example: 'aal2' } } },
    },
}

export const serviceUnavailableResponseSchema = {
    type: 'object',
    properties: {
        error: { type: 'string', example: 'Service Unavailable' },
        // Why, when the code alone does not say: `not_configured` is set-up, not an outage.
        reason: { type: 'string' },
        message: { type: 'string' },
    },
}

export const conflictResponseSchema = {
    type: 'object',
    properties: {
        error: { type: 'string', example: 'Conflict' },
        message: { type: 'string' },
    },
}
