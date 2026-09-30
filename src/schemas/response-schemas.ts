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

export const forbiddenResponseSchema = {
    type: 'object',
    properties: {
        error: { type: 'string', example: 'Forbidden' },
        message: { type: 'string' },
        // Only on a delegated caller's refusal (delegation gate, guard scope check): what the client
        // can act on — `insufficient_scope` with `scope_missing:<permission>`, or `delegation_refused`
        // with `delegation_ineligible:<why>`. A session refusal carries neither.
        code: { type: 'string', example: 'insufficient_scope' },
        reason: { type: 'string', example: 'scope_missing:users:recovery' },
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
