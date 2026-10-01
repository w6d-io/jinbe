import { FastifyError, FastifyReply, FastifyRequest } from 'fastify'
import { ZodError } from 'zod'
import { schemaDetails, validationFailed, zodDetails } from '../utils/validation-error.js'
import { KratosApiError } from '../services/kratos.service.js'
import { POLICY_UNAVAILABLE } from '../authz/policy-unavailable.js'
import { InvalidBindingError } from '../services/group-bindings.js'
import {
  OrganisationInUseError,
  OrganisationNotFoundError,
  OrganisationStoreNotConfiguredError,
  OrganisationStoreUnavailableError,
  organisationStoreNotConfigured,
} from '../services/organisation-store.js'

const isDevelopment = process.env.NODE_ENV === 'development'

/**
 * Global error handler
 * Maintains original error semantics from Next.js API routes
 */
export function errorHandler(
  error: FastifyError | any,
  request: FastifyRequest,
  reply: FastifyReply
) {
  const { log } = request

  // Log error with request context
  log.error(
    {
      err: error,
      requestId: request.headers['x-request-id'],
      method: request.method,
      url: request.url,
    },
    'Request error'
  )

  // Validation errors (400), zod's or the route JSON schema's: one shape, `details[]` naming each
  // field, and a `message` a client can show as it is.
  if (error instanceof ZodError) return reply.status(400).send(validationFailed(zodDetails(error)))
  if (Array.isArray(error.validation) && error.statusCode === 400) {
    return reply.status(400).send(validationFailed(schemaDetails(error.validation, error.validationContext)))
  }

  // Kratos API errors (external service)
  if (error instanceof KratosApiError) {
    // Map Kratos status codes to appropriate responses
    const statusCode = error.statusCode
    let errorMessage = 'Kratos API error'

    if (statusCode === 404) {
      errorMessage = 'User not found'
    } else if (statusCode === 409) {
      errorMessage = 'User already exists'
    } else if (statusCode === 400) {
      errorMessage = 'Invalid user data'
    } else if (statusCode >= 500) {
      errorMessage = 'Identity service unavailable'
    }

    return reply.status(statusCode).send({
      error: errorMessage,
      message: error.message,
      ...(isDevelopment && { details: error.details }),
    })
  }

  // JWT errors (401)
  if (error.message?.includes('jwt') || error.message?.includes('token')) {
    return reply.status(401).send({
      error: 'Unauthorized',
      message: 'Invalid or expired token',
    })
  }

  // Rate limit exceeded (429)
  if (error.statusCode === 429) {
    return reply.status(429).send({
      error: 'Too Many Requests',
      message: 'Rate limit exceeded, please try again later',
    })
  }

  // OPA could not be asked: the same code the guards send, the message kept.
  // No organisation directory (unset, or its database down): an outage of one store, not a crash. A
  // named code lets the console say which part is missing instead of a bare 500.
  if (error instanceof OrganisationNotFoundError) {
    return reply.status(404).send({ error: 'organisation_not_found', message: error.message })
  }
  if (error instanceof OrganisationInUseError) {
    return reply.status(409).send({ error: 'organisation_in_use', message: error.message, members: error.members })
  }
  if (error instanceof OrganisationStoreNotConfiguredError) {
    return reply.status(503).send(organisationStoreNotConfigured())
  }
  if (error instanceof OrganisationStoreUnavailableError) {
    return reply.status(503).send({ error: 'organisation_directory_unavailable', message: error.message })
  }

  if (error instanceof InvalidBindingError) {
    return reply.status(422).send({ error: 'invalid_binding', message: error.message, problems: error.problems })
  }

  if (error.code === POLICY_UNAVAILABLE) {
    return reply.status(503).send({ error: POLICY_UNAVAILABLE, message: error.message })
  }

  // Handle custom HTTP errors with statusCode property. A permission refusal (the escalation guard)
  // carries what the caller can act on — code, what is missing, the groups granting it, a hint —
  // beside the message it always sent as `error`.
  // Something defined in code (the staff groups, super_admins, jinbe's roles and route map): a machine
  // code a console can match, unlike a 409 "already exists".
  if (error.code === 'defined_in_code') {
    return reply.status(error.statusCode ?? 409).send({ error: 'defined_in_code', code: 'defined_in_code', message: error.message })
  }
  if ((error as any).statusCode) {
    const refusal = (error as any).statusCode === 403 && (error as any).refusal && typeof (error as any).refusal === 'object'
      ? (error as any).refusal as Record<string, unknown>
      : undefined
    return reply.status((error as any).statusCode).send({
      ...refusal,
      error: error.message,
      ...(isDevelopment && { stack: error.stack }),
    })
  }

  // Fastify serialization errors (response doesn't match schema)
  if (
    error instanceof TypeError &&
    error.message?.includes('does not match schema definition')
  ) {
    return reply.status(500).send({
      error: 'Internal Server Error',
      message: 'Response serialization failed - data format mismatch',
      ...(isDevelopment && {
        details: error.message,
        stack: error.stack,
      }),
    })
  }

  // Default to 500 for unhandled errors
  const statusCode = error.statusCode || 500
  const message = error.statusCode ? error.message : 'Internal Server Error'

  return reply.status(statusCode).send({
    error: message,
    ...(isDevelopment && {
      details: error.message,
      stack: error.stack,
    }),
  })
}
