import { FastifyError, FastifyReply, FastifyRequest } from 'fastify'
import { ZodError } from 'zod'
import {
  Prisma,
  PrismaClientKnownRequestError,
  PrismaClientValidationError,
  PrismaClientInitializationError,
  PrismaClientRustPanicError,
  PrismaClientUnknownRequestError,
} from '@prisma/client'
import { KratosApiError } from '../services/kratos.service.js'
import { KubeconfigVerificationError } from '../services/cluster.service.js'

const isDevelopment = process.env.NODE_ENV === 'development'

interface PrismaErrorResponse {
  status: number
  error: string
  message: string
}

/**
 * Handle Prisma known request errors with specific error codes
 */
function handlePrismaKnownError(
  error: PrismaClientKnownRequestError
): PrismaErrorResponse {
  switch (error.code) {
    // Unique constraint violation
    case 'P2002':
      return {
        status: 409,
        error: 'Conflict',
        message: `A record with this ${(error.meta?.target as string[])?.join(', ') || 'value'} already exists`,
      }

    // Record not found
    case 'P2025':
      return {
        status: 404,
        error: 'Not Found',
        message: 'The requested record was not found',
      }

    // Foreign key constraint failed
    case 'P2003':
      return {
        status: 400,
        error: 'Bad Request',
        message: `Related ${error.meta?.field_name || 'record'} does not exist`,
      }

    // Required field missing
    case 'P2012':
      return {
        status: 400,
        error: 'Bad Request',
        message: `Missing required field: ${error.meta?.path || 'unknown'}`,
      }

    // Invalid ID format
    case 'P2023':
      return {
        status: 400,
        error: 'Bad Request',
        message: 'Invalid ID format provided',
      }

    // Record to update not found
    case 'P2016':
      return {
        status: 404,
        error: 'Not Found',
        message: 'Record to update was not found',
      }

    // Record to delete not found
    case 'P2017':
      return {
        status: 404,
        error: 'Not Found',
        message: 'Record to delete was not found',
      }

    // Related record not found (for connect operations)
    case 'P2018':
      return {
        status: 400,
        error: 'Bad Request',
        message: 'Related record not found for connection',
      }

    // Input value too long
    case 'P2000':
      return {
        status: 400,
        error: 'Bad Request',
        message: `Value too long for field: ${error.meta?.column_name || 'unknown'}`,
      }

    // Default for unhandled Prisma codes
    default:
      return {
        status: 500,
        error: 'Internal Server Error',
        message: 'A database error occurred',
      }
  }
}

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

  // Zod validation errors (400)
  if (error instanceof ZodError) {
    return reply.status(400).send({
      error: 'Validation failed',
      details: error.errors.map((e) => ({
        path: e.path.join('.'),
        message: e.message,
      })),
    })
  }

  // Prisma validation errors (invalid data shape, missing fields, etc.)
  if (error instanceof PrismaClientValidationError) {
    return reply.status(400).send({
      error: 'Bad Request',
      message: 'Invalid data format or missing required fields',
      ...(isDevelopment && { details: error.message }),
    })
  }

  // Prisma initialization errors (connection issues, schema mismatch)
  if (error instanceof PrismaClientInitializationError) {
    return reply.status(503).send({
      error: 'Service Unavailable',
      message: 'Database connection failed',
      ...(isDevelopment && { details: error.message }),
    })
  }

  // Prisma rust panic errors (critical internal errors)
  if (error instanceof PrismaClientRustPanicError) {
    return reply.status(500).send({
      error: 'Internal Server Error',
      message: 'A critical database error occurred',
      ...(isDevelopment && { details: error.message }),
    })
  }

  // Prisma unknown request errors
  if (error instanceof PrismaClientUnknownRequestError) {
    return reply.status(500).send({
      error: 'Internal Server Error',
      message: 'An unexpected database error occurred',
      ...(isDevelopment && { details: error.message }),
    })
  }

  // Prisma known errors
  if (error instanceof PrismaClientKnownRequestError) {
    const prismaErrorResponse = handlePrismaKnownError(error)
    return reply.status(prismaErrorResponse.status).send({
      error: prismaErrorResponse.error,
      message: prismaErrorResponse.message,
      ...(isDevelopment && { code: error.code, meta: error.meta }),
    })
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

  // Kubeconfig verification errors (400)
  if (error instanceof KubeconfigVerificationError) {
    return reply.status(400).send({
      error: 'Kubeconfig Verification Failed',
      message: error.message,
      verification: error.verificationResult,
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

  // Handle custom HTTP errors with statusCode property
  if ((error as any).statusCode) {
    return reply.status((error as any).statusCode).send({
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
