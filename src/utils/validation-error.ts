import type { ZodError } from 'zod'

// The one 400 body of the API for an invalid request (middleware/error-handler.ts, sites/http.ts).

/** One invalid field: `field` (dotted, `services.3`), the same as `path` (kept for older clients). */
export interface ValidationDetail { field: string; path: string; message: string }

export function zodDetails(error: ZodError): ValidationDetail[] {
  return error.errors.map((e) => {
    const field = e.path.join('.')
    return { field, path: field, message: e.message }
  })
}

/** Fastify/ajv entries: `instancePath` /services/3, or the missing property of a `required` error. */
export function schemaDetails(entries: Array<{ instancePath?: string; message?: string; params?: { missingProperty?: string } }>, context?: string): ValidationDetail[] {
  return entries.map((e) => {
    const at = (e.instancePath ?? '').split('/').filter(Boolean)
    if (e.params?.missingProperty) at.push(e.params.missingProperty)
    const field = at.join('.') || context || 'body'
    return { field, path: field, message: e.message ?? 'is not valid' }
  })
}

export function validationFailed(details: ValidationDetail[]) {
  const shown = details.slice(0, 3).map((d) => `${d.field || 'body'}: ${d.message}`).join('; ')
  return { error: 'Validation failed', message: details.length > 3 ? `${shown} (and ${details.length - 3} more)` : shown, details }
}
