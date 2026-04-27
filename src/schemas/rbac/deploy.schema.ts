import { z } from 'zod'

/**
 * Single file change for deploy
 */
export const fileChangeSchema = z.object({
  filePath: z.string().min(1),
  content: z.unknown(),
  expectedSha: z.string().min(1),
  action: z.enum(['create', 'update', 'delete']).default('update'),
})

/**
 * Deploy request schema
 * Frontend sends all changes at once for atomic commit
 */
export const deployRequestSchema = z.object({
  message: z.string().min(1).max(500),
  changes: z.array(fileChangeSchema).min(1),
  dryRun: z.boolean().default(false),
})

/**
 * Conflict detail
 */
export const conflictDetailSchema = z.object({
  filePath: z.string(),
  expectedSha: z.string(),
  actualSha: z.string(),
  message: z.string(),
})

/**
 * Deploy response schema
 */
export const deployResponseSchema = z.object({
  success: z.boolean(),
  commitId: z.string().optional(),
  commitUrl: z.string().optional(),
  filesModified: z.array(z.string()).optional(),
  timestamp: z.string().datetime().optional(),
  // For conflict response
  error: z.string().optional(),
  conflicts: z.array(conflictDetailSchema).optional(),
})

// Type exports
export type FileChange = z.infer<typeof fileChangeSchema>
export type DeployRequest = z.infer<typeof deployRequestSchema>
export type ConflictDetail = z.infer<typeof conflictDetailSchema>
export type DeployResponse = z.infer<typeof deployResponseSchema>

// JSON Schemas for OpenAPI
export const deployRequestJsonSchema = {
  type: 'object',
  required: ['message', 'changes'],
  properties: {
    message: {
      type: 'string',
      minLength: 1,
      maxLength: 500,
      description: 'Commit message',
    },
    changes: {
      type: 'array',
      minItems: 1,
      description: 'List of file changes to commit atomically',
      items: {
        type: 'object',
        required: ['filePath', 'content', 'expectedSha'],
        properties: {
          filePath: { type: 'string', description: 'Path to the file in the repository' },
          content: { type: 'object', description: 'New file content (JSON)' },
          expectedSha: {
            type: 'string',
            description: 'SHA of the file when it was last read (for conflict detection)',
          },
          action: {
            type: 'string',
            enum: ['create', 'update', 'delete'],
            default: 'update',
            description: 'Type of change',
          },
        },
      },
    },
    dryRun: {
      type: 'boolean',
      default: false,
      description: 'If true, validate changes without committing',
    },
  },
}

export const deploySuccessResponseJsonSchema = {
  type: 'object',
  properties: {
    success: { type: 'boolean', example: true },
    commitId: { type: 'string', description: 'Git commit ID' },
    commitUrl: { type: 'string', format: 'uri', description: 'URL to view the commit' },
    filesModified: {
      type: 'array',
      items: { type: 'string' },
      description: 'List of files that were modified',
    },
    timestamp: { type: 'string', format: 'date-time' },
  },
  required: ['success', 'commitId', 'filesModified', 'timestamp'],
}

export const deployConflictResponseJsonSchema = {
  type: 'object',
  properties: {
    success: { type: 'boolean', example: false },
    error: { type: 'string', example: 'Conflict' },
    conflicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          filePath: { type: 'string' },
          expectedSha: { type: 'string' },
          actualSha: { type: 'string' },
          message: { type: 'string' },
        },
      },
      description: 'List of files with conflicts',
    },
  },
  required: ['success', 'error', 'conflicts'],
}
