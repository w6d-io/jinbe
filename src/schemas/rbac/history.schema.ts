/**
 * History/Audit Schemas for RBAC Configuration Changes
 *
 * Provides Zod schemas and JSON schemas for tracking commit history
 * and changes to RBAC configuration files.
 */

import { z } from 'zod'

// ============================================================================
// Zod Schemas
// ============================================================================

/**
 * Information about a single commit
 */
export const commitInfoSchema = z.object({
  commitId: z.string().describe('Full commit SHA'),
  shortId: z.string().describe('Short commit SHA (7 chars)'),
  title: z.string().describe('First line of commit message'),
  message: z.string().describe('Full commit message'),
  authorName: z.string().describe('Name of the commit author'),
  authorEmail: z.string().email().describe('Email of the commit author'),
  authoredDate: z.string().datetime().describe('ISO timestamp of when commit was authored'),
  commitUrl: z.string().url().describe('URL to view commit in GitLab'),
})

/**
 * Pagination metadata
 */
export const paginationSchema = z.object({
  page: z.number().int().positive().describe('Current page number'),
  perPage: z.number().int().positive().describe('Items per page'),
  total: z.number().int().nonnegative().describe('Total number of items'),
  totalPages: z.number().int().nonnegative().describe('Total number of pages'),
})

/**
 * Response for commit history list
 */
export const historyListResponseSchema = z.object({
  commits: z.array(commitInfoSchema),
  pagination: paginationSchema,
})

/**
 * File change within a commit (for history/diff display)
 */
export const commitFileChangeSchema = z.object({
  filePath: z.string().describe('Current file path'),
  oldPath: z.string().describe('Previous file path (for renames)'),
  newPath: z.string().describe('New file path'),
  action: z.enum(['create', 'update', 'delete', 'rename']).describe('Type of change'),
  diff: z.string().optional().describe('Unified diff of changes'),
})

/**
 * Commit statistics
 */
export const commitStatsSchema = z.object({
  additions: z.number().int().nonnegative().describe('Lines added'),
  deletions: z.number().int().nonnegative().describe('Lines deleted'),
  total: z.number().int().nonnegative().describe('Total lines changed'),
})

/**
 * Detailed commit information including diffs
 */
export const commitDetailsSchema = commitInfoSchema.extend({
  stats: commitStatsSchema,
  changedFiles: z.array(commitFileChangeSchema),
})

// ============================================================================
// Type Exports
// ============================================================================

export type CommitInfo = z.infer<typeof commitInfoSchema>
export type Pagination = z.infer<typeof paginationSchema>
export type HistoryListResponse = z.infer<typeof historyListResponseSchema>
export type CommitFileChange = z.infer<typeof commitFileChangeSchema>
export type CommitStats = z.infer<typeof commitStatsSchema>
export type CommitDetails = z.infer<typeof commitDetailsSchema>

// ============================================================================
// JSON Schemas for Fastify/Swagger
// ============================================================================

/**
 * Query parameters for history list endpoint
 */
export const historyQueryParamsJsonSchema = {
  type: 'object',
  properties: {
    page: {
      type: 'integer',
      minimum: 1,
      default: 1,
      description: 'Page number for pagination',
    },
    perPage: {
      type: 'integer',
      minimum: 1,
      maximum: 100,
      default: 20,
      description: 'Number of items per page',
    },
    path: {
      type: 'string',
      description: 'Filter commits affecting a specific file path',
    },
    author: {
      type: 'string',
      description: 'Filter commits by author email',
    },
    since: {
      type: 'string',
      format: 'date-time',
      description: 'Only commits after this date (ISO 8601)',
    },
    until: {
      type: 'string',
      format: 'date-time',
      description: 'Only commits before this date (ISO 8601)',
    },
    search: {
      type: 'string',
      description: 'Search term to filter commit messages, titles, or authors',
    },
  },
} as const

/**
 * Path parameters for commit details endpoint
 */
export const commitIdParamsJsonSchema = {
  type: 'object',
  required: ['commitId'],
  properties: {
    commitId: {
      type: 'string',
      description: 'Commit SHA (short or full)',
    },
  },
} as const

/**
 * Path parameters for file history endpoint
 */
export const filePathParamsJsonSchema = {
  type: 'object',
  required: ['filePath'],
  properties: {
    filePath: {
      type: 'string',
      description: 'File path to get history for (URL encoded)',
    },
  },
} as const

/**
 * Response schema for history list
 */
export const historyListResponseJsonSchema = {
  type: 'object',
  required: ['commits', 'pagination'],
  properties: {
    commits: {
      type: 'array',
      items: {
        type: 'object',
        required: [
          'commitId',
          'shortId',
          'title',
          'message',
          'authorName',
          'authorEmail',
          'authoredDate',
          'commitUrl',
        ],
        properties: {
          commitId: { type: 'string', description: 'Full commit SHA' },
          shortId: { type: 'string', description: 'Short commit SHA (7 chars)' },
          title: { type: 'string', description: 'First line of commit message' },
          message: { type: 'string', description: 'Full commit message' },
          authorName: { type: 'string', description: 'Name of the commit author' },
          authorEmail: { type: 'string', description: 'Email of the commit author' },
          authoredDate: {
            type: 'string',
            format: 'date-time',
            description: 'When commit was authored',
          },
          commitUrl: { type: 'string', format: 'uri', description: 'URL to view commit' },
        },
      },
    },
    pagination: {
      type: 'object',
      required: ['page', 'perPage', 'total', 'totalPages'],
      properties: {
        page: { type: 'integer', description: 'Current page number' },
        perPage: { type: 'integer', description: 'Items per page' },
        total: { type: 'integer', description: 'Total number of items' },
        totalPages: { type: 'integer', description: 'Total number of pages' },
      },
    },
  },
} as const

/**
 * Response schema for commit details
 */
export const commitDetailsResponseJsonSchema = {
  type: 'object',
  required: [
    'commitId',
    'shortId',
    'title',
    'message',
    'authorName',
    'authorEmail',
    'authoredDate',
    'commitUrl',
    'stats',
    'changedFiles',
  ],
  properties: {
    commitId: { type: 'string', description: 'Full commit SHA' },
    shortId: { type: 'string', description: 'Short commit SHA (7 chars)' },
    title: { type: 'string', description: 'First line of commit message' },
    message: { type: 'string', description: 'Full commit message' },
    authorName: { type: 'string', description: 'Name of the commit author' },
    authorEmail: { type: 'string', description: 'Email of the commit author' },
    authoredDate: {
      type: 'string',
      format: 'date-time',
      description: 'When commit was authored',
    },
    commitUrl: { type: 'string', format: 'uri', description: 'URL to view commit' },
    stats: {
      type: 'object',
      required: ['additions', 'deletions', 'total'],
      properties: {
        additions: { type: 'integer', description: 'Lines added' },
        deletions: { type: 'integer', description: 'Lines deleted' },
        total: { type: 'integer', description: 'Total lines changed' },
      },
    },
    changedFiles: {
      type: 'array',
      items: {
        type: 'object',
        required: ['filePath', 'oldPath', 'newPath', 'action'],
        properties: {
          filePath: { type: 'string', description: 'Current file path' },
          oldPath: { type: 'string', description: 'Previous file path' },
          newPath: { type: 'string', description: 'New file path' },
          action: {
            type: 'string',
            enum: ['create', 'update', 'delete', 'rename'],
            description: 'Type of change',
          },
          diff: { type: 'string', description: 'Unified diff of changes' },
        },
      },
    },
  },
} as const
