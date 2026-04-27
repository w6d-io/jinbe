import { z } from 'zod'

/**
 * Pagination query parameters schema
 * Can be used in any route that needs pagination
 */
export const paginationSchema = z.object({
  page: z
    .string()
    .optional()
    .default('1')
    .transform((val) => parseInt(val, 10))
    .refine((val) => val > 0, { message: 'Page must be greater than 0' }),
  pageSize: z
    .string()
    .optional()
    .default('10')
    .transform((val) => parseInt(val, 10))
    .refine((val) => val > 0 && val <= 100, {
      message: 'Page size must be between 1 and 100',
    }),
})

export type PaginationQuery = z.infer<typeof paginationSchema>

/**
 * Pagination metadata
 */
export interface PaginationMeta {
  page: number
  pageSize: number
  totalItems: number
  totalPages: number
  hasNextPage: boolean
  hasPreviousPage: boolean
}

/**
 * Paginated response wrapper
 */
export interface PaginatedResponse<T> {
  data: T[]
  meta: PaginationMeta
}

/**
 * Calculate skip and take for Prisma queries
 */
export function getPaginationParams(page: number, pageSize: number) {
  return {
    skip: (page - 1) * pageSize,
    take: pageSize,
  }
}

/**
 * Build pagination metadata
 */
export function buildPaginationMeta(
  page: number,
  pageSize: number,
  totalItems: number
): PaginationMeta {
  const totalPages = Math.ceil(totalItems / pageSize)
  
  return {
    page,
    pageSize,
    totalItems,
    totalPages,
    hasNextPage: page < totalPages,
    hasPreviousPage: page > 1,
  }
}

/**
 * Create a paginated response
 */
export function createPaginatedResponse<T>(
  data: T[],
  page: number,
  pageSize: number,
  totalItems: number
): PaginatedResponse<T> {
  return {
    data,
    meta: buildPaginationMeta(page, pageSize, totalItems),
  }
}

/**
 * JSON Schema for Swagger documentation (paginated response)
 */
export function getPaginatedResponseSchema(itemSchema: any) {
  return {
    type: 'object',
    properties: {
      data: {
        type: 'array',
        items: itemSchema,
      },
      meta: {
        type: 'object',
        properties: {
          page: { type: 'number', example: 1 },
          pageSize: { type: 'number', example: 10 },
          totalItems: { type: 'number', example: 42 },
          totalPages: { type: 'number', example: 5 },
          hasNextPage: { type: 'boolean', example: true },
          hasPreviousPage: { type: 'boolean', example: false },
        },
      },
    },
  }
}
