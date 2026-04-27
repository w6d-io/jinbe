import { z } from 'zod'
import { databaseSchema } from './database.schema.js'

/**
 * Cluster schemas
 */

export const clusterCreateSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  config: z.string().min(1, 'Config is required'),
  databases: z.array(databaseSchema.omit({ id: true, clusterId: true })).optional(),
})

export const clusterUpdateSchema = z.object({
  name: z.string().min(1).optional(),
  config: z.string().optional(),
  databases: z.array(databaseSchema.omit({ clusterId: true })).optional(),
})

export const clusterResponseSchema = z.object({
  id: z.string(),
  name: z.string(),
  config: z.string().optional(),
  createdAt: z.date(),
  updatedAt: z.date(),
  databases: z.array(databaseSchema).optional(),
})

export const clusterListResponseSchema = z.array(clusterResponseSchema)

export const clusterQuerySchema = z.object({
  withConfig: z
    .string()
    .transform((val) => val === 'true')
    .optional(),
  withDatabase: z
    .string()
    .transform((val) => val === 'true')
    .optional(),
  page: z
    .string()
    .optional()
    .transform((val) => (val ? parseInt(val, 10) : undefined))
    .refine((val) => val === undefined || val > 0, { message: 'Page must be greater than 0' }),
  pageSize: z
    .string()
    .optional()
    .transform((val) => (val ? parseInt(val, 10) : undefined))
    .refine((val) => val === undefined || (val > 0 && val <= 100), {
      message: 'Page size must be between 1 and 100',
    }),
})

export const clusterIdParamSchema = z.object({
  id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid cluster ID'),
})

export type ClusterCreateInput = z.infer<typeof clusterCreateSchema>
export type ClusterUpdateInput = z.infer<typeof clusterUpdateSchema>
export type ClusterResponse = z.infer<typeof clusterResponseSchema>
export type ClusterQueryParams = z.infer<typeof clusterQuerySchema>
