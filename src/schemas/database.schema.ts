import { z } from 'zod'

/**
 * Database-related schemas
 */

export const roleSchema = z.object({
  username: z.string(),
  adminUsername: z.string(),
})

export const databaseListItemSchema = z.object({
  roles: z.array(roleSchema),
  size: z.number(),
})

export const databaseListSchema = z.record(z.string(), databaseListItemSchema)

export const databaseAPISchema = z.object({
  address: z.string().url('Invalid API address'),
  api_key: z.string().min(1, 'API key is required'),
})

export const dbTypeSchema = z.enum(['postgresql', 'mongodb', 'influxdb'])

export const databaseSchema = z.object({
  id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid ObjectId'),
  type: dbTypeSchema,
  host: z.string().min(1, 'Host is required'),
  port: z.number().positive('Port must be positive'),
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
  clusterId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid ObjectId').optional(),
  api: databaseAPISchema.optional(),
})

export const databaseCreateSchema = databaseSchema.omit({ id: true, clusterId: true })

export const databaseUpdateSchema = databaseSchema.partial().omit({ id: true })

export const databaseQuerySchema = z.object({
  cluster: z.string().min(1, 'Cluster name is required'),
  database: z.string().optional(),
})

export const databaseSelectedSchema = roleSchema.extend({
  database: z.string(),
  size: z.number(),
})

export type RoleType = z.infer<typeof roleSchema>
export type DatabaseListType = z.infer<typeof databaseListSchema>
export type DatabaseAPIType = z.infer<typeof databaseAPISchema>
export type DBType = z.infer<typeof dbTypeSchema>
export type DatabaseType = z.infer<typeof databaseSchema>
export type DatabaseCreateInput = z.infer<typeof databaseCreateSchema>
export type DatabaseUpdateInput = z.infer<typeof databaseUpdateSchema>
export type DatabaseQueryParams = z.infer<typeof databaseQuerySchema>
export type DatabaseSelected = z.infer<typeof databaseSelectedSchema>
