import { z } from 'zod'

/**
 * Backup schemas
 */

export const backupItemSchema = z.object({
  database_type: z.string(),
  name: z.string(),
  admin_username: z.string(),
  username: z.string(),
  filename: z.string(),
  size: z.string().optional(),
})

export const backupCreateItemSchema = backupItemSchema

export const backupCreateSchema = z.object({
  database_type: z.string().min(1, 'Database type is required'),
  date: z.string().or(z.date()).transform((val) => new Date(val)),
  size: z.string().min(1, 'Size is required'),
  backupItems: z.array(backupCreateItemSchema).min(1, 'At least one backup item is required'),
})

export const backupResponseSchema = z.object({
  id: z.string(),
  database_type: z.string(),
  date: z.date(),
  size: z.string(),
  clusterId: z.string(),
  backupItemCount: z.number().optional(),
  Backups: z.array(
    backupItemSchema.extend({
      id: z.string(),
      date: z.date(),
      backupId: z.string(),
    })
  ),
})

export const backupListResponseSchema = z.array(
  backupResponseSchema.omit({ Backups: true }).extend({
    backupItemCount: z.number(),
    Backups: z.array(z.any()).default([]),
  })
)

export const backupQuerySchema = z.object({
  cluster: z.string().optional(),
})

export const backupIdParamSchema = z.object({
  id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid backup ID'),
})

export type BackupItem = z.infer<typeof backupItemSchema>
export type BackupCreateInput = z.infer<typeof backupCreateSchema>
export type BackupResponse = z.infer<typeof backupResponseSchema>
export type BackupQueryParams = z.infer<typeof backupQuerySchema>
