import { z } from 'zod'

/**
 * BackupItem schemas
 */

export const backupItemCreateSchema = z.object({
    database_type: z.string().min(1, 'Database type is required'),
    name: z.string().min(1, 'Name is required'),
    admin_username: z.string().min(1, 'Admin username is required'),
    username: z.string().min(1, 'Username is required'),
    filename: z.string().min(1, 'Filename is required'),
    date: z.string().or(z.date()).transform((val) => new Date(val)),
})

export const backupItemUpdateSchema = backupItemCreateSchema.partial()

export const backupItemIdParamSchema = z.object({
    id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid backup item ID'),
})

export type BackupItemCreateInput = z.infer<typeof backupItemCreateSchema>
export type BackupItemUpdateInput = z.infer<typeof backupItemUpdateSchema>
