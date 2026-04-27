import { z } from 'zod'

/**
 * DatabaseAPI schemas
 */

export const databaseAPICreateSchema = z.object({
    address: z.string().url('Invalid API address'),
    api_key: z.string().min(1, 'API key is required'),
})

export const databaseAPIUpdateSchema = databaseAPICreateSchema.partial()

export const databaseAPIIdParamSchema = z.object({
    id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid database API ID'),
})

export type DatabaseAPICreateInput = z.infer<typeof databaseAPICreateSchema>
export type DatabaseAPIUpdateInput = z.infer<typeof databaseAPIUpdateSchema>
