import { z } from 'zod'

/**
 * Centralized JSON schemas for API responses
 * Eliminates duplication across route files
 */

// ===================
// Common Schemas
// ===================

export const notFoundResponseSchema = {
    type: 'object',
    properties: {
        message: { type: 'string' },
    },
}

export const messageResponseSchema = {
    type: 'object',
    properties: {
        message: { type: 'string' },
    },
}

export const unauthorizedResponseSchema = {
    type: 'object',
    properties: {
        error: { type: 'string', example: 'Unauthorized' },
        message: {
            type: 'string',
            example: 'Valid authentication required. Please provide a valid ory_kratos_session cookie.',
        },
    },
}

export const badRequestResponseSchema = {
    type: 'object',
    properties: {
        error: { type: 'string', example: 'Bad Request' },
        message: { type: 'string' },
    },
}

export const forbiddenResponseSchema = {
    type: 'object',
    properties: {
        error: { type: 'string', example: 'Forbidden' },
        message: { type: 'string' },
    },
}

export const serviceUnavailableResponseSchema = {
    type: 'object',
    properties: {
        error: { type: 'string', example: 'Service Unavailable' },
        message: { type: 'string' },
    },
}

export const conflictResponseSchema = {
    type: 'object',
    properties: {
        error: { type: 'string', example: 'Conflict' },
        message: { type: 'string' },
    },
}

// ===================
// Common Param Schemas (Zod)
// ===================

export const objectIdParamSchema = z.object({
    id: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid ObjectId'),
})

export const clusterIdParamSchema = z.object({
    clusterId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid cluster ID'),
})

export const databaseIdParamSchema = z.object({
    databaseId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid database ID'),
})

export const backupIdParamSchema = z.object({
    backupId: z.string().regex(/^[0-9a-fA-F]{24}$/, 'Invalid backup ID'),
})

// ===================
// Cluster Schemas
// ===================

const databaseInClusterSchema = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        type: { type: 'string' },
        host: { type: 'string' },
        port: { type: 'number' },
        username: { type: 'string' },
    },
}

const clusterCountSchema = {
    type: 'object',
    properties: {
        databases: { type: 'number' },
        backups: { type: 'number' },
    },
}

export const clusterItemSchema = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        name: { type: 'string' },
        config: { type: 'string' },
        createdAt: { type: 'string', format: 'date-time' },
        updatedAt: { type: 'string', format: 'date-time' },
        databases: {
            type: 'array',
            nullable: true,
            items: databaseInClusterSchema,
        },
        _count: clusterCountSchema,
    },
}

export const clusterBaseSchema = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        name: { type: 'string' },
        config: { type: 'string' },
        createdAt: { type: 'string', format: 'date-time' },
        updatedAt: { type: 'string', format: 'date-time' },
    },
}

export const clusterRefSchema = {
    type: 'object',
    nullable: true,
    properties: {
        id: { type: 'string' },
        name: { type: 'string' },
    },
}

// ===================
// Database Schemas
// ===================

const databaseApiInDatabaseSchema = {
    type: 'object',
    nullable: true,
    properties: {
        id: { type: 'string' },
        address: { type: 'string' },
        api_key: { type: 'string' },
    },
}

export const databaseItemSchema = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        type: { type: 'string', enum: ['postgresql', 'mongodb', 'influxdb'] },
        host: { type: 'string' },
        port: { type: 'number' },
        username: { type: 'string' },
        clusterId: { type: 'string' },
        cluster: clusterRefSchema,
        api: databaseApiInDatabaseSchema,
    },
}

export const databaseBaseSchema = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        type: { type: 'string', enum: ['postgresql', 'mongodb', 'influxdb'] },
        host: { type: 'string' },
        port: { type: 'number' },
        username: { type: 'string' },
        clusterId: { type: 'string' },
    },
}

export const databaseRefSchema = {
    type: 'object',
    nullable: true,
    properties: {
        id: { type: 'string' },
        type: { type: 'string', enum: ['postgresql', 'mongodb', 'influxdb'] },
        host: { type: 'string' },
        port: { type: 'number' },
    },
}

// ===================
// DatabaseAPI Schemas
// ===================

export const databaseAPIItemSchema = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        address: { type: 'string' },
        api_key: { type: 'string' },
        databaseId: { type: 'string' },
        database: databaseRefSchema,
    },
}

export const databaseAPIBaseSchema = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        address: { type: 'string' },
        api_key: { type: 'string' },
        databaseId: { type: 'string' },
    },
}

// ===================
// BackupItem Schemas
// ===================

const backupRefSchema = {
    type: 'object',
    nullable: true,
    properties: {
        id: { type: 'string' },
        database_type: { type: 'string' },
        date: { type: 'string', format: 'date-time' },
    },
}

export const backupItemSchema = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        database_type: { type: 'string' },
        name: { type: 'string' },
        admin_username: { type: 'string' },
        username: { type: 'string' },
        filename: { type: 'string' },
        date: { type: 'string', format: 'date-time' },
        backupId: { type: 'string' },
        backup: backupRefSchema,
    },
}

export const backupItemBaseSchema = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        database_type: { type: 'string' },
        name: { type: 'string' },
        admin_username: { type: 'string' },
        username: { type: 'string' },
        filename: { type: 'string' },
        date: { type: 'string', format: 'date-time' },
        backupId: { type: 'string' },
    },
}

// ===================
// Backup Schemas
// ===================

// Alias: same shape used both standalone and embedded in backup
export const backupItemInBackupSchema = backupItemBaseSchema

export const backupFullSchema = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        database_type: { type: 'string' },
        date: { type: 'string', format: 'date-time' },
        size: { type: 'string' },
        clusterId: { type: 'string' },
        backupItemCount: { type: 'number' },
        cluster: clusterRefSchema,
        BackupItem: {
            type: 'array',
            items: backupItemInBackupSchema,
        },
    },
}

export const backupBaseSchema = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        database_type: { type: 'string' },
        date: { type: 'string', format: 'date-time' },
        size: { type: 'string' },
        clusterId: { type: 'string' },
        backupItemCount: { type: 'number' },
    },
}
