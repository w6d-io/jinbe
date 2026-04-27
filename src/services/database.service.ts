import { prisma } from '../utils/prisma.js'
import { DatabaseCreateInput, DatabaseUpdateInput, DatabaseListType } from '../schemas/database.schema.js'
import { getPaginationParams } from '../utils/pagination.js'
import { getDatabasesAndRoles } from '../database/postgresql.js'
import { encryptPassword } from '../utils/encryption.js'

// Shared select shapes to avoid repetition
const DB_SELECT_WITH_RELATIONS = {
    id: true,
    type: true,
    host: true,
    port: true,
    username: true,
    clusterId: true,
    cluster: { select: { id: true, name: true } },
    api: { select: { id: true, address: true, api_key: true } },
} as const

const DB_SELECT_WITH_API = {
    id: true,
    type: true,
    host: true,
    port: true,
    username: true,
    clusterId: true,
    api: { select: { id: true, address: true, api_key: true } },
} as const

const DB_SELECT_BASE = {
    id: true,
    type: true,
    host: true,
    port: true,
    username: true,
    clusterId: true,
} as const

export class DatabaseService {
    /**
     * Get all databases with optional pagination
     */
    async getDatabases(clusterId?: string, page?: number, pageSize?: number) {
        const where = clusterId ? { clusterId } : undefined

        if (page && pageSize) {
            const { skip, take } = getPaginationParams(page, pageSize)
            const [databases, total] = await Promise.all([
                prisma.database.findMany({ where, select: DB_SELECT_WITH_RELATIONS, skip, take }),
                prisma.database.count({ where }),
            ])
            return { data: databases, total }
        }

        const databases = await prisma.database.findMany({ where, select: DB_SELECT_WITH_RELATIONS })
        return { data: databases, total: databases.length }
    }

    /**
     * Get database by ID
     */
    async getDatabaseById(id: string) {
        return prisma.database.findUnique({ where: { id }, select: DB_SELECT_WITH_RELATIONS })
    }

    /**
     * Create new database
     */
    async createDatabase(clusterId: string, databaseData: DatabaseCreateInput) {
        return prisma.database.create({
            data: {
                type: databaseData.type,
                host: databaseData.host,
                port: databaseData.port,
                username: databaseData.username,
                password: encryptPassword(databaseData.password),
                clusterId,
                api: databaseData.api ? { create: databaseData.api } : undefined,
            },
            select: DB_SELECT_WITH_API,
        })
    }

    /**
     * Update database by ID
     */
    async updateDatabase(id: string, databaseData: DatabaseUpdateInput) {
        return prisma.database.update({
            where: { id },
            data: {
                type: databaseData.type,
                host: databaseData.host,
                port: databaseData.port,
                username: databaseData.username,
                password: databaseData.password ? encryptPassword(databaseData.password) : undefined,
                api: databaseData.api
                    ? { upsert: { create: databaseData.api, update: databaseData.api } }
                    : undefined,
            },
            select: DB_SELECT_WITH_API,
        })
    }

    /**
     * Delete database by ID
     * Cascade deletes associated DatabaseAPI first
     */
    async deleteDatabase(id: string) {
        await prisma.databaseAPI.deleteMany({ where: { databaseId: id } })
        return prisma.database.delete({ where: { id }, select: DB_SELECT_BASE })
    }

    /**
     * List databases from the actual database server
     * Fetches all databases with their roles and sizes from the PostgreSQL/MongoDB server
     * Uses the db-agent API if configured, otherwise connects directly
     */
    async listDatabasesFromServer(id: string): Promise<DatabaseListType> {
        const database = await prisma.database.findUnique({
            where: { id },
            select: {
                id: true,
                type: true,
                host: true,
                port: true,
                username: true,
                password: true,
                api: {
                    select: {
                        id: true,
                        address: true,
                        api_key: true,
                    },
                },
            },
        })

        if (!database) {
            throw new Error('Database configuration not found')
        }

        // Build the database config object expected by getDatabasesAndRoles
        const databaseConfig = {
            id: database.id,
            type: database.type,
            host: database.host,
            port: database.port,
            username: database.username,
            password: database.password,
            api: database.api ? {
                id: database.api.id,
                address: database.api.address,
                api_key: database.api.api_key,
            } : undefined,
        }

        return getDatabasesAndRoles(databaseConfig)
    }
}

export const databaseService = new DatabaseService()
