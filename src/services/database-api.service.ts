import { prisma } from '../utils/prisma.js'
import { DatabaseAPICreateInput, DatabaseAPIUpdateInput } from '../schemas/database-api.schema.js'

const DB_API_INCLUDE = {
    database: { select: { id: true, type: true, host: true, port: true } },
} as const

const DB_API_SELECT_BASE = {
    id: true,
    address: true,
    api_key: true,
    databaseId: true,
} as const

export class DatabaseAPIService {
    async getDatabaseAPIs() {
        return prisma.databaseAPI.findMany({ include: DB_API_INCLUDE })
    }

    async getDatabaseAPIById(id: string) {
        return prisma.databaseAPI.findUnique({ where: { id }, include: DB_API_INCLUDE })
    }

    async getDatabaseAPIByDatabaseId(databaseId: string) {
        return prisma.databaseAPI.findUnique({ where: { databaseId }, include: DB_API_INCLUDE })
    }

    async createDatabaseAPI(databaseId: string, data: DatabaseAPICreateInput) {
        return prisma.databaseAPI.create({
            data: { address: data.address, api_key: data.api_key, databaseId },
            include: DB_API_INCLUDE,
        })
    }

    async updateDatabaseAPI(id: string, data: DatabaseAPIUpdateInput) {
        return prisma.databaseAPI.update({
            where: { id },
            data: { address: data.address, api_key: data.api_key },
            include: DB_API_INCLUDE,
        })
    }

    async deleteDatabaseAPI(id: string) {
        return prisma.databaseAPI.delete({ where: { id }, select: DB_API_SELECT_BASE })
    }
}

export const databaseAPIService = new DatabaseAPIService()
