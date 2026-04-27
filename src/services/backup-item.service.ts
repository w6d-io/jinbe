import { prisma } from '../utils/prisma.js'
import { BackupItemCreateInput, BackupItemUpdateInput } from '../schemas/backup-item.schema.js'

const BACKUP_ITEM_INCLUDE = {
    backup: { select: { id: true, database_type: true, date: true } },
} as const

const BACKUP_ITEM_SELECT_BASE = {
    id: true,
    database_type: true,
    name: true,
    admin_username: true,
    username: true,
    filename: true,
    date: true,
    backupId: true,
} as const

export class BackupItemService {
    async getBackupItems(backupId?: string) {
        return prisma.backupItem.findMany({
            where: backupId ? { backupId } : undefined,
            include: BACKUP_ITEM_INCLUDE,
        })
    }

    async getBackupItemById(id: string) {
        return prisma.backupItem.findUnique({ where: { id }, include: BACKUP_ITEM_INCLUDE })
    }

    async createBackupItem(backupId: string, data: BackupItemCreateInput) {
        return prisma.backupItem.create({
            data: {
                database_type: data.database_type,
                name: data.name,
                admin_username: data.admin_username,
                username: data.username,
                filename: data.filename,
                date: data.date,
                backupId,
            },
            include: BACKUP_ITEM_INCLUDE,
        })
    }

    async updateBackupItem(id: string, data: BackupItemUpdateInput) {
        return prisma.backupItem.update({
            where: { id },
            data: {
                database_type: data.database_type,
                name: data.name,
                admin_username: data.admin_username,
                username: data.username,
                filename: data.filename,
                date: data.date,
            },
            include: BACKUP_ITEM_INCLUDE,
        })
    }

    async deleteBackupItem(id: string) {
        return prisma.backupItem.delete({ where: { id }, select: BACKUP_ITEM_SELECT_BASE })
    }
}

export const backupItemService = new BackupItemService()
