import { prisma } from '../utils/prisma.js'
import { BackupCreateInput } from '../schemas/backup.schema.js'

export class BackupService {
    /**
     * Get all backups
     */
    async getBackups(clusterId?: string) {
        const backups = await prisma.backup.findMany({
            where: clusterId ? { clusterId } : undefined,
            include: {
                BackupItem: true,
                cluster: {
                    select: {
                        id: true,
                        name: true,
                    },
                },
            },
        })

        return backups.map((backup) => {
            return { ...backup, backupItemCount: backup.BackupItem.length }
        })
    }

    /**
     * Get backup by ID
     */
    async getBackupById(id: string) {
        const backup = await prisma.backup.findUnique({
            where: { id },
            include: {
                BackupItem: true,
                cluster: {
                    select: {
                        id: true,
                        name: true,
                    },
                },
            },
        })

        if (!backup) {
            return null
        }

        return { ...backup, backupItemCount: backup.BackupItem.length }
    }

    /**
     * Create new backup
     */
    async createBackup(clusterId: string, backupData: BackupCreateInput) {
        const backup = await prisma.backup.create({
            data: {
                database_type: backupData.database_type,
                date: backupData.date,
                size: backupData.size,
                clusterId,
                BackupItem: {
                    create: backupData.backupItems.map((item) => ({
                        ...item,
                        date: backupData.date,
                    })),
                },
            },
            include: {
                BackupItem: true,
            },
        })

        return { ...backup, backupItemCount: backup.BackupItem.length }
    }

    /**
     * Delete backup by ID
     */
    async deleteBackup(id: string) {
        // First, delete all related BackupItems
        await prisma.backupItem.deleteMany({
            where: { backupId: id },
        })

        // Then delete the backup
        const backup = await prisma.backup.delete({
            where: { id },
            select: {
                id: true,
                database_type: true,
                date: true,
                size: true,
                clusterId: true,
            },
        })
        return backup
    }
}

export const backupService = new BackupService()
