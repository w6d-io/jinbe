// lib/prisma.ts
import { PrismaClient } from '@prisma/client'

declare global {
  // eslint-disable-next-line no-var
  var __prisma: PrismaClient | undefined
}

/** Singleton pour éviter d'ouvrir plusieurs connexions en dev */
const prisma = global.__prisma ?? new PrismaClient({
  log: ['warn', 'error'],
})

if (process.env.NODE_ENV !== 'production') {
  global.__prisma = prisma
}

export default prisma
