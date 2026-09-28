import { PrismaClient } from '@prisma/client'
import { componentLogger } from '../telemetry/logger.js'

const log = () => componentLogger('mongodb')

/**
 * Prisma Client singleton
 * Maintains single instance across the application
 */
const prismaClientSingleton = () => {
  return new PrismaClient({
    log:
      process.env.NODE_ENV === 'development'
        ? ['query', 'error', 'warn']
        : ['error'],
  })
}

/**
 * Test MongoDB connection
 * Call this before starting the server to verify database connectivity
 */
export async function testDatabaseConnection(): Promise<void> {
  const startTime = Date.now()

  try {
    // Attempt to connect and run a simple command
    await prisma.$connect()
    // Run a simple query to verify the connection is working
    await prisma.$runCommandRaw({ ping: 1 })

    const duration = Date.now() - startTime
    log().info({ durationMs: duration }, 'MongoDB connection successful')
  } catch (error) {
    const duration = Date.now() - startTime
    const message = error instanceof Error ? error.message : String(error)
    // Provide helpful debugging hints based on common errors
    const hint = message.includes('ECONNREFUSED') ? 'MongoDB server may not be running'
      : message.includes('authentication failed') ? 'Check your MongoDB credentials in DATABASE_URL'
      : message.includes('ENOTFOUND') ? 'MongoDB host not found - check your connection string'
      : message.includes('timed out') ? 'Connection timed out - check network/firewall settings'
      : undefined
    log().error({ durationMs: duration, reason: message, ...(hint ? { hint } : {}) }, 'MongoDB connection failed')

    throw error
  }
}

/**
 * Disable MongoDB schema validation on collections
 * Prisma handles data integrity at the application level
 * MongoDB validators can conflict with Prisma's internal fields and BSON types
 */
const collectionsToDisableValidation = [
  'Database',
  'DatabaseAPI',
  'Cluster',
  'Backup',
  'BackupItem',
]

/**
 * Disable MongoDB schema validation on startup
 * This prevents conflicts between MongoDB validators and Prisma
 */
export async function applyMongoValidation(): Promise<void> {

  for (const collection of collectionsToDisableValidation) {
    try {
      await prisma.$runCommandRaw({
        collMod: collection,
        validator: {},
        validationLevel: 'off',
      })
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error)
      // Check if collection doesn't exist yet (MongoDB error: NamespaceNotFound)
      const isNamespaceNotFound =
        message.includes('NamespaceNotFound') ||
        message.includes('ns does not exist') ||
        message.includes('ns not found')
      if (isNamespaceNotFound) {
        log().debug({ collection }, "collection doesn't exist yet, schema validation not changed")
      } else {
        log().warn({ collection, reason: message }, 'could not disable schema validation')
      }
    }
  }

  log().info('MongoDB schema validation disabled (Prisma handles integrity)')
}

declare global {
  // eslint-disable-next-line no-var
  var prisma: PrismaClient | undefined
}

export const prisma = globalThis.prisma ?? prismaClientSingleton()

if (process.env.NODE_ENV !== 'production') {
  globalThis.prisma = prisma
}

// Graceful shutdown
process.on('beforeExit', async () => {
  await prisma.$disconnect()
})
