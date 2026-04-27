import { PrismaClient } from '@prisma/client'

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
  console.log('🔌 Testing MongoDB connection...')

  try {
    // Attempt to connect and run a simple command
    await prisma.$connect()
    // Run a simple query to verify the connection is working
    await prisma.$runCommandRaw({ ping: 1 })

    const duration = Date.now() - startTime
    console.log(`✅ MongoDB connection successful (${duration}ms)`)
  } catch (error) {
    const duration = Date.now() - startTime
    console.error(`❌ MongoDB connection failed after ${duration}ms`)

    if (error instanceof Error) {
      console.error(`   Error: ${error.message}`)

      // Provide helpful debugging hints based on common errors
      if (error.message.includes('ECONNREFUSED')) {
        console.error('   Hint: MongoDB server may not be running')
      } else if (error.message.includes('authentication failed')) {
        console.error('   Hint: Check your MongoDB credentials in DATABASE_URL')
      } else if (error.message.includes('ENOTFOUND')) {
        console.error('   Hint: MongoDB host not found - check your connection string')
      } else if (error.message.includes('timed out')) {
        console.error('   Hint: Connection timed out - check network/firewall settings')
      }
    }

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
  console.log('🔧 Disabling MongoDB schema validation (Prisma handles integrity)...')

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
        console.log(`   ⏭️  ${collection}: collection doesn't exist yet, skipping`)
      } else {
        console.warn(`   ⚠️  ${collection}: ${message}`)
      }
    }
  }

  console.log('✅ MongoDB schema validation disabled')
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
