import { Pool, PoolClient } from 'pg'
import { DatabaseType, DatabaseAPIType, DatabaseListType } from '../schemas/database.schema.js'
import { decryptPassword } from '../utils/encryption.js'

/**
 * Fetches databases and roles from PostgreSQL directly
 */
async function getDatabaseFromLocal(
  database: DatabaseType
): Promise<DatabaseListType> {
  const pool = new Pool({
    user: database.username,
    host: database.host,
    database: 'postgres',
    password: decryptPassword(database.password),
    port: database.port,
  })

  const client: PoolClient = await pool.connect()

  try {
    // Query to get all databases and their owners
    const databaseQuery = `
      SELECT 
        d.datname AS database,
        r.rolname AS username,
        pg_catalog.pg_get_userbyid(d.datdba) AS admin_username,
        pg_database_size(d.datname) AS size
      FROM pg_database d
      CROSS JOIN pg_roles r
      WHERE d.datistemplate = false 
        AND r.rolcanlogin = true
        AND has_database_privilege(r.rolname, d.datname, 'CREATE')
        AND r.rolname != pg_catalog.pg_get_userbyid(d.datdba)
      ORDER BY d.datname, r.rolname;
    `

    const result = await client.query(databaseQuery)

    const groupedDatabases = result.rows.reduce<DatabaseListType>(
      (acc: DatabaseListType, curr) => {
        const { database, username, admin_username, size } = curr

        if (!acc[database]) {
          acc[database] = {
            roles: [],
            size: size,
          }
        }

        acc[database].roles.push({
          username,
          adminUsername: admin_username,
        })

        return acc
      },
      {}
    )

    return groupedDatabases as DatabaseListType
  } catch (error) {
    // Specific error handling for different PostgreSQL errors
    if (error instanceof Error) {
      switch (true) {
        case error.message.includes('authentication failed'):
          throw new Error(
            'Database authentication failed - Invalid credentials'
          )
        case error.message.includes('timeout'):
          throw new Error(
            'Database connection timeout - Server may be down or unreachable'
          )
        case error.message.includes('connection refused'):
          throw new Error(
            'Database connection refused - Check host and port configuration'
          )
        default:
          throw new Error(`Database connection error: ${error.message}`)
      }
    }
    throw error
  } finally {
    client.release()
    await pool.end()
  }
}

/**
 * Fetches databases and roles from remote API
 */
export async function getDatabasesFromAPI(
  database: DatabaseType,
  api: DatabaseAPIType
): Promise<DatabaseListType> {
  try {
    const response = await fetch(`${api.address}/api/database`, {
      method: 'POST',
      body: JSON.stringify(database),
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': decryptPassword(api.api_key),
      },
    })

    if (response.ok) {
      return (await response.json()) as Promise<DatabaseListType>
    }

    throw new Error(`API request failed with status ${response.status}`)
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to fetch databases from API: ${error.message}`)
    }
    throw error
  }
}

/**
 * Validates if an API configuration is valid
 */
function isValidDatabaseAPI(api: unknown): api is DatabaseAPIType {
  if (!api || typeof api !== 'object') return false
  const apiObj = api as DatabaseAPIType
  return !!apiObj.api_key && apiObj.api_key.length > 0 && !!apiObj.address && apiObj.address.length > 0
}

/**
 * Main function to get databases and roles
 * Automatically chooses between API and direct connection
 */
export async function getDatabasesAndRoles(
  database: DatabaseType
): Promise<DatabaseListType> {
  if (database.api && isValidDatabaseAPI(database.api)) {
    return getDatabasesFromAPI(database, database.api)
  }
  return getDatabaseFromLocal(database)
}
