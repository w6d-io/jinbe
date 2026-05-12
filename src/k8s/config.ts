import prisma from '../lib/prisma.js'
import { env } from '../config/env.js'

export interface K8sApiError extends Error {
    response?: {
        statusCode?: number
    }
}

// Default backup tool configuration shared across clusters.
// Image URLs are deployer-specific (private registry) — provide them via
// BACKUP_IMAGE_MONGO / BACKUP_IMAGE_POSTGRES env vars.
const defaultConfig = {
    mongodb: {
        image: env.BACKUP_IMAGE_MONGO ?? '',
        sourceYamlTemplate: `sources:
  mongo:
    enabled: true
    dbNames:
    {{#bases}}
      - {{database}}
    {{/bases}}
`,
    },
    postgresql: {
        image: env.BACKUP_IMAGE_POSTGRES ?? '',
        sourceYamlTemplate: `sources:
  postgres:
    enabled: true
    dbNames:
    {{#bases}}
      - {{database}}
    {{/bases}}
    grant:
    {{#bases}}
      - database: {{database}}
        admin_username: {{adminUsername}}
        username: {{username}}
    {{/bases}}
output:
  gcs:
    enabled: true
`,
    },
}

const dict: {
    [key: string]: { [key: string]: { [key: string]: string } }
} = {
    // Add cluster-specific overrides here if needed
    // All clusters fall back to defaultConfig
}

export async function getSource(
    cluster: string,
    database: string,
    key: string
): Promise<string> {
    // Try cluster-specific config first, then fall back to default
    const clusterConfig = dict[cluster]
    const dbConfig = clusterConfig?.[database] ?? defaultConfig[database as keyof typeof defaultConfig]

    if (!dbConfig) {
        throw new Error(`Database config "${database}" not found`)
    }
    const value = dbConfig[key as keyof typeof dbConfig]
    if (!value) {
        throw new Error(`Key "${key}" not found for database type "${database}"`)
    }
    return value
}

export async function getKubeConfig(name: string): Promise<string> {
    const cluster = await prisma.cluster.findUnique({
        where: { name },
    })

    if (!cluster) {
        throw new Error(`Config "${name}" not found`)
    }

    if (typeof cluster.config !== 'string') {
        throw new Error(`Config "${name}" not found`)
    }

    return cluster.config
}
