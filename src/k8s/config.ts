import prisma from '../lib/prisma.js'

export interface K8sApiError extends Error {
    response?: {
        statusCode?: number
    }
}

// Default backup tool configuration shared across clusters
const defaultConfig = {
    mongodb: {
        image: 'europe-docker.pkg.dev/k8s-w6d-qa/library/backup-tool/mongo',
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
        image: 'europe-docker.pkg.dev/k8s-w6d-qa/library/backup-tool/postgres',
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
