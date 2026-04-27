# Plan de Migration: Jobs K8s Backup/Restore

## Objectif
Migrer les fonctionnalités de création de jobs Kubernetes backup/restore depuis Kuma vers Jinbe-API.

---

## Phase 1: Dépendances

### 1.1 Ajouter les dépendances npm manquantes

```bash
pnpm add @kubernetes/client-node mustache moment
pnpm add -D @types/mustache
```

| Package | Version Kuma | Usage |
|---------|--------------|-------|
| `@kubernetes/client-node` | ^0.19.0 | Client K8s API |
| `mustache` | ^4.2.0 | Templating source.yaml |
| `moment` | ^2.29.4 | Formatage dates/âge jobs |

---

## Phase 2: Création des fichiers K8s

### 2.1 Créer `src/k8s/template.ts`

**Contenu à migrer depuis:** `kuma/src/k8s/template.ts`

Templates K8s Job pour:
- `jobBackupPostgresTemplate`
- `jobRestorePostgresTemplate`
- `jobBackupMongoTemplate`
- `jobRestoreMongoTemplate`
- `sourceTemplate` (ConfigMap)

**Adaptations nécessaires:**
- Convertir en ESM (`export` au lieu de `module.exports`)
- Ajouter l'extension `.js` aux imports

---

### 2.2 Créer `src/k8s/config.ts`

**Contenu à migrer depuis:** `kuma/src/k8s/config.ts`

```typescript
// Structure à implémenter
export interface K8sApiError extends Error {
    response?: { statusCode?: number }
}

// Configuration par cluster/database_type
const sourceConfigs = {
    qualif: {
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
    },
}

export async function getSource(cluster: string, database: string, key: string): Promise<string>
export async function getKubeConfig(name: string): Promise<string>
```

**⚠️ TODO:** Rendre la config dynamique (base de données ou env vars au lieu de hardcodé)

---

### 2.3 Créer `src/k8s/configmap.ts`

**Contenu à migrer depuis:** `kuma/src/k8s/configmap.ts`

```typescript
export async function createOrReplaceConfigMap(
    cluster: string,
    namespace: string,
    manifest: V1ConfigMap
): Promise<boolean>
```

---

### 2.4 Créer `src/k8s/job.ts`

**Contenu à migrer depuis:** `kuma/src/k8s/job.ts`

Fonctions à implémenter:
```typescript
// Création de job backup/restore
export async function createJob(
    database_type: string,
    action: 'backup' | 'restore',
    cluster: string,
    date: Date,
    bases: DatabaseSelected[]
): Promise<true | string>

// Liste des jobs
export async function getJobsInfo(
    namespace: string,
    cluster: string
): Promise<JobInfo[]>

// Pods de backup (optionnel)
export async function getBackupPods(
    namespace: string,
    cluster: string
): Promise<V1Pod[]>
```

**Adaptations nécessaires:**
- Retirer `'use server'` et `import 'server-only'` (Next.js specific)
- Convertir en ESM
- Adapter les imports Prisma pour Fastify

---

## Phase 3: Schémas Zod

### 3.1 Mettre à jour `src/schemas/database.schema.ts`

Ajouter le type `DatabaseSelected`:
```typescript
export const databaseSelectedSchema = z.object({
    database: z.string(),
    size: z.number(),
    username: z.string(),
    adminUsername: z.string(),
})

export type DatabaseSelected = z.infer<typeof databaseSelectedSchema>
```

---

### 3.2 Créer `src/schemas/job.schema.ts`

```typescript
import { z } from 'zod'

export const jobInfoSchema = z.object({
    database_type: z.string(),
    name: z.string(),
    timestamp: z.string(),
    status: z.enum(['pending', 'running', 'completed', 'failed', 'Unknown']),
    age: z.string(),
    namespace: z.string(),
    creationTimestamp: z.coerce.date(),
})

export type JobInfo = z.infer<typeof jobInfoSchema>

export const createJobRequestSchema = z.object({
    database_type: z.enum(['postgresql', 'mongodb']),
    action: z.enum(['backup', 'restore']),
    cluster: z.string(),
    date: z.coerce.date(),
    bases: z.array(z.object({
        database: z.string(),
        size: z.number().optional().default(0),
        username: z.string(),
        adminUsername: z.string(),
    })),
})

export type CreateJobRequest = z.infer<typeof createJobRequestSchema>
```

---

## Phase 4: Services

### 4.1 Créer `src/services/job.service.ts`

```typescript
import { createJob, getJobsInfo, getBackupPods } from '../k8s/job.js'
import { CreateJobRequest, JobInfo } from '../schemas/job.schema.js'

export class JobService {
    async createBackupJob(clusterId: string, data: CreateJobRequest): Promise<true | string>
    async createRestoreJob(clusterId: string, data: CreateJobRequest): Promise<true | string>
    async getJobs(cluster: string, namespace?: string): Promise<JobInfo[]>
    async getJobPods(cluster: string, namespace?: string): Promise<any[]>
}

export const jobService = new JobService()
```

---

### 4.2 Mettre à jour `src/services/database.service.ts`

Ajouter la méthode pour lister les databases PostgreSQL:
```typescript
import { getDatabasesAndRoles } from '../database/postgresql.js'

// Dans DatabaseService
async listDatabasesFromServer(databaseId: string): Promise<DatabaseListType> {
    const database = await this.getDatabaseById(databaseId)
    if (!database) throw new Error('Database config not found')
    return getDatabasesAndRoles(database)
}
```

---

## Phase 5: Controllers

### 5.1 Créer `src/controllers/job.controller.ts`

```typescript
import { FastifyRequest, FastifyReply } from 'fastify'
import { jobService } from '../services/job.service.js'
import { CreateJobRequest } from '../schemas/job.schema.js'

export class JobController {
    // POST /api/clusters/:clusterId/jobs
    async createJob(
        request: FastifyRequest<{ 
            Params: { clusterId: string }
            Body: CreateJobRequest 
        }>,
        reply: FastifyReply
    )

    // GET /api/clusters/:clusterId/jobs
    async getJobs(
        request: FastifyRequest<{
            Params: { clusterId: string }
            Querystring: { namespace?: string }
        }>,
        reply: FastifyReply
    )

    // GET /api/clusters/:clusterId/jobs/pods
    async getJobPods(
        request: FastifyRequest<{
            Params: { clusterId: string }
            Querystring: { namespace?: string }
        }>,
        reply: FastifyReply
    )
}

export const jobController = new JobController()
```

---

### 5.2 Mettre à jour `src/controllers/database.controller.ts`

Ajouter endpoint pour lister les DBs depuis PostgreSQL:
```typescript
// GET /api/databases/:id/list
async listDatabasesFromServer(
    request: FastifyRequest<{ Params: { id: string } }>,
    reply: FastifyReply
) {
    const databases = await databaseService.listDatabasesFromServer(request.params.id)
    return reply.send(databases)
}
```

---

## Phase 6: Routes

### 6.1 Créer `src/routes/job.routes.ts`

```typescript
import { FastifyInstance } from 'fastify'
import { jobController } from '../controllers/job.controller.js'

export async function jobRoutes(fastify: FastifyInstance) {
    // Créer un job backup/restore
    fastify.post(
        '/clusters/:clusterId/jobs',
        {
            schema: {
                description: 'Create a backup or restore job',
                tags: ['jobs'],
                params: { clusterId: { type: 'string' } },
                body: {
                    type: 'object',
                    required: ['database_type', 'action', 'date', 'bases'],
                    properties: {
                        database_type: { type: 'string', enum: ['postgresql', 'mongodb'] },
                        action: { type: 'string', enum: ['backup', 'restore'] },
                        date: { type: 'string', format: 'date-time' },
                        bases: {
                            type: 'array',
                            items: {
                                type: 'object',
                                properties: {
                                    database: { type: 'string' },
                                    size: { type: 'number' },
                                    username: { type: 'string' },
                                    adminUsername: { type: 'string' },
                                },
                            },
                        },
                    },
                },
            },
        },
        jobController.createJob.bind(jobController)
    )

    // Lister les jobs
    fastify.get(
        '/clusters/:clusterId/jobs',
        {
            schema: {
                description: 'List jobs for a cluster',
                tags: ['jobs'],
                params: { clusterId: { type: 'string' } },
                querystring: {
                    type: 'object',
                    properties: {
                        namespace: { type: 'string', default: 'default' },
                    },
                },
            },
        },
        jobController.getJobs.bind(jobController)
    )
}
```

---

### 6.2 Mettre à jour `src/routes/database.routes.ts`

Ajouter la route pour lister les databases depuis PostgreSQL:
```typescript
// GET /databases/:id/list - Liste les DBs depuis le serveur PostgreSQL
fastify.get(
    '/:id/list',
    {
        schema: {
            description: 'List databases and roles from PostgreSQL server',
            tags: ['databases'],
            params: objectIdParamSchema,
            response: {
                200: {
                    type: 'object',
                    additionalProperties: {
                        type: 'object',
                        properties: {
                            roles: {
                                type: 'array',
                                items: {
                                    type: 'object',
                                    properties: {
                                        username: { type: 'string' },
                                        adminUsername: { type: 'string' },
                                    },
                                },
                            },
                            size: { type: 'number' },
                        },
                    },
                },
            },
        },
    },
    databaseController.listDatabasesFromServer.bind(databaseController)
)
```

---

### 6.3 Mettre à jour `src/server.ts`

Enregistrer les nouvelles routes:
```typescript
import { jobRoutes } from './routes/job.routes.js'

// Dans la fonction de démarrage
fastify.register(jobRoutes, { prefix: '/api' })
```

---

## Phase 7: Tests

### 7.1 Créer `src/__tests__/job.test.ts`

Tests unitaires pour:
- Création de job backup PostgreSQL
- Création de job restore PostgreSQL
- Création de job backup MongoDB
- Création de job restore MongoDB
- Liste des jobs
- Gestion des erreurs

### 7.2 Créer `src/__tests__/database-list.test.ts`

Tests pour:
- Listing databases depuis PostgreSQL
- Listing via API externe
- Gestion des erreurs de connexion

---

## Phase 8: Documentation

### 8.1 Mettre à jour le README.md

Ajouter la documentation des nouveaux endpoints:
- `POST /api/clusters/:clusterId/jobs`
- `GET /api/clusters/:clusterId/jobs`
- `GET /api/databases/:id/list`

### 8.2 Mettre à jour Swagger

Les schémas dans les routes seront automatiquement ajoutés à Swagger.

---

## Résumé des fichiers à créer/modifier

### Nouveaux fichiers (8)
| Fichier | Description |
|---------|-------------|
| `src/k8s/template.ts` | Templates K8s Job |
| `src/k8s/config.ts` | Config cluster + getKubeConfig |
| `src/k8s/configmap.ts` | CRUD ConfigMap K8s |
| `src/k8s/job.ts` | Création/listing jobs |
| `src/schemas/job.schema.ts` | Schémas Zod pour jobs |
| `src/services/job.service.ts` | Service métier jobs |
| `src/controllers/job.controller.ts` | Controller HTTP jobs |
| `src/routes/job.routes.ts` | Routes Fastify jobs |

### Fichiers à modifier (4)
| Fichier | Modification |
|---------|--------------|
| `package.json` | Ajouter dépendances |
| `src/schemas/database.schema.ts` | Ajouter DatabaseSelected |
| `src/services/database.service.ts` | Ajouter listDatabasesFromServer |
| `src/controllers/database.controller.ts` | Ajouter endpoint list |
| `src/routes/database.routes.ts` | Ajouter route /:id/list |
| `src/server.ts` | Enregistrer jobRoutes |

---

## Points d'attention

### ⚠️ Configuration hardcodée
La config dans `src/k8s/config.ts` est actuellement hardcodée pour le cluster "qualif". Il faudra:
1. Soit la rendre configurable via variables d'environnement
2. Soit la stocker en base de données (nouvelle table ClusterConfig)

### ⚠️ Namespace par défaut
Les jobs sont créés dans le namespace "default". Considérer rendre cela configurable.

### ⚠️ Labels operator/name
Les jobs utilisent le label `operator/name: kuma`. Décider si on garde ce nom ou si on passe à `jinbe`.

### ⚠️ Vault integration
Les templates utilisent des annotations Vault (Banzai Cloud). S'assurer que le cluster K8s a le mutating webhook configuré.
