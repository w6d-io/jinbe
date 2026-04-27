# Jinbe API - Project Overview

## Project Identity

**Name**: Jinbe API (package name: `kuma-api`)  
**Description**: Standalone Node.js API for Kubernetes cluster and database management  
**Origin**: Migrated from a Next.js application  
**Primary Language**: TypeScript (strict mode, ESM modules)

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Runtime** | Node.js 18+ (ESM) |
| **Framework** | Fastify 4 |
| **Database** | MongoDB via Prisma ORM |
| **Validation** | Zod |
| **Security** | Helmet, CORS, Rate Limiting |
| **Documentation** | OpenAPI 3.1 + Swagger UI |
| **Testing** | Vitest + Supertest |
| **Logging** | Pino with request correlation |

---

## Architecture

### Layer Structure

```
┌─────────────────────────────────────────────────┐
│                   Routes Layer                   │
│  (src/routes/*.routes.ts)                       │
│  - Defines HTTP endpoints                        │
│  - Swagger schemas for request/response         │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│               Controllers Layer                  │
│  (src/controllers/*.controller.ts)               │
│  - HTTP request/response handling               │
│  - Input validation (via Zod)                   │
│  - Error formatting                             │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│                Services Layer                    │
│  (src/services/*.service.ts)                     │
│  - Business logic                               │
│  - Prisma database operations                   │
│  - Password encryption/decryption               │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│              Prisma + MongoDB                    │
│  (prisma/schema.prisma)                         │
└─────────────────────────────────────────────────┘
```

### Middleware Pipeline

1. **requestIdMiddleware** - Adds unique request ID for tracing
2. **extractIdentity** - Extracts user context from AuthKeeper headers
3. **corsPlugin** - CORS handling
4. **rateLimitPlugin** - Rate limiting protection
5. **swaggerPlugin** - API documentation
6. **helmetPlugin** - Security headers
7. **auditLogger** - Post-response audit logging

---

## Data Model (MongoDB/Prisma)

### Entity Relationships

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│   Cluster   │──1:N──│   Backup    │──1:N──│ BackupItem  │
└─────────────┘       └─────────────┘       └─────────────┘
       │
       │ 1:N
       ▼
┌─────────────┐       ┌─────────────┐
│  Database   │──1:1──│ DatabaseAPI │
└─────────────┘       └─────────────┘
```

### Models

#### Cluster
- `id` (ObjectId) - Primary key
- `name` (String, unique) - Cluster identifier
- `config` (String) - Cluster configuration (kubeconfig or similar)
- `createdAt`, `updatedAt` - Timestamps
- Relations: `backups[]`, `databases[]`

#### Database
- `id` (ObjectId) - Primary key
- `type` (DBType enum: postgresql | mongodb | influxdb)
- `host`, `port` - Connection info
- `username`, `password` - Credentials (password is AES encrypted)
- `clusterId` - Foreign key to Cluster
- Relation: `api?` (optional DatabaseAPI)
- Unique constraint: `[clusterId, type]`

#### DatabaseAPI
- `id` (ObjectId) - Primary key
- `address` (String) - API endpoint
- `api_key` (String) - API authentication key
- `databaseId` (unique) - 1:1 relation to Database

#### Backup
- `id` (ObjectId) - Primary key
- `database_type` (String) - Type of DB backed up
- `date` (DateTime) - Backup timestamp
- `size` (String) - Total backup size
- `clusterId` - Foreign key to Cluster
- Relation: `BackupItem[]`
- Unique constraint: `[database_type, date]`

#### BackupItem
- `id` (ObjectId) - Primary key
- `database_type` (String) - DB type
- `name` (String) - Database name that was backed up
- `admin_username` (String) - Admin account used for backup
- `username` (String) - DB owner
- `filename` (String) - Backup file name
- `date` (DateTime) - Backup date
- `backupId` - Foreign key to Backup

---

## API Routes

All routes are prefixed with `/api`

| Route | Description |
|-------|-------------|
| `GET /api/health` | Health check endpoint |
| `/api/whoami` | User identity information |
| `/api/clusters/*` | Cluster CRUD operations |
| `/api/databases/*` | Database CRUD operations |
| `/api/backups/*` | Backup CRUD operations |
| `/api/backup-items/*` | BackupItem CRUD operations |
| `/api/database-apis/*` | DatabaseAPI CRUD operations |

### Query Parameters

- `GET /clusters?withConfig=true&withDatabase=true` - Include config/databases
- `GET /databases?clusterId=xxx` - Filter by cluster
- `GET /backups?clusterId=xxx` - Filter by cluster
- `GET /backup-items?backupId=xxx` - Filter by backup

---

## Authentication & Authorization

### Current Model (AuthKeeper/OPA)

The API does **NOT** perform authentication internally. It trusts headers injected by an upstream proxy (AuthKeeper/OPA):

**Expected Headers:**
- `X-User-Email` - User's email
- `X-User-ID` - User's unique ID  
- `X-User-Name` - User's display name

These are extracted in `identity-extractor.ts` and attached to `request.userContext` for audit/logging purposes.

### Security Layers
- **Helmet** - Security headers
- **CORS** - Cross-origin protection
- **Rate Limiting** - Request throttling

---

## Configuration (Environment Variables)

### Required
| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | MongoDB connection string |
| `ENCRYPTION_KEY` | AES key for password encryption (min 32 chars) |

### Optional
| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | development | Environment mode |
| `PORT` | 3000 | Server port |
| `HOST` | 0.0.0.0 | Server host |
| `CORS_ORIGIN` | * | Allowed origins |
| `CORS_CREDENTIALS` | false | Allow credentials |
| `RATE_LIMIT_MAX` | 100 | Max requests per window |
| `RATE_LIMIT_TIME_WINDOW` | 60000 | Window in ms |
| `LOG_LEVEL` | info | Pino log level |
| `ENABLE_SWAGGER` | true | Enable Swagger UI at /docs |
| `COMMIT_SHA` | - | Git commit for health check |

---

## Key Services

### ClusterService
- `getClusters()` - List all clusters (with optional relations)
- `getClusterById(id)` - Get single cluster with databases
- `createCluster(data)` - Create cluster with optional databases
- `updateCluster(id, data)` - Update cluster and manage databases
- `deleteCluster(id)` - Delete cluster (cascade to databases/backups)

### DatabaseService
- `getDatabases(clusterId?)` - List databases (optionally filtered)
- `getDatabaseById(id)` - Get single database with decrypted password
- `createDatabase(data)` - Create database (encrypts password)
- `updateDatabase(id, data)` - Update database
- `deleteDatabase(id)` - Delete database

### BackupService
- `getBackups(clusterId?)` - List backups (optionally filtered)
- `getBackupById(id)` - Get backup with all items
- `createBackup(clusterId, data)` - Create backup with items (transactional)
- `deleteBackup(id)` - Delete backup and all items

### BackupItemService
- `getBackupItems(backupId?)` - List items
- `getBackupItemById(id)` - Get single item
- `createBackupItem(backupId, data)` - Add item to existing backup
- `updateBackupItem(id, data)` - Update item
- `deleteBackupItem(id)` - Delete item

---

## Encryption

Database passwords are encrypted at rest using AES (crypto-js):
- **Location**: `src/utils/encryption.ts`
- **Key**: `ENCRYPTION_KEY` environment variable
- **Usage**: Encrypt on create/update, decrypt on read

---

## Project Structure

```
jinbe-api/
├── src/
│   ├── server.ts                 # Main entry point
│   ├── config/
│   │   ├── env.ts               # Zod-validated environment
│   │   └── index.ts             # Config exports
│   ├── controllers/             # HTTP handlers
│   │   ├── backup.controller.ts
│   │   ├── backup-item.controller.ts
│   │   ├── cluster.controller.ts
│   │   ├── database.controller.ts
│   │   └── database-api.controller.ts
│   ├── services/                # Business logic
│   │   ├── backup.service.ts
│   │   ├── backup-item.service.ts
│   │   ├── cluster.service.ts
│   │   ├── database.service.ts
│   │   └── database-api.service.ts
│   ├── routes/                  # Route definitions
│   │   ├── backup.routes.ts
│   │   ├── backup-item.routes.ts
│   │   ├── cluster.routes.ts
│   │   ├── database.routes.ts
│   │   ├── database-api.routes.ts
│   │   ├── health.routes.ts
│   │   └── whoami.routes.ts
│   ├── schemas/                 # Zod validation schemas
│   │   ├── backup.schema.ts
│   │   ├── backup-item.schema.ts
│   │   ├── cluster.schema.ts
│   │   ├── database.schema.ts
│   │   ├── database-api.schema.ts
│   │   └── response-schemas.ts
│   ├── middleware/
│   │   ├── identity-extractor.ts  # AuthKeeper header extraction
│   │   ├── error-handler.ts       # Global error handling
│   │   ├── audit-logger.ts        # Post-response logging
│   │   └── request-id.ts          # Request correlation
│   ├── plugins/                 # Fastify plugins
│   │   ├── cors.ts
│   │   ├── helmet.ts
│   │   ├── rate-limit.ts
│   │   └── swagger.ts
│   └── utils/
│       ├── prisma.ts            # Prisma client singleton
│       ├── encryption.ts        # AES encrypt/decrypt
│       ├── password.ts          # Password validation
│       └── pagination.ts        # Pagination helpers
├── prisma/
│   └── schema.prisma            # Database schema
├── package.json
├── tsconfig.json
└── docker-compose.yml
```

---

## Development Commands

```bash
pnpm dev              # Development with hot reload
pnpm build            # Compile TypeScript
pnpm start            # Production server
pnpm test             # Run tests
pnpm test:coverage    # Tests with coverage
pnpm lint             # ESLint
pnpm format           # Prettier
pnpm typecheck        # TypeScript check
pnpm prisma:generate  # Generate Prisma client
pnpm prisma:push      # Push schema to DB
pnpm prisma:studio    # Open Prisma Studio
```

---

## Error Handling

Standard HTTP status codes:
- **400** - Validation errors (Zod failures)
- **401** - Authentication required
- **403** - Authorization denied
- **404** - Resource not found (Prisma P2025)
- **409** - Unique constraint violation (Prisma P2002)
- **500** - Internal server error
- **503** - Database connection refused
- **504** - Database timeout

---

## Notes

- **No internal auth**: API trusts upstream proxy (AuthKeeper/OPA)
- **Cascade deletes**: Not configured in Prisma; handled manually in services
- **Password encryption**: Critical to maintain same ENCRYPTION_KEY for data continuity
- **Logging**: Structured JSON logs with request ID correlation
