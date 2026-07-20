import { z } from 'zod'
import dotenv from 'dotenv'
import { MIN_ADMIN_PASSWORD_LENGTH, WEAK_ADMIN_PASSWORD_PREFIX } from './admin-password.js'

// Load environment variables
dotenv.config()

// FQDN regex: at least one dot, alphanumeric + hyphens, no scheme/path/port.
// Catches mistakes like "http://app.example.com" and "app.example.com:8080".
const fqdnSchema = z
  .string()
  .regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i, {
    message: 'must be a bare FQDN (no scheme, no port, no path)',
  })

// Environment schema with validation
export const envSchema = z.object({
  // Server
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('production'),
  PORT: z.string().transform(Number).pipe(z.number().positive()).default('3000'),
  HOST: z.string().default('0.0.0.0'),
  BASE_URL: z.string().url().optional(),

  // Database
  DATABASE_URL: z.string().optional(),

  // Encryption (still needed for database credentials)
  ENCRYPTION_KEY: z.string().min(32, 'ENCRYPTION_KEY must be at least 32 characters'),

  // CORS
  CORS_ORIGIN: z.string().default('*'),
  CORS_CREDENTIALS: z
    .string()
    .transform((val) => val === 'true')
    .default('false'),
  // Set 'true' in production when oathkeeper handles CORS — prevents
  // duplicate Access-Control-Allow-Origin headers (oathkeeper emits its
  // own, jinbe layering its own causes browser rejection).
  DISABLE_CORS: z.string().default('false'),

  // Rate Limiting
  RATE_LIMIT_MAX: z.string().transform(Number).pipe(z.number().positive()).default('100'),
  RATE_LIMIT_TIME_WINDOW: z.string().transform(Number).pipe(z.number().positive()).default('60000'),

  // Logging
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  // API Documentation
  ENABLE_SWAGGER: z
    .string()
    .transform((val) => val === 'true')
    .default('true'),

  // Optional
  COMMIT_SHA: z.string().optional(),
  RELEASE_NAME: z.string().optional(),
  APP_VERSION: z.string().optional(),

  // Development only - bypass authentication (NEVER use in production!)
  DEV_BYPASS_AUTH: z
    .string()
    .transform((val) => val === 'true')
    .default('false'),
  // Fake user email for dev bypass
  DEV_USER_EMAIL: z.string().email().optional(),

  // Kratos APIs
  KRATOS_PUBLIC_URL: z.string().url().default('http://kratos-public:80'),
  KRATOS_ADMIN_URL: z.string().url().default('http://kratos-admin:80'),
  // Per-request timeout (ms) for Kratos Admin directory calls. Bounds the
  // OPAL /bindings directory walk so a HUNG Kratos aborts and the route can
  // fail closed instead of hanging the datasource fetch.
  KRATOS_REQUEST_TIMEOUT_MS: z
    .string()
    .transform(Number)
    .pipe(z.number().int().positive())
    .default('10000'),

  // Hydra Admin API (private — never expose publicly). Used to manage
  // OAuth2 clients that back per-organization M2M API keys.
  HYDRA_ADMIN_URL: z.string().url().default('http://auth-hydra-admin:4445'),
  // Allowed API-key scopes catalog (comma-separated). Requested scopes are
  // validated against this set server-side before a client is created.
  API_KEY_ALLOWED_SCOPES: z
    .string()
    .default('api:read,api:write')
    .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean)),

  // OPAL/OPA Client
  OPA_URL: z.string().url().default('http://opal-client:8181'),

  // Application name for OPAL fine-grained authorization
  APP_NAME: z.string().min(1, 'APP_NAME is required for OPAL authorization').default('jinbe'),

  // OPAL Server (for real-time RBAC update triggers)
  OPAL_SERVER_URL: z.string().url().default('http://opal-server:7002'),
  // Internal URL that opal-server uses to fetch data from this jinbe instance.
  // Set to the in-cluster service URL in production.
  JINBE_INTERNAL_URL: z.string().url().default('http://jinbe:8080'),

  // OPA Data API (direct push — replaces OPAL data sync)
  OPA_DATA_URL: z.string().url().default('http://opal-client:8181'),

  // Redis (RBAC data store + audit streams)
  REDIS_URL: z.string().default('redis://redis:6379'),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.string().transform(Number).pipe(z.number().min(0)).default('0'),
  REDIS_AUDIT_STREAM: z.string().default('auth:audit:events'),

  // Service Creation Defaults (for Oathkeeper rules and kustomization).
  // The defaults are placeholders — every production deployment must set
  // these explicitly to the deployer's namespace/domain.
  SERVICE_DEFAULT_NAMESPACE: z.string().default('default'),
  SERVICE_DEFAULT_DOMAIN: z.string().default('example.com'),
  SERVICE_DEFAULT_PORT: z.string().transform(Number).pipe(z.number().positive()).default('8080'),

  // Internal service URLs for bootstrap (Oathkeeper upstream rules)
  LOGIN_UI_URL: z.string().url().optional(),
  ADMIN_UI_URL: z.string().url().optional(),

  // Domain configuration (for Oathkeeper rule generation)
  AUTH_DOMAIN: fqdnSchema.optional(),
  APP_DOMAIN: fqdnSchema.optional(),
  API_DOMAIN: fqdnSchema.optional(),

  // OPA remote_json authorizer URL (used when generating per-service Oathkeeper rules)
  OPA_AUTHZ_REMOTE: z.string().url().default('http://opa-authz-proxy:8080/v1/data/rbac/allow'),

  // Default admin identity (only required on first bootstrap — see src/cli/bootstrap.ts).
  // ADMIN_PASSWORD seeds the first super_admins identity: it must be at least
  // MIN_ADMIN_PASSWORD_LENGTH chars and must not start with a well-known weak
  // prefix. Kept in sync with the seed-admin runtime guard via the shared policy
  // in ./admin-password.ts. Validated whenever present; the first-run presence
  // check lives in src/cli/bootstrap.ts.
  ADMIN_EMAIL: z.string().email().optional(),
  ADMIN_PASSWORD: z
    .string()
    .min(MIN_ADMIN_PASSWORD_LENGTH, `ADMIN_PASSWORD must be at least ${MIN_ADMIN_PASSWORD_LENGTH} characters`)
    .refine((v) => !WEAK_ADMIN_PASSWORD_PREFIX.test(v), {
      message:
        'ADMIN_PASSWORD starts with a well-known weak prefix (changeme/password/admin/123)',
    })
    .optional(),
  ADMIN_NAME: z.string().min(1).default('Admin'),

  // Reset path guards (CLI only). Both must be set; reset only if RESET_CONFIRM matches the running image SHA.
  JINBE_BOOTSTRAP_DANGEROUS_RESET: z
    .string()
    .transform((val) => val === 'true')
    .default('false'),
  JINBE_BOOTSTRAP_RESET_CONFIRM: z.string().optional(),

  // Sidecar notification service (jinbe-service)
  JINBE_SERVICE_URL: z.string().url().optional(),

  // Backup tool images (deployer-private registry). Required if the
  // /backups feature is used; left unset, attempts to render a backup
  // job will fail with a clear "image not configured" error.
  BACKUP_IMAGE_MONGO: z.string().optional(),
  BACKUP_IMAGE_POSTGRES: z.string().optional(),

  // GCP project ID injected into backup job env. Required for the GCS
  // output of the backup tool.
  BACKUP_GCP_PROJECT_ID: z.string().optional(),
})

// Parse and validate environment variables
const parseEnv = () => {
  try {
    return envSchema.parse(process.env)
  } catch (error) {
    if (error instanceof z.ZodError) {
      console.error('❌ Invalid environment variables:')
      error.errors.forEach((err) => {
        console.error(`  ${err.path.join('.')}: ${err.message}`)
      })
      process.exit(1)
    }
    throw error
  }
}

export const env = parseEnv()

// Type export for TypeScript
export type Env = z.infer<typeof envSchema>
