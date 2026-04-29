import { z } from 'zod'
import dotenv from 'dotenv'

// Load environment variables
dotenv.config()

// Environment schema with validation
const envSchema = z.object({
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

  // OPAL/OPA Client
  OPA_URL: z.string().url().default('http://opal-client:8181'),

  // Application name for OPAL fine-grained authorization
  APP_NAME: z.string().min(1, 'APP_NAME is required for OPAL authorization').default('jinbe'),

  // OPAL Server (for real-time RBAC update triggers — legacy, being replaced by OPA direct push)
  OPAL_SERVER_URL: z.string().url().default('http://auth-w6d-opal-server:7002'),
  JINBE_INTERNAL_URL: z.string().url().default('http://jinbe.w6d-ops:8080'),

  // OPA Data API (direct push — replaces OPAL data sync)
  OPA_DATA_URL: z.string().url().default('http://auth-w6d-opal-client.auth-w6d.svc.cluster.local:8181'),

  // Redis (RBAC data store + audit streams)
  REDIS_URL: z.string().default('redis://auth-w6d-redis-master.auth-w6d.svc.cluster.local:6379'),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.string().transform(Number).pipe(z.number().min(0)).default('0'),
  REDIS_AUDIT_STREAM: z.string().default('auth:audit:events'),

  // Service Creation Defaults (for Oathkeeper rules and kustomization)
  SERVICE_DEFAULT_NAMESPACE: z.string().default('w6d-ops'),
  SERVICE_DEFAULT_DOMAIN: z.string().default('kuma.dev.w6d.io'),
  SERVICE_DEFAULT_PORT: z.string().transform(Number).pipe(z.number().positive()).default('8080'),

  // Internal service URLs for bootstrap (Oathkeeper upstream rules)
  LOGIN_UI_URL: z.string().url().optional(),   // e.g. http://auth-w6d-kratos-login-ui:80
  ADMIN_UI_URL: z.string().url().optional(),   // e.g. http://auth-w6d-admin-ui:80

  // Domain configuration (for Oathkeeper rule generation)
  AUTH_DOMAIN: z.string().optional(),   // e.g. auth.example.com — Kratos + Login UI
  APP_DOMAIN: z.string().optional(),    // e.g. app.example.com  — Kuma admin UI
  API_DOMAIN: z.string().optional(),    // e.g. api.example.com  — Jinbe API (defaults to APP_DOMAIN)
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
