import { vi, beforeEach } from 'vitest'

// Set environment variables BEFORE any imports
// This must be done before any module that depends on env is loaded
process.env.NODE_ENV = 'test'
process.env.DATABASE_URL = 'mongodb://localhost:27017/test'
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-chars-long'
process.env.APP_NAME = 'jinbe'
process.env.SERVICE_DEFAULT_NAMESPACE = 'w6d-ops'
process.env.SERVICE_DEFAULT_DOMAIN = 'kuma.dev.w6d.io'
process.env.SERVICE_DEFAULT_PORT = '8080'
process.env.DEV_BYPASS_AUTH = 'false'
process.env.KRATOS_PUBLIC_URL = 'http://localhost:4433'
process.env.KRATOS_ADMIN_URL = 'http://localhost:4434'
process.env.OPA_URL = 'http://localhost:8181'
process.env.ENABLE_SWAGGER = 'false'
process.env.LOG_LEVEL = 'error'
// Remove BASE_URL if it exists to avoid validation errors
delete process.env.BASE_URL

// Reset all mocks between tests
beforeEach(() => {
  vi.clearAllMocks()
})
