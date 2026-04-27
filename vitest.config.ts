import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/__tests__/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'clover', 'lcov'],
      include: [
        'src/services/rbac.service.ts',
        'src/services/git-proxy.service.ts',
        'src/controllers/rbac.controller.ts',
        'src/routes/rbac.routes.ts',
        'src/services/kustomization.service.ts',
        'src/middleware/require-admin.ts',
        'src/middleware/require-auth.ts',
        'src/services/kratos.service.ts',
        'src/services/kratos-session.service.ts',
        'src/controllers/admin.controller.ts',
        'src/routes/whoami.routes.ts',
        'src/services/cluster.service.ts',
        'src/controllers/cluster.controller.ts',
        'src/services/database.service.ts',
        'src/controllers/database.controller.ts',
        'src/services/database-api.service.ts',
        'src/controllers/database-api.controller.ts',
        'src/services/backup.service.ts',
        'src/controllers/backup.controller.ts',
        'src/services/backup-item.service.ts',
        'src/controllers/backup-item.controller.ts',
      ],
    },
    setupFiles: ['src/__tests__/setup.ts'],
    testTimeout: 10000,
  },
})
