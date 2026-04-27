import { vi } from 'vitest'

export interface SyncKustomizationResult {
  commitId: string
  commitUrl: string
  filePath: string
  message: string
  authorEmail: string
  timestamp: string
  changes?: {
    added: string[]
    removed: string[]
  }
}

/**
 * Creates a mock kustomizationService
 */
export function createKustomizationMock() {
  return {
    syncKustomization: vi.fn().mockImplementation(async (
      authorEmail: string,
      _branch?: string
    ): Promise<SyncKustomizationResult> => {
      return {
        commitId: 'sync-commit-123',
        commitUrl: 'https://gitlab.example.com/project/-/commit/sync-commit-123',
        filePath: 'kustomization.yaml',
        message: 'chore: sync kustomization',
        authorEmail,
        timestamp: new Date().toISOString(),
        changes: { added: [], removed: [] },
      }
    }),

    addServiceFiles: vi.fn().mockImplementation(async (
      _serviceName: string,
      authorEmail: string,
      _branch?: string
    ): Promise<SyncKustomizationResult> => {
      return {
        commitId: 'add-commit-123',
        commitUrl: 'https://gitlab.example.com/project/-/commit/add-commit-123',
        filePath: 'kustomization.yaml',
        message: 'chore: add service to kustomization',
        authorEmail,
        timestamp: new Date().toISOString(),
      }
    }),

    removeServiceFiles: vi.fn().mockImplementation(async (
      _serviceName: string,
      authorEmail: string,
      _branch?: string
    ): Promise<SyncKustomizationResult> => {
      return {
        commitId: 'remove-commit-123',
        commitUrl: 'https://gitlab.example.com/project/-/commit/remove-commit-123',
        filePath: 'kustomization.yaml',
        message: 'chore: remove service from kustomization',
        authorEmail,
        timestamp: new Date().toISOString(),
      }
    }),

    getKustomization: vi.fn().mockResolvedValue({
      content: {
        apiVersion: 'kustomize.config.k8s.io/v1beta1',
        kind: 'Kustomization',
        configMapGenerator: [
          {
            name: 'auth-w6d-opal-static-data',
            files: [
              'bindings.json=configmaps/bindings.json',
              'groups.json=configmaps/groups.json',
            ],
          },
        ],
      },
      sha: 'kustomization-sha-1',
    }),

    serviceExistsInKustomization: vi.fn().mockResolvedValue(false),
    getServicesFromKustomization: vi.fn().mockResolvedValue([]),
  }
}
