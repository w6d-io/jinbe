/**
 * Cluster test fixtures
 */

export interface MockCluster {
  id: string
  name: string
  config: string
  createdAt: Date
  updatedAt: Date
  databases?: MockDatabase[]
  backups?: MockBackup[]
  _count?: {
    databases: number
    backups: number
  }
}

export interface MockDatabase {
  id: string
  type: 'postgresql' | 'mongodb' | 'influxdb'
  host: string
  port: number
  username: string
  password?: string
  clusterId: string
  api?: MockDatabaseAPI
}

export interface MockDatabaseAPI {
  id: string
  address: string
  api_key: string
  databaseId: string
}

export interface MockBackup {
  id: string
  database_type: string
  date: Date
  size: string
  clusterId: string
  BackupItem?: MockBackupItem[]
}

export interface MockBackupItem {
  id: string
  database_type: string
  name: string
  admin_username: string
  username: string
  filename: string
  date: Date
  backupId: string
}

/**
 * Create a mock cluster
 */
export function createMockCluster(overrides: Partial<MockCluster> = {}): MockCluster {
  const id = overrides.id || '507f1f77bcf86cd799439011'
  return {
    id,
    name: overrides.name || 'test-cluster',
    config: overrides.config || 'apiVersion: v1\nkind: Config\nclusters: []',
    createdAt: overrides.createdAt || new Date('2024-01-01'),
    updatedAt: overrides.updatedAt || new Date('2024-01-01'),
    databases: overrides.databases,
    backups: overrides.backups,
    _count: overrides._count || { databases: 0, backups: 0 },
  }
}

/**
 * Create a mock database
 */
export function createMockDatabase(
  clusterId: string,
  overrides: Partial<MockDatabase> = {}
): MockDatabase {
  return {
    id: overrides.id || '507f1f77bcf86cd799439021',
    type: overrides.type || 'postgresql',
    host: overrides.host || 'localhost',
    port: overrides.port || 5432,
    username: overrides.username || 'admin',
    password: overrides.password || 'secret',
    clusterId,
    api: overrides.api,
  }
}

/**
 * Create a mock database API
 */
export function createMockDatabaseAPI(
  databaseId: string,
  overrides: Partial<MockDatabaseAPI> = {}
): MockDatabaseAPI {
  return {
    id: overrides.id || '507f1f77bcf86cd799439031',
    address: overrides.address || 'http://api.example.com',
    api_key: overrides.api_key || 'api-key-123',
    databaseId,
  }
}

/**
 * Create a mock backup
 */
export function createMockBackup(
  clusterId: string,
  overrides: Partial<MockBackup> = {}
): MockBackup {
  return {
    id: overrides.id || '507f1f77bcf86cd799439041',
    database_type: overrides.database_type || 'postgresql',
    date: overrides.date || new Date('2024-01-15'),
    size: overrides.size || '1GB',
    clusterId,
    BackupItem: overrides.BackupItem,
  }
}

/**
 * Create a mock backup item
 */
export function createMockBackupItem(
  backupId: string,
  overrides: Partial<MockBackupItem> = {}
): MockBackupItem {
  return {
    id: overrides.id || '507f1f77bcf86cd799439051',
    database_type: overrides.database_type || 'postgresql',
    name: overrides.name || 'test_db',
    admin_username: overrides.admin_username || 'admin',
    username: overrides.username || 'user',
    filename: overrides.filename || 'backup_2024-01-15.sql',
    date: overrides.date || new Date('2024-01-15'),
    backupId,
  }
}

/**
 * Create a cluster with full cascade data (databases with APIs, backups with items)
 */
export function createClusterWithCascadeData(): {
  cluster: MockCluster
  databases: MockDatabase[]
  databaseAPIs: MockDatabaseAPI[]
  backups: MockBackup[]
  backupItems: MockBackupItem[]
} {
  const clusterId = '507f1f77bcf86cd799439011'

  const database1 = createMockDatabase(clusterId, {
    id: '507f1f77bcf86cd799439021',
    type: 'postgresql',
  })
  const database2 = createMockDatabase(clusterId, {
    id: '507f1f77bcf86cd799439022',
    type: 'mongodb',
    port: 27017,
  })

  const dbApi1 = createMockDatabaseAPI(database1.id, { id: '507f1f77bcf86cd799439031' })
  const dbApi2 = createMockDatabaseAPI(database2.id, { id: '507f1f77bcf86cd799439032' })

  database1.api = dbApi1
  database2.api = dbApi2

  const backup1 = createMockBackup(clusterId, {
    id: '507f1f77bcf86cd799439041',
    database_type: 'postgresql',
  })
  const backup2 = createMockBackup(clusterId, {
    id: '507f1f77bcf86cd799439042',
    database_type: 'mongodb',
  })

  const backupItem1 = createMockBackupItem(backup1.id, { id: '507f1f77bcf86cd799439051' })
  const backupItem2 = createMockBackupItem(backup1.id, { id: '507f1f77bcf86cd799439052' })
  const backupItem3 = createMockBackupItem(backup2.id, { id: '507f1f77bcf86cd799439053' })

  backup1.BackupItem = [backupItem1, backupItem2]
  backup2.BackupItem = [backupItem3]

  const cluster = createMockCluster({
    id: clusterId,
    name: 'cascade-test-cluster',
    databases: [database1, database2],
    backups: [backup1, backup2],
    _count: { databases: 2, backups: 2 },
  })

  return {
    cluster,
    databases: [database1, database2],
    databaseAPIs: [dbApi1, dbApi2],
    backups: [backup1, backup2],
    backupItems: [backupItem1, backupItem2, backupItem3],
  }
}

/**
 * Sample valid kubeconfig for testing
 */
export const sampleKubeconfig = `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://kubernetes.example.com:6443
    certificate-authority-data: LS0tLS1CRUdJTi...
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: eyJhbGciOiJSUzI1NiIs...`

/**
 * Sample kubeconfig verification result
 */
export const sampleVerificationResult = {
  success: true,
  cluster: {
    name: 'test-cluster',
    server: 'https://kubernetes.example.com:6443',
    version: 'v1.28.0',
  },
  user: {
    name: 'test-user',
    authMethod: 'token' as const,
  },
  identity: {
    username: 'system:serviceaccount:default:test-sa',
    groups: ['system:serviceaccounts', 'system:authenticated'],
  },
  permissions: {
    canListNamespaces: true,
    canListPods: true,
    canCreateJobs: true,
    canListSecrets: false,
    namespaces: ['default', 'kube-system'],
  },
}
