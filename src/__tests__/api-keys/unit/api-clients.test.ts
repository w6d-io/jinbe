import { describe, it, expect, vi, beforeEach } from 'vitest'

// data.api_clients: per org key, what its scopes stand for in all (`scopes`) and one by one
// (`by_scope`), so a token asking for some of the key's scopes is narrowed to those (rbac.rego).

const ORG = '11111111-1111-4111-8111-111111111111'
const h = vi.hoisted(() => ({ clients: [] as Array<Record<string, unknown>> }))

vi.mock('../../../services/hydra.service.js', () => ({ hydraService: { listAllClients: vi.fn(async () => h.clients) } }))
vi.mock('../../../services/opal-publisher.js', () => ({ opalPublisher: { schedule: vi.fn() } }))
vi.mock('../../../services/api-key-scopes.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  loadKeyModel: vi.fn(async () => ({
    orgSites: { [ORG]: ['earnings'] },
    roles: { earnings: { viewer: ['earnings:read'], partner: ['earnings.external:read'] } },
    groups: {},
    asked: { earnings: ['earnings.external:read', 'earnings:read'] },
  })),
}))

import { apiClientsDataset, resetApiClients } from '../../../services/api-clients.js'

beforeEach(() => resetApiClients())

describe('apiClientsDataset', () => {
  it('publishes each scope of an org key with what it stands for, beside the union', async () => {
    h.clients = [
      { client_id: 'k1', scope: 'role:earnings:viewer earnings.external:read', metadata: { organization_id: ORG } },
      { client_id: 'mine', scope: 'mcp', metadata: { organization_id: ORG, kind: 'personal' } },
    ]
    const data = await apiClientsDataset()
    expect(data.k1).toEqual({
      org: ORG,
      scopes: ['earnings.external:read', 'earnings:read'],
      by_scope: { 'role:earnings:viewer': ['earnings:read'], 'earnings.external:read': ['earnings.external:read'] },
    })
    expect(data.mine).toBeUndefined()
  })

  it('a scope that opens nothing any more is kept, standing for nothing', async () => {
    h.clients = [{ client_id: 'k2', scope: 'role:earnings:gone', metadata: { organization_id: ORG } }]
    expect((await apiClientsDataset()).k2).toMatchObject({ scopes: [], by_scope: { 'role:earnings:gone': [] } })
  })
})
