import { describe, it, expect, vi } from 'vitest'
import Fastify from 'fastify'

// A site named like a fixed path segment is shadowed by that route (GET /api/admin/sites/deleted is the
// deleted list, never the site `deleted`). Every fixed segment the Sites plugins mount must be a reserved
// name: this fails when a new fixed route is added without regenerating the route map.

vi.mock('../../services/redis-client.service.js', () => ({ getRedisClient: () => ({}) }))

import { sitesRoutes } from '../../sites/routes.js'
import { publicSitesRoutes } from '../../sites/public.routes.js'
import { RESERVED_NAMES, render } from '../../sites/render.js'
import { payrollSite, platform } from './fixtures.js'

async function fixedSegments(plugin: typeof sitesRoutes | typeof publicSitesRoutes, prefix: string): Promise<string[]> {
  const app = Fastify()
  const urls: string[] = []
  app.addHook('onRoute', (route) => { urls.push(route.url) })
  await app.register(plugin, { prefix })
  await app.ready()
  await app.close()
  return [...new Set(urls.map((u) => u.slice(prefix.length).split('/')[1]).filter((s) => s && !s.startsWith(':')))]
}

describe('reserved site names', () => {
  it('every fixed segment under /api/admin/sites and /api/public/sites is reserved', async () => {
    const segments = [...await fixedSegments(sitesRoutes, '/api/admin/sites'), ...await fixedSegments(publicSitesRoutes, '/api/public/sites')]
    expect(segments).toEqual(expect.arrayContaining(['deleted', 'gateways', 'deletion-requests', 'zones', 'by-host']))
    expect(segments.filter((s) => !RESERVED_NAMES.includes(s))).toEqual([])
  })

  it('a site named after one is refused at render (reserved_name)', () => {
    for (const name of ['deleted', 'gateways', 'deletion-requests', 'mine']) {
      const out = render(payrollSite({ name }), platform)
      expect(out.checks).toEqual(expect.arrayContaining([expect.objectContaining({ level: 'error', code: 'reserved_name' })]))
    }
  })
})
