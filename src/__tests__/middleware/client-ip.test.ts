import { describe, expect, it } from 'vitest'
import Fastify from 'fastify'
import { clientIp, trustProxySetting } from '../../utils/client-ip.js'

/**
 * The address jinbe records and rate-limits on. On the stack, Envoy (or nginx) appends the address it
 * accepted the connection from to X-Forwarded-For and Oathkeeper forwards the header untouched, so
 * jinbe sees `<whatever the client wrote>, <client>` from the Oathkeeper pod: one trusted hop.
 */
async function ipSeen(hops: number, headers: Record<string, string>, trustEnvoy = false) {
  const app = Fastify({ trustProxy: trustProxySetting(hops) })
  app.get('/', async (request) => ({ ip: request.ip, client: clientIp(request, trustEnvoy) }))
  const res = await app.inject({ method: 'GET', url: '/', headers, remoteAddress: '192.168.99.0' })
  await app.close()
  return res.json() as { ip: string; client: string }
}

describe('client address', () => {
  it('the leftmost X-Forwarded-For entry, which the client wrote, is never the answer', async () => {
    expect(await ipSeen(1, { 'x-forwarded-for': '6.6.6.6, 176.1.2.3' })).toEqual({ ip: '176.1.2.3', client: '176.1.2.3' })
  })

  it('more hops are walked back only as far as configured', async () => {
    expect((await ipSeen(2, { 'x-forwarded-for': '6.6.6.6, 176.1.2.3, 10.0.0.7' })).ip).toBe('176.1.2.3')
  })

  it('0 hops: the socket peer, the header ignored', async () => {
    expect(trustProxySetting(0)).toBe(false)
    expect((await ipSeen(0, { 'x-forwarded-for': '176.1.2.3' })).ip).toBe('192.168.99.0')
  })

  it('the default is one hop (Envoy -> Oathkeeper -> jinbe)', async () => {
    const trust = trustProxySetting()
    expect(trust && [trust('192.168.99.0', 0), trust('176.1.2.3', 1)]).toEqual([true, false])
  })

  it("Envoy's x-envoy-external-address wins only where it is trusted", async () => {
    const headers = { 'x-forwarded-for': '6.6.6.6, 176.1.2.3', 'x-envoy-external-address': '176.9.9.9' }
    expect((await ipSeen(1, headers, true)).client).toBe('176.9.9.9')
    expect((await ipSeen(1, headers, false)).client).toBe('176.1.2.3')
    expect((await ipSeen(1, { 'x-forwarded-for': '176.1.2.3' }, true)).client).toBe('176.1.2.3')
  })
})
