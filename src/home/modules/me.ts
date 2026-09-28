import * as sources from '../sources.js'
import type { Me, SourceDetail } from '../types.js'
import { ok, probe, src, type ModuleDef } from './common.js'

/** The caller (home-data §3.5 me): per caller, never cached or shared. */
export const meModule: ModuleDef<Me> = {
  name: 'me',
  tier: 'direct',
  freshMs: 0,
  timeoutMs: 200,
  async compute(ctx) {
    const { scope } = ctx
    const [names, inbox] = await Promise.all([
      probe(() => sources.orgNames(scope.orgs), 150),
      probe(() => sources.inbox(scope.email), 150),
    ])
    const srcs: Record<string, SourceDetail> = {
      organisations: src(names.ok ? 'ok' : names.state),
      recert: src(inbox.ok ? 'ok' : inbox.state),
    }
    return ok({
      subject: scope.subject,
      name: scope.name,
      roles: scope.roles,
      orgs: scope.orgs.map((id) => ({ id, name: (names.ok ? names.value[id] : undefined) ?? id })),
      recertPending: inbox.ok ? inbox.value.length : 0,
      aal: scope.aal,
    }, srcs)
  },
}
