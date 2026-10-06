import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { env } from '../config/index.js'
import { getRedisClient } from './redis-client.service.js'
import { withRedisLock } from './redis-lock.js'

/**
 * Invitations into an organization: an org admin (org.members:write) invites somebody by address,
 * for an account that exists or not; the person joins only by accepting, signed in with that address
 * verified (consent). Nobody is pulled into an organization by somebody else.
 *
 *   jinbe:org_invitations   Hash id → JSON Invitation   one per (org, address); a new one replaces it
 *
 * The token is shown once to the inviter (in the link they send: jinbe has no mailer) and kept only
 * as its sha256. An invitation lives INVITATION_TTL_DAYS; expired ones are dropped on every write and
 * never answered. Org roles named in it were cleared by the holding rule when it was made, and are
 * asked again of the inviter when it is accepted (rights can change in a week) — except an owner
 * invited by the platform with a new organisation (`byPlatform`).
 *
 * A new person registers through the link: the sign-up guards let exactly that address in when the flow
 * returns to it with a pending token (sign-in-protection/guard.ts invitedAddress).
 *
 * People's data, not generated from intents: not in the bootstrap wipe; in the backup snapshot with the
 * organization records (bundle-stores.ts), restored exactly for the snapshot's orgs.
 */

export const INVITATION_TTL_DAYS = 7
const KEY = 'jinbe:org_invitations'
const DAY_MS = 24 * 60 * 60 * 1000

export interface Invitation {
  id: string
  org: string
  /** Lowercased. */
  email: string
  /** Org roles (`svc:role`) given on acceptance. */
  roles: string[]
  invitedBy: { id: string | null; email: string }
  /**
   * Made by the platform (an organisation created for its owner, POST /api/admin/organizations): its
   * roles were decided by a holder of orgs:write there, not under the holding rule of the org.
   */
  byPlatform?: boolean
  createdAt: string
  expiresAt: string
  tokenHash: string
}

export type InvitationView = Omit<Invitation, 'tokenHash'>

export const viewOf = ({ tokenHash: _, ...view }: Invitation): InvitationView => view

const hashOf = (token: string) => createHash('sha256').update(token).digest('hex')
const redis = () => getRedisClient()
const normal = (email: string) => email.trim().toLowerCase()

function parse(raw: string): Invitation | null {
  try {
    const v = JSON.parse(raw) as Partial<Invitation>
    if (typeof v.id !== 'string' || typeof v.org !== 'string' || typeof v.email !== 'string' || typeof v.tokenHash !== 'string' || typeof v.expiresAt !== 'string') return null
    return { roles: [], invitedBy: { id: null, email: '' }, createdAt: '', ...v } as Invitation
  } catch {
    return null
  }
}

const live = (i: Invitation, now: number) => Date.parse(i.expiresAt) > now

async function all(now = Date.now()): Promise<Invitation[]> {
  return Object.values(await redis().hgetall(KEY)).map(parse).filter((i): i is Invitation => i !== null && live(i, now))
}

/** The link the inviter sends, when the deployment says where invitations are accepted. */
export function invitationLink(token: string): string | null {
  if (!env.INVITATION_URL) return null
  const url = new URL(env.INVITATION_URL)
  url.searchParams.set('token', token)
  return url.toString()
}

export const orgInvitations = {
  /**
   * A new invitation of `email` into `org`, replacing a pending one for the same address there.
   * Returns it with its token (shown once).
   */
  async create(input: { org: string; email: string; roles: readonly string[]; invitedBy: Invitation['invitedBy']; byPlatform?: boolean }, now = Date.now()): Promise<{ invitation: Invitation; token: string }> {
    const token = randomBytes(32).toString('base64url')
    const email = normal(input.email)
    const invitation: Invitation = {
      id: randomUUID(),
      org: input.org,
      email,
      roles: [...new Set(input.roles)].sort(),
      invitedBy: input.invitedBy,
      ...(input.byPlatform ? { byPlatform: true } : {}),
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + INVITATION_TTL_DAYS * DAY_MS).toISOString(),
      tokenHash: hashOf(token),
    }
    await withRedisLock('org-invitations', async () => {
      const raw = await redis().hgetall(KEY)
      for (const [id, value] of Object.entries(raw)) {
        const held = parse(value)
        if (!held || !live(held, now) || (held.org === invitation.org && held.email === email)) await redis().hdel(KEY, id)
      }
      await redis().hset(KEY, invitation.id, JSON.stringify(invitation))
    })
    return { invitation, token }
  },

  /** The pending invitations of one organization, newest first. */
  async ofOrg(org: string, now = Date.now()): Promise<Invitation[]> {
    return (await all(now)).filter((i) => i.org === org).sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  },

  /** The pending invitations addressed to `email`, newest first. */
  async forEmail(email: string, now = Date.now()): Promise<Invitation[]> {
    const wanted = normal(email)
    return (await all(now)).filter((i) => i.email === wanted).sort((a, b) => b.createdAt.localeCompare(a.createdAt))
  },

  async byId(id: string, now = Date.now()): Promise<Invitation | null> {
    const raw = await redis().hget(KEY, id)
    const i = raw ? parse(raw) : null
    return i && live(i, now) ? i : null
  },

  async byToken(token: string, now = Date.now()): Promise<Invitation | null> {
    const wanted = hashOf(token)
    return (await all(now)).find((i) => i.tokenHash === wanted) ?? null
  },

  /** Gone (accepted, declined, revoked). True when it was there. */
  async remove(id: string): Promise<boolean> {
    return (await redis().hdel(KEY, id)) > 0
  },

  /** The organization was deleted: its invitations go. */
  async forgetOrg(org: string): Promise<void> {
    await withRedisLock('org-invitations', async () => {
      for (const [id, value] of Object.entries(await redis().hgetall(KEY))) if (parse(value)?.org === org) await redis().hdel(KEY, id)
    })
  },
}
