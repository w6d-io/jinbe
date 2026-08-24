/**
 * SCIM bearer-token management CLI (SCIM provisioning spec §3).
 *
 * Usage:
 *   scim-token mint --label <label> [--created-by <email>]   # prints the token ONCE
 *   scim-token list
 *   scim-token revoke <tokenId>
 *
 * Tokens are stored SHA-256-hashed in Redis (rbac:scim:tokens) — the plaintext
 * printed by `mint` is the only copy that will ever exist. Paste it into the
 * IdP's "Secret Token" field (Entra / Google Workspace SCIM provisioning).
 *
 * Exit codes: 0 success · 1 usage error · 2 operation failed / not found
 */

import { redisClientService } from '../services/redis-client.service.js'
import { scimTokenService } from '../services/scim-token.service.js'

function usage(): void {
  console.error(
    'Usage:\n' +
      '  scim-token mint --label <label> [--created-by <email>]\n' +
      '  scim-token list\n' +
      '  scim-token revoke <tokenId>'
  )
}

function argValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag)
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined
}

async function main(): Promise<number> {
  const [command, ...args] = process.argv.slice(2)

  switch (command) {
    case 'mint': {
      const label = argValue(args, '--label')
      if (!label) {
        usage()
        return 1
      }
      const createdBy = argValue(args, '--created-by') ?? null
      const { tokenId, token } = await scimTokenService.mint({ label, createdBy })
      console.log(`SCIM token minted (label: ${label}, tokenId: ${tokenId})`)
      console.log('This token is shown ONCE — store it in the IdP now:')
      console.log(token)
      return 0
    }
    case 'list': {
      const tokens = await scimTokenService.list()
      if (tokens.length === 0) {
        console.log('No SCIM tokens.')
        return 0
      }
      for (const t of tokens) {
        console.log(
          `${t.tokenId}  label=${t.label}  createdBy=${t.createdBy ?? '-'}  createdAt=${t.createdAt}  lastUsedAt=${t.lastUsedAt ?? 'never'}`
        )
      }
      return 0
    }
    case 'revoke': {
      const tokenId = args[0]
      if (!tokenId) {
        usage()
        return 1
      }
      const revoked = await scimTokenService.revoke(tokenId)
      if (!revoked) {
        console.error(`No SCIM token with id ${tokenId}`)
        return 2
      }
      console.log(`SCIM token ${tokenId} revoked`)
      return 0
    }
    default:
      usage()
      return 1
  }
}

main()
  .then(async (code) => {
    await redisClientService.disconnect().catch(() => {})
    process.exit(code)
  })
  .catch(async (err) => {
    console.error('scim-token failed:', err instanceof Error ? err.message : err)
    await redisClientService.disconnect().catch(() => {})
    process.exit(2)
  })
