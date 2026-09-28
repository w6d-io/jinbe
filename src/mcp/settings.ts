import { env } from '../config/index.js'
import { redisRbacRepository } from '../services/redis-rbac.repository.js'
import { PERSONAL_KEY_MAX_DAYS } from '../schemas/api-key.schema.js'

/**
 * The platform setting "AI assistants (MCP)" — rbac:config `mcp`, one JSON document edited from the
 * console (Settings → AI assistants).
 *
 *   enabled              the administrator's switch for delegated tokens, personal keys and /api/mcp/*
 *   serverUrl            the MCP server address shown to people (kuma Connections); null = MCP_PUBLIC_URL
 *   personalKeys.maxDays the longest a new personal key may live (≤ 30, the owner's ceiling)
 *   allowedOrgs          'all', or the organizations whose members may use it
 *
 * DELEGATED_TOKENS_ENABLED is the deployment's hard ceiling: false and nothing here turns MCP on.
 * Unset: OFF — MCP stays off until an administrator opts in (owner decision) — no URL, 30 days, every
 * org. Read on
 * every delegated token and key exchange, so it is cached for a few seconds; a write refreshes the
 * cache at once — turning it off refuses tokens on this replica now and on the others within 5 s.
 */

export const MCP_SETTINGS_KEY = 'mcp'

export interface McpSettings {
  enabled: boolean
  serverUrl: string | null
  personalKeys: { maxDays: number }
  allowedOrgs: 'all' | string[]
}

export const MAX_ORGS = 500
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export function defaultMcpSettings(): McpSettings {
  return { enabled: false, serverUrl: null, personalKeys: { maxDays: PERSONAL_KEY_MAX_DAYS }, allowedOrgs: 'all' }
}

export type SettingsProblem = { field: string; message: string }

function checkUrl(raw: string): string | null {
  if (raw.length > 2048) return null
  try {
    const u = new URL(raw)
    if (u.protocol !== 'https:' || u.username || u.password || u.hash) return null
    return u.toString()
  } catch {
    return null
  }
}

/**
 * The deployment's MCP server address (MCP_PUBLIC_URL), shown when the administrator has saved none.
 * Held to the same rule as a saved one; anything else is no address.
 */
export function deploymentServerUrl(): string | null {
  const raw = String(env.MCP_PUBLIC_URL ?? '').trim()
  return raw ? checkUrl(raw) : null
}

/** A saved address, or the deployment's when none is saved. */
export const effectiveServerUrl = (settings: McpSettings): string | null => settings.serverUrl ?? deploymentServerUrl()

/** A candidate document as a clean one, or the problems that stop it. Org lists are lowercased, de-duplicated and sorted. */
export function validateMcpSettings(input: unknown, opts: { forSave?: boolean } = { forSave: true }): { ok: true; value: McpSettings } | { ok: false; problems: SettingsProblem[] } {
  const problems: SettingsProblem[] = []
  const o = (input ?? {}) as Record<string, unknown>
  const pk = (o.personalKeys ?? {}) as Record<string, unknown>
  const value = defaultMcpSettings()

  if (o.enabled !== undefined) {
    if (typeof o.enabled !== 'boolean') problems.push({ field: 'enabled', message: 'must be true or false' })
    else value.enabled = o.enabled
  }
  if (o.serverUrl !== undefined && o.serverUrl !== null && o.serverUrl !== '') {
    const url = typeof o.serverUrl === 'string' ? checkUrl(o.serverUrl.trim()) : null
    if (!url) problems.push({ field: 'serverUrl', message: 'must be an https:// address without credentials' })
    else value.serverUrl = url
  }
  if (pk.maxDays !== undefined) {
    const d = pk.maxDays
    if (typeof d !== 'number' || !Number.isInteger(d) || d < 1 || d > PERSONAL_KEY_MAX_DAYS) {
      problems.push({ field: 'personalKeys.maxDays', message: `must be a whole number of days from 1 to ${PERSONAL_KEY_MAX_DAYS}` })
    } else value.personalKeys.maxDays = d
  }
  if (o.allowedOrgs !== undefined && o.allowedOrgs !== 'all') {
    const raw = o.allowedOrgs
    if (!Array.isArray(raw) || !raw.every((s) => typeof s === 'string')) {
      problems.push({ field: 'allowedOrgs', message: "must be 'all' or a list of organization ids" })
    } else {
      const list = [...new Set((raw as string[]).map((s) => s.trim().toLowerCase()).filter(Boolean))].sort()
      const bad = list.filter((s) => !UUID.test(s))
      if (bad.length) problems.push({ field: 'allowedOrgs', message: `not an organization id: ${bad.slice(0, 5).join(', ')}` })
      if (list.length > MAX_ORGS) problems.push({ field: 'allowedOrgs', message: `at most ${MAX_ORGS} organizations` })
      if (opts.forSave && !list.length) problems.push({ field: 'allowedOrgs', message: "list at least one organization (or choose 'all')" })
      value.allowedOrgs = list
    }
  }
  return problems.length ? { ok: false, problems } : { ok: true, value }
}

/** A stored value as a clean document; a missing or unreadable one is the default. */
export function parseMcpSettings(raw: string | undefined): McpSettings {
  if (raw === undefined) return defaultMcpSettings()
  try {
    const v = validateMcpSettings(JSON.parse(raw), { forSave: false })
    return v.ok ? v.value : defaultMcpSettings()
  } catch {
    return defaultMcpSettings()
  }
}

const TTL_MS = 5_000
let cached: { at: number; value: McpSettings } | null = null

/** Test seam. */
export function resetMcpSettingsCache(): void {
  cached = null
}

/**
 * The current document. Throws when Redis cannot be read and nothing was ever read; after one good
 * read a Redis outage keeps answering the last known document.
 */
export async function getMcpSettings(): Promise<McpSettings> {
  if (cached && Date.now() - cached.at < TTL_MS) return cached.value
  try {
    const config = await redisRbacRepository.getConfig()
    const value = parseMcpSettings(config[MCP_SETTINGS_KEY])
    cached = { at: Date.now(), value }
    return value
  } catch (err) {
    if (cached) return cached.value
    throw err
  }
}

export async function setMcpSettings(value: McpSettings): Promise<McpSettings> {
  await redisRbacRepository.setConfig(MCP_SETTINGS_KEY, JSON.stringify(value))
  cached = { at: Date.now(), value }
  return value
}

/** The deployment's ceiling (DELEGATED_TOKENS_ENABLED). */
export const mcpCeiling = (): boolean => env.DELEGATED_TOKENS_ENABLED

export function orgAllowed(settings: McpSettings, org: string): boolean {
  return settings.allowedOrgs === 'all' || settings.allowedOrgs.includes(org.toLowerCase())
}

/**
 * Whether MCP is on right now: `off` is 'deployment' (the env ceiling), 'administrator' (the switch)
 * or 'unavailable' (the setting cannot be read and never was — refused, never guessed on).
 */
export type McpGate = { on: true; off?: undefined; settings: McpSettings } | { on: false; off: 'deployment' | 'administrator' | 'unavailable'; settings?: McpSettings }

export async function mcpGate(): Promise<McpGate> {
  if (!mcpCeiling()) return { on: false, off: 'deployment' }
  let settings: McpSettings
  try {
    settings = await getMcpSettings()
  } catch {
    return { on: false, off: 'unavailable' }
  }
  return settings.enabled ? { on: true, settings } : { on: false, off: 'administrator', settings }
}
