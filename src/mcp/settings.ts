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
 *   allowedGroups        'all', or the groups whose members may use it (staff rights come from groups;
 *                        a personal key is bound to no organization)
 *   oauth                browser sign-in for MCP clients (src/oauth/): `enabled` (ON by default whenever
 *                        MCP is on — owner decision D5, 2026-09-30), `maxDays` the absolute life of one
 *                        sign-in (≤ 30), and protected actions: 'window' allows them for
 *                        `protectedActionsHours` after the consent-time second factor (12 h, D1), 'off' never
 *
 * DELEGATED_TOKENS_ENABLED is the deployment's hard ceiling: false and nothing here turns MCP on.
 * Unset: OFF — MCP stays off until an administrator opts in (owner decision) — no URL, 30 days, every
 * group. A document saved before groups (`allowedOrgs`) is migrated on read: 'all' stays 'all', an org
 * list — which names no group — becomes no group at all (closed, never widened). Read on
 * every delegated token and key exchange, so it is cached for a few seconds; a write refreshes the
 * cache at once — turning it off refuses tokens on this replica now and on the others within 5 s.
 */

export const MCP_SETTINGS_KEY = 'mcp'

export interface McpSettings {
  enabled: boolean
  serverUrl: string | null
  personalKeys: { maxDays: number }
  allowedGroups: 'all' | string[]
  oauth: OAuthSettings
}

export interface OAuthSettings {
  enabled: boolean
  maxDays: number
  protectedActions: 'off' | 'window'
  protectedActionsHours: number
}

export const OAUTH_MAX_DAYS = 30
export const OAUTH_MAX_PROTECTED_HOURS = 720

export const MAX_GROUPS = 500
const GROUP_NAME = /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/

export function defaultMcpSettings(): McpSettings {
  return {
    enabled: false, serverUrl: null, personalKeys: { maxDays: PERSONAL_KEY_MAX_DAYS }, allowedGroups: 'all',
    oauth: { enabled: true, maxDays: OAUTH_MAX_DAYS, protectedActions: 'window', protectedActionsHours: 12 },
  }
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

/** A candidate document as a clean one, or the problems that stop it. Group lists are trimmed, de-duplicated and sorted. */
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
  if (o.allowedOrgs !== undefined && !opts.forSave && o.allowedGroups === undefined) {
    // Stored before groups: an org list names no group, so it allows none — closed, never widened.
    value.allowedGroups = o.allowedOrgs === 'all' ? 'all' : []
  }
  if (o.allowedOrgs !== undefined && opts.forSave) {
    problems.push({ field: 'allowedOrgs', message: 'replaced by allowedGroups: MCP is allowed by group, not by organization' })
  }
  if (o.allowedGroups !== undefined && o.allowedGroups !== 'all') {
    const raw = o.allowedGroups
    if (!Array.isArray(raw) || !raw.every((s) => typeof s === 'string')) {
      problems.push({ field: 'allowedGroups', message: "must be 'all' or a list of group names" })
    } else {
      const list = [...new Set((raw as string[]).map((s) => s.trim()).filter(Boolean))].sort()
      const bad = list.filter((s) => !GROUP_NAME.test(s))
      if (bad.length) problems.push({ field: 'allowedGroups', message: `not a group name: ${bad.slice(0, 5).join(', ')}` })
      if (list.length > MAX_GROUPS) problems.push({ field: 'allowedGroups', message: `at most ${MAX_GROUPS} groups` })
      if (opts.forSave && !list.length) problems.push({ field: 'allowedGroups', message: "list at least one group (or choose 'all')" })
      value.allowedGroups = list
    }
  }
  if (o.oauth !== undefined) {
    if (o.oauth === null || typeof o.oauth !== 'object' || Array.isArray(o.oauth)) problems.push({ field: 'oauth', message: 'must be an object' })
    else validateOAuth(o.oauth as Record<string, unknown>, value.oauth, problems)
  }
  return problems.length ? { ok: false, problems } : { ok: true, value }
}

function wholeIn(v: unknown, min: number, max: number): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max
}

function validateOAuth(o: Record<string, unknown>, value: OAuthSettings, problems: SettingsProblem[]): void {
  if (o.enabled !== undefined) {
    if (typeof o.enabled !== 'boolean') problems.push({ field: 'oauth.enabled', message: 'must be true or false' })
    else value.enabled = o.enabled
  }
  if (o.maxDays !== undefined) {
    if (!wholeIn(o.maxDays, 1, OAUTH_MAX_DAYS)) problems.push({ field: 'oauth.maxDays', message: `must be a whole number of days from 1 to ${OAUTH_MAX_DAYS}` })
    else value.maxDays = o.maxDays
  }
  if (o.protectedActions !== undefined) {
    if (o.protectedActions !== 'off' && o.protectedActions !== 'window') problems.push({ field: 'oauth.protectedActions', message: "must be 'off' or 'window'" })
    else value.protectedActions = o.protectedActions
  }
  if (o.protectedActionsHours !== undefined) {
    if (!wholeIn(o.protectedActionsHours, 1, OAUTH_MAX_PROTECTED_HOURS)) {
      problems.push({ field: 'oauth.protectedActionsHours', message: `must be a whole number of hours from 1 to ${OAUTH_MAX_PROTECTED_HOURS}` })
    } else value.protectedActionsHours = o.protectedActionsHours
  }
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

function isPreGroups(raw: string): boolean {
  try {
    const o = JSON.parse(raw) as Record<string, unknown>
    return o !== null && typeof o === 'object' && 'allowedOrgs' in o
  } catch {
    return false
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
    const raw = config[MCP_SETTINGS_KEY]
    const value = parseMcpSettings(raw)
    cached = { at: Date.now(), value }
    if (raw !== undefined && isPreGroups(raw)) {
      // Store the migrated document once, so the next reader (and the console) sees groups.
      await redisRbacRepository.setConfig(MCP_SETTINGS_KEY, JSON.stringify(value)).catch(() => {})
    }
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

/** Whether a person holding `groups` may use MCP. */
export function groupAllowed(settings: McpSettings, groups: readonly string[]): boolean {
  return settings.allowedGroups === 'all' || groups.some((g) => (settings.allowedGroups as string[]).includes(g))
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
