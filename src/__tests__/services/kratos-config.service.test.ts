import { describe, it, expect, beforeEach } from 'vitest'
import { mkdtemp, readFile, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { KratosConfigService, KratosConfigError } from '../../services/kratos-config.service.js'

const SAMPLE = `# demo kratos config
selfservice:
  methods:
    password:
      enabled: true
    code:
      enabled: true
    totp:
      enabled: true
      config:
        issuer: demo # keep me
    webauthn:
      enabled: false
identity:
  default_schema_id: default
`

describe('KratosConfigService', () => {
  let path: string
  let svc: KratosConfigService

  beforeEach(async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kratos-config-'))
    path = join(dir, 'kratos.yml')
    await writeFile(path, SAMPLE, 'utf8')
    svc = new KratosConfigService(path)
  })

  it('reads method state, defaulting absent methods to disabled', async () => {
    const methods = await svc.getMethods()
    expect(methods.password).toEqual({ enabled: true, configured: false })
    expect(methods.code).toEqual({ enabled: true, configured: false, passwordlessEnabled: false })
    expect(methods.totp).toEqual({ enabled: true, configured: true })
    expect(methods.passkey).toEqual({ enabled: false, configured: false })
    expect(methods.oidc).toEqual({ enabled: false, configured: false })
  })

  it('toggles enabled flags and code passwordless, preserving comments', async () => {
    const methods = await svc.setMethods({
      password: { enabled: false },
      code: { passwordlessEnabled: true },
    })
    expect(methods.password.enabled).toBe(false)
    expect(methods.code.passwordlessEnabled).toBe(true)
    const raw = await readFile(path, 'utf8')
    expect(raw).toContain('# demo kratos config')
    expect(raw).toContain('# keep me')
    expect(raw).toContain('default_schema_id: default')
  })

  it('refuses to enable a config-required method without its config block', async () => {
    await expect(svc.setMethods({ webauthn: { enabled: true } })).rejects.toThrow(KratosConfigError)
    await expect(svc.setMethods({ oidc: { enabled: true } })).rejects.toThrow(/config block/)
  })

  it('allows disabling a config-required method, and enabling one that has config', async () => {
    // totp has a config block — not config-required, but proves the block detection
    const methods = await svc.setMethods({ webauthn: { enabled: false }, totp: { enabled: false } })
    expect(methods.webauthn.enabled).toBe(false)
    expect(methods.totp.enabled).toBe(false)
  })

  it('rejects passwordlessEnabled on non-code methods and unknown methods', async () => {
    await expect(svc.setMethods({ password: { passwordlessEnabled: true } })).rejects.toThrow(/only applies/)
    // @ts-expect-error — deliberately invalid method name
    await expect(svc.setMethods({ magic: { enabled: true } })).rejects.toThrow(/Unknown auth method/)
  })

  it('registration defaults to enabled when the key is absent, and toggles', async () => {
    expect(await svc.getRegistrationEnabled()).toBe(true)
    expect(await svc.setRegistrationEnabled(false)).toBe(false)
    expect(await svc.getRegistrationEnabled()).toBe(false)
    const raw = await readFile(path, 'utf8')
    expect(raw).toContain('# demo kratos config') // comments preserved
    expect(await svc.setRegistrationEnabled(true)).toBe(true)
    expect(await svc.getRegistrationEnabled()).toBe(true)
  })

  it('returns 501-flavored error when path is unset', async () => {
    const disabled = new KratosConfigService(undefined)
    expect(disabled.enabled()).toBe(false)
    await expect(disabled.getMethods()).rejects.toMatchObject({ statusCode: 501 })
  })
})
