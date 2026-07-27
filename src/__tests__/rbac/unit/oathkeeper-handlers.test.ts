import { describe, it, expect } from 'vitest'
import {
  getEnabledHandlers,
  isHandlerEnabled,
  getEnabledHandlerNames,
} from '../../../services/oathkeeper-handlers.js'

// The test env leaves OATHKEEPER_ENABLED_* unset, so the safe defaults apply:
//   authenticators: cookie_session, noop
//   authorizers:    allow, remote_json
//   mutators:       noop, header
//   error handlers: redirect, json

describe('oathkeeper-handlers catalog', () => {
  describe('getEnabledHandlers', () => {
    const catalog = getEnabledHandlers()

    it('returns the four grouped lists in the contract shape', () => {
      expect(Object.keys(catalog).sort()).toEqual([
        'authenticators',
        'authorizers',
        'errorHandlers',
        'mutators',
      ])
    })

    it('returns ONLY the enabled handlers for each kind (default sets)', () => {
      expect(catalog.authenticators.map((h) => h.handler).sort()).toEqual(['cookie_session', 'noop'])
      expect(catalog.authorizers.map((h) => h.handler).sort()).toEqual(['allow', 'remote_json'])
      expect(catalog.mutators.map((h) => h.handler).sort()).toEqual(['header', 'noop'])
      expect(catalog.errorHandlers.map((h) => h.handler).sort()).toEqual(['json', 'redirect'])
    })

    it('never leaks a non-enabled handler (e.g. jwt / deny)', () => {
      expect(catalog.authenticators.map((h) => h.handler)).not.toContain('jwt')
      expect(catalog.authorizers.map((h) => h.handler)).not.toContain('deny')
    })

    it('emits full descriptors (no internal kind field)', () => {
      const cookie = catalog.authenticators.find((h) => h.handler === 'cookie_session')!
      expect(cookie).toBeDefined()
      expect(cookie).not.toHaveProperty('kind')
      expect(cookie.label).toBeTruthy()
      expect(cookie.description).toBeTruthy()
      expect(typeof cookie.hasFreeformConfig).toBe('boolean')
      expect(Array.isArray(cookie.fields)).toBe(true)
    })

    it('carries rich guided fields for the enabled handlers', () => {
      const cookie = catalog.authenticators.find((h) => h.handler === 'cookie_session')!
      expect(cookie.fields.map((f) => f.key)).toContain('check_session_url')

      const remoteJson = catalog.authorizers.find((h) => h.handler === 'remote_json')!
      const remoteField = remoteJson.fields.find((f) => f.key === 'remote')!
      expect(remoteField.type).toBe('url')
      expect(remoteField.required).toBe(true)

      const header = catalog.mutators.find((h) => h.handler === 'header')!
      const headersField = header.fields.find((f) => f.key === 'headers')!
      expect(headersField.type).toBe('kv')
      expect(headersField.required).toBe(true)
    })

    it('marks no-config handlers with hasFreeformConfig=false and no fields', () => {
      const noop = catalog.authenticators.find((h) => h.handler === 'noop')!
      expect(noop.fields).toEqual([])
      expect(noop.hasFreeformConfig).toBe(false)

      const allow = catalog.authorizers.find((h) => h.handler === 'allow')!
      expect(allow.fields).toEqual([])
      expect(allow.hasFreeformConfig).toBe(false)
    })
  })

  describe('isHandlerEnabled', () => {
    it('is true for handlers in the enabled set', () => {
      expect(isHandlerEnabled('authenticator', 'cookie_session')).toBe(true)
      expect(isHandlerEnabled('authorizer', 'remote_json')).toBe(true)
      expect(isHandlerEnabled('mutator', 'header')).toBe(true)
      expect(isHandlerEnabled('error', 'redirect')).toBe(true)
    })

    it('is false for handlers absent from the enabled set', () => {
      expect(isHandlerEnabled('authenticator', 'jwt')).toBe(false)
      expect(isHandlerEnabled('authorizer', 'deny')).toBe(false)
      expect(isHandlerEnabled('mutator', 'id_token')).toBe(false)
      expect(isHandlerEnabled('error', 'not_a_handler')).toBe(false)
    })
  })

  describe('getEnabledHandlerNames', () => {
    it('returns the raw enabled name list per kind', () => {
      expect(getEnabledHandlerNames('authorizer').sort()).toEqual(['allow', 'remote_json'])
    })
  })
})
