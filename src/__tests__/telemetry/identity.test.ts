import { describe, it, expect } from 'vitest'
import { serviceIdentity, tracingRequested } from '../../telemetry/identity.js'
import { logBase, traceFields } from '../../telemetry/log-correlation.js'

describe('serviceIdentity', () => {
  it('reads the same variables the SDK reads, so the two cannot name the service differently', () => {
    expect(serviceIdentity({
      OTEL_SERVICE_NAME: 'jinbe',
      OTEL_RESOURCE_ATTRIBUTES: 'service.version=1.2.3,deployment.environment=dev',
    })).toEqual({ service: 'jinbe', env: 'dev', version: '1.2.3' })
  })

  it('lets OTEL_SERVICE_NAME win over the attribute, as the SDK does', () => {
    expect(serviceIdentity({
      OTEL_SERVICE_NAME: 'wins',
      OTEL_RESOURCE_ATTRIBUTES: 'service.name=loses',
    }).service).toBe('wins')
  })

  it('answers null rather than a guess when nothing is configured', () => {
    expect(serviceIdentity({})).toEqual({ service: null, env: null, version: null })
  })

  it('survives a malformed attribute string instead of throwing at startup', () => {
    for (const raw of ['', '=', 'novalue=', '=nokey', 'a', ',,,']) {
      expect(() => serviceIdentity({ OTEL_RESOURCE_ATTRIBUTES: raw })).not.toThrow()
    }
    expect(serviceIdentity({ OTEL_RESOURCE_ATTRIBUTES: 'a,service.version=9' }).version).toBe('9')
  })

  it('keeps a value containing an equals sign whole', () => {
    expect(serviceIdentity({ OTEL_RESOURCE_ATTRIBUTES: 'service.version=1=2' }).version).toBe('1=2')
  })
})

describe('tracingRequested', () => {
  it('treats the absence of an endpoint as the off position', () => {
    expect(tracingRequested({})).toBe(false)
    expect(tracingRequested({ OTEL_SERVICE_NAME: 'jinbe' })).toBe(false)
  })

  it('is on for either the general or the traces-specific endpoint', () => {
    expect(tracingRequested({ OTEL_EXPORTER_OTLP_ENDPOINT: 'http://t:4317' })).toBe(true)
    expect(tracingRequested({ OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: 'http://t:4318/v1/traces' })).toBe(true)
  })
})

describe('log correlation', () => {
  it('adds nothing when no span is active, rather than a zeroed identifier', () => {
    // A zeroed trace id matches Grafana's derived-field regex and links to a trace that never was.
    expect(traceFields()).toEqual({})
  })

  it('omits a field it has nothing to say about', () => {
    const service = process.env.OTEL_SERVICE_NAME
    const attrs = process.env.OTEL_RESOURCE_ATTRIBUTES
    delete process.env.OTEL_SERVICE_NAME
    process.env.OTEL_RESOURCE_ATTRIBUTES = 'deployment.environment=dev'
    try {
      expect(logBase()).toEqual({ env: 'dev' })
    } finally {
      if (service !== undefined) process.env.OTEL_SERVICE_NAME = service
      if (attrs !== undefined) process.env.OTEL_RESOURCE_ATTRIBUTES = attrs
      else delete process.env.OTEL_RESOURCE_ATTRIBUTES
    }
  })
})
