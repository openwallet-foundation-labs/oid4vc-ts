import { describe, expect, test } from 'vitest'
import { parseClientIdentifier } from '../src/client-identifier-scheme/parse-client-identifier-scheme'

describe('Correctly parses the client identifier', () => {
  describe('legacy client_id_scheme', () => {
  test(`correctly handles legacy client_id_schme 'entity_id'`, () => {
    const client = parseClientIdentifier({
      request: {
        response_mode: 'direct_post',
        client_id: 'https://example.com',
        nonce: 'nonce',
        response_type: 'vp_token',
        client_id_scheme: 'entity_id',
      },
      callbacks: {},
    })

    expect(client).toMatchObject({
      identifier: 'https://example.com',
      originalValue: 'https://example.com',
      scheme: 'https',
      trustChain: undefined,
    })
  })

  test(`correctly handles legacy client_id_schme 'did'`, () => {
    const client = parseClientIdentifier({
      // @ts-expect-error
      jar: { signer: { publicJwk: { kid: 'did:example:123#key-1' } } },
      request: {
        response_mode: 'direct_post',
        client_id: 'did:example:123#key-1',
        nonce: 'nonce',
        response_type: 'vp_token',
        client_id_scheme: 'did',
      },
      callbacks: {},
    })

    expect(client).toMatchObject({
      identifier: 'did:example:123#key-1',
      originalValue: 'did:example:123#key-1',
      scheme: 'did',
    })
  })

  test(`correctly handles legacy client_id_schme 'x509_san_dns'`, () => {
    const client = parseClientIdentifier({
      // @ts-expect-error
      jar: { signer: { method: 'x5c', x5c: ['certificate'] } },
      request: {
        response_mode: 'direct_post',
        client_id: 'example.com',
        redirect_uri: 'https://example.com',
        nonce: 'nonce',
        response_type: 'vp_token',
        client_id_scheme: 'x509_san_dns',
      },
      callbacks: {
        getX509CertificateMetadata: () => ({ sanDnsNames: ['example.com'], sanUriNames: [] }),
      },
    })

    expect(client).toMatchObject({
      identifier: 'example.com',
      originalValue: 'x509_san_dns:example.com',
      scheme: 'x509_san_dns',
    })
  })

  test(`correctly handles legacy client_id_schme 'x509_san_uri'`, () => {
    const client = parseClientIdentifier({
      // @ts-expect-error
      jar: { signer: { method: 'x5c', x5c: ['certificate'] } },
      request: {
        response_mode: 'direct_post',
        client_id: 'https://example.com',
        redirect_uri: 'https://example.com',
        nonce: 'nonce',
        response_type: 'vp_token',
        client_id_scheme: 'x509_san_uri',
      },
      callbacks: {
        getX509CertificateMetadata: () => ({ sanDnsNames: [], sanUriNames: ['https://example.com'] }),
      },
    })

    expect(client).toMatchObject({
      identifier: 'https://example.com',
      originalValue: 'x509_san_uri:https://example.com',
      scheme: 'x509_san_uri',
    })
  })

  test('correctly assumes no client_id_scheme as pre-registered', () => {
    const client = parseClientIdentifier({
      request: {
        response_mode: 'direct_post',
        client_id: 'pre-registered client',
        nonce: 'nonce',
        response_type: 'vp_token',
      },
      callbacks: {},
    })

    expect(client).toMatchObject({
      identifier: 'pre-registered client',
      originalValue: 'pre-registered client',
      scheme: 'pre-registered',
    })
  })

  test('correctly applies pre-registered', () => {
    const client = parseClientIdentifier({
      request: {
        response_mode: 'direct_post',
        client_id: 'pre-registered client',
        nonce: 'nonce',
        response_type: 'vp_token',
        client_id_scheme: 'pre-registered',
      },
      callbacks: {},
    })

    expect(client).toMatchObject({
      identifier: 'pre-registered client',
      originalValue: 'pre-registered client',
      scheme: 'pre-registered',
    })
  })
})


  describe('client_id_scheme', () => {
  test(`correctly handles client_id_schme 'entity_id'`, () => {
    const client = parseClientIdentifier({
      request: {
        response_mode: 'direct_post',
        client_id: 'https://example.com',
        nonce: 'nonce',
        response_type: 'vp_token',
      },
      callbacks: {},
    })

    expect(client).toMatchObject({
      identifier: 'https://example.com',
      originalValue: 'https://example.com',
      scheme: 'https',
      trustChain: undefined,
    })
  })

  test(`correctly handles client_id_schme 'did'`, () => {
    const client = parseClientIdentifier({
      // @ts-expect-error
      jar: { signer: { publicJwk: { kid: 'did:example:123#key-1' } } },
      request: {
        response_mode: 'direct_post',
        client_id: 'did:example:123#key-1',
        nonce: 'nonce',
        response_type: 'vp_token',
      },
      callbacks: {},
    })

    expect(client).toMatchObject({
      identifier: 'did:example:123#key-1',
      originalValue: 'did:example:123#key-1',
      scheme: 'did',
    })
  })

  test(`correctly handles client_id_schme 'x509_san_dns'`, () => {
    const client = parseClientIdentifier({
      // @ts-expect-error
      jar: { signer: { method: 'x5c', x5c: ['certificate'] } },
      request: {
        response_mode: 'direct_post',
        client_id: 'x509_san_dns:example.com',
        redirect_uri: 'https://example.com',
        nonce: 'nonce',
        response_type: 'vp_token',
      },
      callbacks: {
        getX509CertificateMetadata: () => ({ sanDnsNames: ['example.com'], sanUriNames: [] }),
      },
    })

    expect(client).toMatchObject({
      identifier: 'example.com',
      originalValue: 'x509_san_dns:example.com',
      scheme: 'x509_san_dns',
    })
  })

  test(`correctly handles legacy client_id_schme 'x509_san_uri'`, () => {
    const client = parseClientIdentifier({
      // @ts-expect-error
      jar: { signer: { method: 'x5c', x5c: ['certificate'] } },
      request: {
        response_mode: 'direct_post',
        client_id: 'x509_san_uri:https://example.com',
        redirect_uri: 'https://example.com',
        nonce: 'nonce',
        response_type: 'vp_token',
      },
      callbacks: {
        getX509CertificateMetadata: () => ({ sanDnsNames: [], sanUriNames: ['https://example.com'] }),
      },
    })

    expect(client).toMatchObject({
      identifier: 'https://example.com',
      originalValue: 'x509_san_uri:https://example.com',
      scheme: 'x509_san_uri',
    })
  })

  test('correctly assumes no client_id_scheme as pre-registered', () => {
    const client = parseClientIdentifier({
      request: {
        response_mode: 'direct_post',
        client_id: 'pre-registered client',
        nonce: 'nonce',
        response_type: 'vp_token',
      },
      callbacks: {},
    })

    expect(client).toMatchObject({
      identifier: 'pre-registered client',
      originalValue: 'pre-registered client',
      scheme: 'pre-registered',
    })
  })

  test('correctly applies pre-registered', () => {
    const client = parseClientIdentifier({
      request: {
        response_mode: 'direct_post',
        client_id: 'pre-registered:pre-registered client',
        nonce: 'nonce',
        response_type: 'vp_token',
      },
      callbacks: {},
    })

    expect(client).toMatchObject({
      identifier: 'pre-registered client',
      originalValue: 'pre-registered:pre-registered client',
      scheme: 'pre-registered',
    })
  })
})
})
