import { getGlobalConfig, setGlobalConfig } from '@openid4vc/utils'
import { describe, expect, test } from 'vitest'
import { callbacks as oauth2TestCallbacks } from '../../oauth2/tests/util.mjs'
import {
  getOpenid4vpClientId,
  validateOpenid4vpClientId,
} from '../src/client-identifier-prefix/parse-client-identifier-prefix.js'

const callbacks = {
  getX509CertificateMetadata: () => ({ sanDnsNames: ['example.com'], sanUriNames: ['https://example.com'] }),
  hash: oauth2TestCallbacks.hash,
}

describe('Correctly parses the client identifier', () => {
  describe('legacy client_id_scheme', () => {
    test(`correctly handles legacy client_id_scheme 'entity_id'`, async () => {
      const client = await validateOpenid4vpClientId({
        jar: {
          signer: {
            method: 'federation',
            alg: '',
            kid: '',
            // @ts-ignore
            publicJwk: {},
          },
        },
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'https://example.com',
          nonce: 'nonce',
          response_type: 'vp_token',
          client_id_scheme: 'entity_id',
        },
        callbacks,
      })

      expect(client).toEqual({
        clientMetadata: undefined,
        effective: 'https://example.com',
        identifier: 'https://example.com',
        original: {
          clientId: 'https://example.com',
          clientIdScheme: 'entity_id',
        },
        prefix: 'openid_federation',
        trustChain: undefined,
      })
    })

    test(`correctly handles legacy client_id_scheme 'did'`, async () => {
      const client = await validateOpenid4vpClientId({
        jar: {
          signer: {
            method: 'did',
            didUrl: 'did:example:123#key-1',
            // @ts-expect-error
            publicJwk: { kid: 'did:example:123#key-1' },
          },
        },
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'did:example:123',
          nonce: 'nonce',
          response_type: 'vp_token',
          client_id_scheme: 'did',
        },
        callbacks,
      })

      expect(client).toEqual({
        clientMetadata: undefined,
        identifier: 'did:example:123',
        didUrl: 'did:example:123#key-1',
        effective: 'did:example:123',
        original: {
          clientId: 'did:example:123',
          clientIdScheme: 'did',
        },
        prefix: 'decentralized_identifier',
      })
    })

    test(`correctly handles legacy client_id_scheme 'x509_san_dns'`, async () => {
      const client = await validateOpenid4vpClientId({
        // @ts-expect-error
        jar: { signer: { method: 'x5c', x5c: ['certificate'] } },
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'example.com',
          redirect_uri: 'https://example.com',
          nonce: 'nonce',
          response_type: 'vp_token',
          client_id_scheme: 'x509_san_dns',
        },
        callbacks,
      })

      expect(client).toEqual({
        clientMetadata: undefined,
        identifier: 'example.com',
        effective: 'example.com',
        original: {
          clientId: 'example.com',
          clientIdScheme: 'x509_san_dns',
        },
        prefix: 'x509_san_dns',
        x5c: ['certificate'],
      })
    })

    test(`correctly handles legacy client_id_scheme 'x509_san_uri'`, async () => {
      const client = await validateOpenid4vpClientId({
        // @ts-expect-error
        jar: { signer: { method: 'x5c', x5c: ['certificate'] } },
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'https://example.com',
          redirect_uri: 'https://example.com',
          nonce: 'nonce',
          response_type: 'vp_token',
          client_id_scheme: 'x509_san_uri',
        },
        callbacks,
      })

      expect(client).toEqual({
        clientMetadata: undefined,
        identifier: 'https://example.com',
        original: {
          clientId: 'https://example.com',
          clientIdScheme: 'x509_san_uri',
        },
        effective: 'https://example.com',
        prefix: 'x509_san_uri',
        x5c: ['certificate'],
      })
    })

    test('correctly assumes no client_id_scheme as pre-registered', async () => {
      const client = await validateOpenid4vpClientId({
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'pre-registered client',
          nonce: 'nonce',
          response_type: 'vp_token',
        },
        callbacks,
      })

      expect(client).toEqual({
        identifier: 'pre-registered client',
        effective: 'pre-registered client',
        prefix: 'pre-registered',
        original: {
          clientId: 'pre-registered client',
        },
      })
    })

    test('correctly applies pre-registered', async () => {
      const client = await validateOpenid4vpClientId({
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'pre-registered client',
          nonce: 'nonce',
          response_type: 'vp_token',
          client_id_scheme: 'pre-registered',
        },
        callbacks,
      })

      expect(client).toEqual({
        identifier: 'pre-registered client',
        effective: 'pre-registered client',
        prefix: 'pre-registered',
        original: {
          clientId: 'pre-registered client',
          clientIdScheme: 'pre-registered',
        },
      })
    })
  })

  describe('client id prefix', () => {
    test(`correctly handles client id prefix 'entity_id'`, async () => {
      const client = await validateOpenid4vpClientId({
        jar: {
          signer: {
            method: 'federation',
            kid: '',
            alg: '',
            // @ts-ignore
            publicJwk: {},
          },
        },
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'https://example.com',
          nonce: 'nonce',
          response_type: 'vp_token',
        },
        callbacks,
      })

      expect(client).toEqual({
        identifier: 'https://example.com',
        effective: 'https://example.com',
        prefix: 'openid_federation',
        trustChain: undefined,
        original: {
          clientId: 'https://example.com',
        },
      })
    })

    test(`correctly handles client id prefix 'did'`, async () => {
      const client = await validateOpenid4vpClientId({
        jar: {
          signer: {
            method: 'did',
            didUrl: 'did:example:123#key-1',
            // @ts-expect-error
            publicJwk: {
              kid: 'did:example:123#key-1',
            },
          },
        },
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'did:example:123',
          nonce: 'nonce',
          response_type: 'vp_token',
        },
        callbacks,
      })

      expect(client).toEqual({
        clientMetadata: undefined,
        identifier: 'did:example:123',
        didUrl: 'did:example:123#key-1',
        effective: 'did:example:123',
        prefix: 'decentralized_identifier',
        original: {
          clientId: 'did:example:123',
        },
      })
    })

    test(`correctly handles client id prefix 'decentralized_identifier'`, async () => {
      const client = await validateOpenid4vpClientId({
        jar: {
          signer: {
            method: 'did',
            didUrl: 'did:example:123#key-1',
            // @ts-expect-error
            publicJwk: {
              kid: 'did:example:123#key-1',
            },
          },
        },
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'decentralized_identifier:did:example:123',
          nonce: 'nonce',
          response_type: 'vp_token',
        },
        callbacks,
      })

      expect(client).toEqual({
        clientMetadata: undefined,
        didUrl: 'did:example:123#key-1',
        identifier: 'did:example:123',
        effective: 'decentralized_identifier:did:example:123',
        prefix: 'decentralized_identifier',
        original: {
          clientId: 'decentralized_identifier:did:example:123',
        },
      })
    })

    test(`correctly handles client id prefix 'x509_san_dns'`, async () => {
      const client = await validateOpenid4vpClientId({
        // @ts-expect-error
        jar: { signer: { method: 'x5c', x5c: ['certificate'] } },
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'x509_san_dns:example.com',
          redirect_uri: 'https://example.com',
          nonce: 'nonce',
          response_type: 'vp_token',
        },
        callbacks,
      })

      expect(client).toEqual({
        clientMetadata: undefined,
        identifier: 'example.com',
        effective: 'x509_san_dns:example.com',
        original: {
          clientId: 'x509_san_dns:example.com',
        },
        prefix: 'x509_san_dns',
        x5c: ['certificate'],
      })
    })

    test(`correctly handles legacy client id prefix 'x509_san_uri'`, async () => {
      const client = await validateOpenid4vpClientId({
        // @ts-expect-error
        jar: { signer: { method: 'x5c', x5c: ['certificate'] } },
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'x509_san_uri:https://example.com',
          redirect_uri: 'https://example.com',
          nonce: 'nonce',
          response_type: 'vp_token',
        },
        callbacks,
      })

      expect(client).toEqual({
        clientMetadata: undefined,
        identifier: 'https://example.com',
        effective: 'x509_san_uri:https://example.com',
        original: {
          clientId: 'x509_san_uri:https://example.com',
        },
        prefix: 'x509_san_uri',
        x5c: ['certificate'],
      })
    })

    test(`correctly handles client id prefix 'x509_hash'`, async () => {
      const client = await validateOpenid4vpClientId({
        // @ts-expect-error
        jar: { signer: { method: 'x5c', x5c: ['certificate'] } },
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'x509_hash:2ipT8gPhDJOK76YJvl98T8BSOd4Zjld1k6KtMuLU90s',
          redirect_uri: 'https://example.com',
          nonce: 'nonce',
          response_type: 'vp_token',
        },
        callbacks,
      })

      expect(client).toEqual({
        clientMetadata: undefined,
        identifier: '2ipT8gPhDJOK76YJvl98T8BSOd4Zjld1k6KtMuLU90s',
        effective: 'x509_hash:2ipT8gPhDJOK76YJvl98T8BSOd4Zjld1k6KtMuLU90s',
        original: {
          clientId: 'x509_hash:2ipT8gPhDJOK76YJvl98T8BSOd4Zjld1k6KtMuLU90s',
        },
        prefix: 'x509_hash',
        x5c: ['certificate'],
      })
    })

    test('throws error if the x509_hash does not match', async () => {
      await expect(
        validateOpenid4vpClientId({
          // @ts-expect-error
          jar: { signer: { method: 'x5c', x5c: ['certificate2'] } },
          authorizationRequestPayload: {
            response_mode: 'direct_post',
            client_id: 'x509_hash:2ipT8gPhDJOK76YJvl98T8BSOd4Zjld1k6KtMuLU90s',
            redirect_uri: 'https://example.com',
            nonce: 'nonce',
            response_type: 'vp_token',
          },
          callbacks,
        })
      ).rejects.toThrowError(
        "Invalid client identifier. Expected the base64url encoded sha-256 hash of the leaf x5c certificate ('qaHUFMOlSq7yMw5DbiyQRppMLnwLc63TtTZOLjNvv5I') to match the client identifier '2ipT8gPhDJOK76YJvl98T8BSOd4Zjld1k6KtMuLU90s'"
      )
    })

    test('correctly assumes no client id prefix as pre-registered', async () => {
      const client = await validateOpenid4vpClientId({
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'pre-registered client',
          nonce: 'nonce',
          response_type: 'vp_token',
        },
        callbacks,
      })

      expect(client).toEqual({
        clientMetadata: undefined,
        effective: 'pre-registered client',
        identifier: 'pre-registered client',
        prefix: 'pre-registered',
        original: {
          clientId: 'pre-registered client',
        },
      })
    })

    test('correctly applies pre-registered', async () => {
      const client = await validateOpenid4vpClientId({
        authorizationRequestPayload: {
          response_mode: 'direct_post',
          client_id: 'pre-registered client',
          nonce: 'nonce',
          response_type: 'vp_token',
        },
        callbacks,
      })

      expect(client).toEqual({
        clientMetadata: undefined,
        identifier: 'pre-registered client',
        effective: 'pre-registered client',
        prefix: 'pre-registered',
        original: {
          clientId: 'pre-registered client',
        },
      })
    })
  })

  describe('getOpenid4vpClientId', () => {
    test('handles http url if allow insecure ', () => {
      const beforeValue = getGlobalConfig().allowInsecureUrls

      expect(() =>
        getOpenid4vpClientId({
          responseMode: 'direct_post.jwt',
          clientId: 'http://federation.com/entity',
        })
      ).toThrow(`Failed to parse client identifier. Unsupported client_id 'http://federation.com/entity'.`)

      setGlobalConfig({ allowInsecureUrls: true })
      expect(
        getOpenid4vpClientId({
          responseMode: 'direct_post.jwt',
          clientId: 'http://federation.com/entity',
        })
      ).toEqual({
        clientIdIdentifier: 'http://federation.com/entity',
        clientIdPrefix: 'openid_federation',
        effectiveClientId: 'http://federation.com/entity',
        effectiveClientIdPrefix: 'https',
        original: {
          clientId: 'http://federation.com/entity',
        },
      })

      setGlobalConfig({ allowInsecureUrls: beforeValue })
    })
  })
})
