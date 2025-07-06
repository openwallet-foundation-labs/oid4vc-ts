import { getGlobalConfig, setGlobalConfig } from '@openid4vc/utils'
import { describe, expect, test } from 'vitest'
import { callbacks as oauth2TestCallbacks } from '../../oauth2/tests/util.mjs'
import {
  getOpenid4vpClientId,
  validateOpenid4vpClientId,
} from '../src/client-identifier-scheme/parse-client-identifier-scheme.js'

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

      expect(client).toMatchObject({
        identifier: 'https://example.com',
        originalValue: 'https://example.com',
        scheme: 'https',
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

      expect(client).toMatchObject({
        identifier: 'did:example:123',
        originalValue: 'did:example:123',
        scheme: 'did',
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

      expect(client).toMatchObject({
        identifier: 'example.com',
        originalValue: 'x509_san_dns:example.com',
        scheme: 'x509_san_dns',
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

      expect(client).toMatchObject({
        identifier: 'https://example.com',
        originalValue: 'x509_san_uri:https://example.com',
        scheme: 'x509_san_uri',
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

      expect(client).toMatchObject({
        identifier: 'pre-registered client',
        originalValue: 'pre-registered client',
        scheme: 'pre-registered',
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

      expect(client).toMatchObject({
        identifier: 'pre-registered client',
        originalValue: 'pre-registered client',
        scheme: 'pre-registered',
      })
    })
  })

  describe('client_id_scheme', () => {
    test(`correctly handles client_id_scheme 'entity_id'`, async () => {
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

      expect(client).toMatchObject({
        identifier: 'https://example.com',
        originalValue: 'https://example.com',
        scheme: 'https',
        trustChain: undefined,
      })
    })

    test(`correctly handles client_id_scheme 'did'`, async () => {
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

      expect(client).toMatchObject({
        identifier: 'did:example:123',
        originalValue: 'did:example:123',
        scheme: 'did',
      })
    })

    test(`correctly handles client_id_scheme 'x509_san_dns'`, async () => {
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

      expect(client).toMatchObject({
        identifier: 'example.com',
        originalValue: 'x509_san_dns:example.com',
        scheme: 'x509_san_dns',
      })
    })

    test(`correctly handles legacy client_id_scheme 'x509_san_uri'`, async () => {
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

      expect(client).toMatchObject({
        identifier: 'https://example.com',
        originalValue: 'x509_san_uri:https://example.com',
        scheme: 'x509_san_uri',
      })
    })

    test(`correctly handles client_id_scheme 'x509_hash'`, async () => {
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

      expect(client).toMatchObject({
        identifier: '2ipT8gPhDJOK76YJvl98T8BSOd4Zjld1k6KtMuLU90s',
        originalValue: 'x509_hash:2ipT8gPhDJOK76YJvl98T8BSOd4Zjld1k6KtMuLU90s',
        scheme: 'x509_hash',
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

      expect(client).toMatchObject({
        identifier: 'pre-registered client',
        originalValue: 'pre-registered client',
        scheme: 'pre-registered',
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

      expect(client).toMatchObject({
        identifier: 'pre-registered client',
        originalValue: 'pre-registered client',
        scheme: 'pre-registered',
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
        clientId: 'http://federation.com/entity',
        clientIdScheme: 'https',
      })

      setGlobalConfig({ allowInsecureUrls: beforeValue })
    })
  })
})
