import { ContentType } from '@openid4vc/utils'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../../tests/util.mjs'
import type { Jwk, JwkSet } from '../../common/jwk/z-jwk.js'
import { jwtHeaderFromJwtSigner } from '../../common/jwt/decode-jwt.js'
import type { JwtSigner } from '../../common/jwt/z-jwt.js'
import type { AuthorizationServerMetadata } from '../../metadata/authorization-server/z-authorization-server-metadata.js'
import { verifyIdTokenJwt } from '../verify-id-token.js'

const server = setupServer()

const signerJwk = {
  kty: 'EC',
  d: 'Y2KgM6WsS5lAiZMj96VaqPm0YpP67mclJ5yXbhM7oQE',
  crv: 'P-256',
  x: 'kazsvNpTiwE4mB6k-uLHNfexl_UysiJqNvDRO6SZE1A',
  y: 'VnWF5YzCR5ZWiugFM4rxPDviOWmMXU4pUVCRAdz-uLI',
} satisfies Jwk
const { d: __1, ...signerJwkPublic } = signerJwk

const signer = {
  method: 'jwk',
  alg: 'ES256',
  publicJwk: signerJwkPublic,
} satisfies JwtSigner

const signJwt = getSignJwtCallback([signerJwk])

const authorizationServerMetadata = {
  issuer: 'https://authorization-server.com',
  token_endpoint: 'https://authorization-server.com/token',
  jwks_uri: 'https://authorization-server.com/jwks.json',
} satisfies AuthorizationServerMetadata

describe('Verify ID Token JWT', () => {
  beforeAll(() => {
    server.listen()
  })

  afterEach(() => {
    server.resetHandlers()
  })

  afterAll(() => {
    server.close()
  })

  describe(`valid token`, async () => {
    const header = {
      ...jwtHeaderFromJwtSigner(signer),
      alg: 'ES256',
      typ: 'JWT',
    }

    const payload = {
      iss: authorizationServerMetadata.issuer,
      aud: ['my-client-id'],
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      sub: 'user-123',
      name: 'John Doe',
      nickname: 'marmite',
      website: 'https://example.com',
    }

    const { jwt } = await signJwt(signer, {
      header,
      payload,
    })

    server.resetHandlers(
      http.get(authorizationServerMetadata.jwks_uri, () =>
        HttpResponse.json({ keys: [signerJwkPublic] } satisfies JwkSet, {
          headers: { 'Content-Type': ContentType.JwkSet },
        })
      )
    )

    test('resolves when parameters are correct', async () => {
      await expect(
        verifyIdTokenJwt({
          idToken: jwt,
          clientId: 'my-client-id',
          callbacks: {
            verifyJwt: callbacks.verifyJwt,
            fetch,
          },
          authorizationServer: authorizationServerMetadata,
        })
      ).resolves.toMatchObject({
        header,
        payload,
      })
    })

    test('rejects when clientId is unexpected', async () => {
      await expect(
        verifyIdTokenJwt({
          idToken: jwt,
          clientId: 'mamma-mia',
          callbacks: {
            verifyJwt: callbacks.verifyJwt,
            fetch,
          },
          authorizationServer: authorizationServerMetadata,
        })
      ).rejects.toThrow(`jwt 'aud' does not match expected value`)
    })
  })
})
