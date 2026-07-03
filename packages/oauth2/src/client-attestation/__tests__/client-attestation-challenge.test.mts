import { ContentType, Headers, ValidationError } from '@openid4vc/utils'
import * as jose from 'jose'
import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../../tests/util.mjs'
import type { AccessTokenResponse } from '../../access-token/z-access-token'
import { clientAuthenticationClientAttestationJwt } from '../../client-authentication'
import type { Jwk } from '../../common/jwk/z-jwk'
import { decodeJwt } from '../../common/jwt/decode-jwt'
import { Oauth2Error } from '../../error/Oauth2Error'
import type { AuthorizationServerMetadata } from '../../metadata/authorization-server/z-authorization-server-metadata'
import { clientCredentialsGrantIdentifier } from '../../z-grant-type'
import { createClientAttestationJwt } from '../client-attestation'
import {
  requestClientAttestationChallenge,
  shouldRetryAuthorizationServerRequestWithClientAttestationChallenge,
} from '../client-attestation-challenge'
import {
  oauthClientAttestationChallengeHeader,
  oauthClientAttestationPopHeader,
  zClientAttestationPopJwtHeader,
  zClientAttestationPopJwtPayload,
} from '../z-client-attestation'

const server = setupServer()

const mockAuthorizationServerMetadata: AuthorizationServerMetadata = {
  issuer: 'https://auth.example.com',
  token_endpoint: 'https://auth.example.com/token',
  authorization_endpoint: 'https://auth.example.com/authorize',
  challenge_endpoint: 'https://auth.example.com/challenge',
  grant_types_supported: [clientCredentialsGrantIdentifier],
}

async function generateEs256Key() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return {
    privateJwk: (await jose.exportJWK(privateKey)) as Jwk,
    publicJwk: (await jose.exportJWK(publicKey)) as Jwk,
  }
}

function decodePop(compactPop: string) {
  return decodeJwt({
    jwt: compactPop,
    headerSchema: zClientAttestationPopJwtHeader,
    payloadSchema: zClientAttestationPopJwtPayload,
  })
}

describe('Client Attestation challenge', () => {
  let attester: Awaited<ReturnType<typeof generateEs256Key>>
  let instance: Awaited<ReturnType<typeof generateEs256Key>>
  let signJwt: ReturnType<typeof getSignJwtCallback>
  let clientAttestationJwt: string

  beforeAll(async () => {
    server.listen()

    attester = await generateEs256Key()
    instance = await generateEs256Key()
    signJwt = getSignJwtCallback([attester.privateJwk, instance.privateJwk])

    clientAttestationJwt = await createClientAttestationJwt({
      callbacks: { signJwt },
      clientId: 'wallet',
      confirmation: { jwk: instance.publicJwk },
      expiresAt: new Date(Date.now() + 3600 * 1000),
      signer: { method: 'jwk', alg: 'ES256', publicJwk: attester.publicJwk },
    })
  })

  afterEach(() => {
    server.resetHandlers()
  })

  afterAll(() => {
    server.close()
  })

  describe('requestClientAttestationChallenge', () => {
    test('fetches the challenge from the challenge_endpoint', async () => {
      server.resetHandlers(
        http.post(mockAuthorizationServerMetadata.challenge_endpoint as string, () =>
          HttpResponse.json(
            { attestation_challenge: 'challenge-abc' },
            { headers: { 'Content-Type': ContentType.Json } }
          )
        )
      )

      const result = await requestClientAttestationChallenge({
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: { fetch },
      })

      expect(result.challenge).toBe('challenge-abc')
    })

    test('throws when the authorization server has no challenge_endpoint', async () => {
      await expect(
        requestClientAttestationChallenge({
          authorizationServerMetadata: { ...mockAuthorizationServerMetadata, challenge_endpoint: undefined },
          callbacks: { fetch },
        })
      ).rejects.toThrow(Oauth2Error)
    })

    test('throws a ValidationError when the response body is invalid', async () => {
      server.resetHandlers(
        http.post(mockAuthorizationServerMetadata.challenge_endpoint as string, () =>
          HttpResponse.json({ not_a_challenge: true }, { headers: { 'Content-Type': ContentType.Json } })
        )
      )

      await expect(
        requestClientAttestationChallenge({
          authorizationServerMetadata: mockAuthorizationServerMetadata,
          callbacks: { fetch },
        })
      ).rejects.toThrow(ValidationError)
    })
  })

  describe('clientAuthenticationClientAttestationJwt', () => {
    test('includes the statically configured challenge in the PoP', async () => {
      const headers = new Headers()
      await clientAuthenticationClientAttestationJwt({
        clientAttestationJwt,
        callbacks: { signJwt, generateRandom: callbacks.generateRandom },
        challenge: 'static-challenge',
      })({
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        url: mockAuthorizationServerMetadata.token_endpoint,
        method: 'POST',
        headers,
        contentType: ContentType.XWwwFormUrlencoded,
        body: {},
      })

      const { payload } = decodePop(headers.get(oauthClientAttestationPopHeader) as string)
      expect(payload.challenge).toBe('static-challenge')
    })

    test('prefers a server-provided attestationChallenge over the static challenge', async () => {
      const headers = new Headers()
      await clientAuthenticationClientAttestationJwt({
        clientAttestationJwt,
        callbacks: { signJwt, generateRandom: callbacks.generateRandom },
        challenge: 'static-challenge',
      })({
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        url: mockAuthorizationServerMetadata.token_endpoint,
        method: 'POST',
        headers,
        contentType: ContentType.XWwwFormUrlencoded,
        body: {},
        attestationChallenge: 'server-challenge',
      })

      const { payload } = decodePop(headers.get(oauthClientAttestationPopHeader) as string)
      expect(payload.challenge).toBe('server-challenge')
    })
  })

  describe('shouldRetryAuthorizationServerRequestWithClientAttestationChallenge', () => {
    test('retries and extracts the challenge on use_attestation_challenge', () => {
      const result = shouldRetryAuthorizationServerRequestWithClientAttestationChallenge({
        errorResponse: { error: 'use_attestation_challenge' },
        responseHeaders: new Headers({ [oauthClientAttestationChallengeHeader]: 'fresh-challenge' }),
      })

      expect(result).toEqual({ retry: true, attestationChallenge: 'fresh-challenge' })
    })

    test('does not retry for other errors', () => {
      const result = shouldRetryAuthorizationServerRequestWithClientAttestationChallenge({
        errorResponse: { error: 'invalid_client' },
        responseHeaders: new Headers(),
      })

      expect(result).toEqual({ retry: false })
    })

    test('throws when the challenge header is missing', () => {
      expect(() =>
        shouldRetryAuthorizationServerRequestWithClientAttestationChallenge({
          errorResponse: { error: 'use_attestation_challenge' },
          responseHeaders: new Headers(),
        })
      ).toThrow(Oauth2Error)
    })
  })

  describe('reactive challenge retry in the token flow', () => {
    test('retries the token request with the server-provided challenge', async () => {
      const { retrieveClientCredentialsAccessToken } = await import('../../access-token/retrieve-access-token')

      const mockResponse: AccessTokenResponse = {
        access_token: 'test_access_token',
        token_type: 'Bearer',
        expires_in: 3600,
      }

      const popChallenges: (string | undefined)[] = []
      let call = 0

      server.resetHandlers(
        http.post(mockAuthorizationServerMetadata.token_endpoint, async ({ request }) => {
          const pop = request.headers.get(oauthClientAttestationPopHeader)
          popChallenges.push(pop ? decodePop(pop).payload.challenge : undefined)

          call += 1
          if (call === 1) {
            return HttpResponse.json(
              { error: 'use_attestation_challenge' },
              {
                status: 400,
                headers: {
                  'Content-Type': ContentType.Json,
                  [oauthClientAttestationChallengeHeader]: 'retry-challenge',
                },
              }
            )
          }

          return HttpResponse.json(mockResponse, { headers: { 'Content-Type': ContentType.Json } })
        })
      )

      const result = await retrieveClientCredentialsAccessToken({
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: {
          ...callbacks,
          signJwt,
          fetch,
          clientAuthentication: clientAuthenticationClientAttestationJwt({
            clientAttestationJwt,
            callbacks: { signJwt, generateRandom: callbacks.generateRandom },
          }),
        },
      })

      expect(result.accessTokenResponse).toEqual(mockResponse)
      // First attempt has no challenge, retry carries the server-provided challenge.
      expect(popChallenges).toEqual([undefined, 'retry-challenge'])
    })

    test('surfaces a fresh challenge from a successful response for reuse (§6.2)', async () => {
      const { retrieveClientCredentialsAccessToken } = await import('../../access-token/retrieve-access-token')

      const mockResponse: AccessTokenResponse = {
        access_token: 'test_access_token',
        token_type: 'Bearer',
        expires_in: 3600,
      }

      server.resetHandlers(
        http.post(mockAuthorizationServerMetadata.token_endpoint, () =>
          HttpResponse.json(mockResponse, {
            headers: {
              'Content-Type': ContentType.Json,
              [oauthClientAttestationChallengeHeader]: 'next-challenge',
            },
          })
        )
      )

      const result = await retrieveClientCredentialsAccessToken({
        authorizationServerMetadata: mockAuthorizationServerMetadata,
        callbacks: {
          ...callbacks,
          signJwt,
          fetch,
          clientAuthentication: clientAuthenticationClientAttestationJwt({
            clientAttestationJwt,
            callbacks: { signJwt, generateRandom: callbacks.generateRandom },
          }),
        },
      })

      expect(result.attestationChallenge).toBe('next-challenge')
    })
  })
})
