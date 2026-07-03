import { ContentType, Headers } from '@openid4vc/utils'
import * as jose from 'jose'
import { beforeAll, describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../../tests/util.mjs'
import { verifyPreAuthorizedCodeAccessTokenRequest } from '../../access-token/verify-access-token-request'
import { clientAuthenticationClientAttestationJwtDpop } from '../../client-authentication'
import type { Jwk } from '../../common/jwk/z-jwk'
import { decodeJwt } from '../../common/jwt/decode-jwt'
import { createDpopJwt } from '../../dpop/dpop'
import { zDpopJwtHeader, zDpopJwtPayload } from '../../dpop/z-dpop'
import type { AuthorizationServerMetadata } from '../../metadata/authorization-server/z-authorization-server-metadata'
import { preAuthorizedCodeGrantIdentifier } from '../../z-grant-type'
import { createClientAttestationJwt } from '../client-attestation'
import { oauthClientAttestationHeader, oauthClientAttestationPopHeader } from '../z-client-attestation'

const request = {
  headers: new Headers(),
  method: 'POST',
  url: 'https://request.com/token',
} as const

const authorizationServerMetadata = {
  issuer: 'https://server.com',
  token_endpoint: 'https://server.com/token',
} satisfies AuthorizationServerMetadata

async function generateEs256Key() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return {
    privateJwk: (await jose.exportJWK(privateKey)) as Jwk,
    publicJwk: (await jose.exportJWK(publicKey)) as Jwk,
  }
}

function decodeDpop(compact: string) {
  return decodeJwt({ jwt: compact, headerSchema: zDpopJwtHeader, payloadSchema: zDpopJwtPayload })
}

describe('DPoP-bound client attestation (attest_jwt_client_auth_dpop)', () => {
  // Attester signs the client attestation; the instance key is both the confirmation key and the DPoP key.
  let attester: Awaited<ReturnType<typeof generateEs256Key>>
  let instance: Awaited<ReturnType<typeof generateEs256Key>>
  let other: Awaited<ReturnType<typeof generateEs256Key>>
  let signJwt: ReturnType<typeof getSignJwtCallback>
  let clientAttestationJwt: string

  beforeAll(async () => {
    attester = await generateEs256Key()
    instance = await generateEs256Key()
    other = await generateEs256Key()
    signJwt = getSignJwtCallback([attester.privateJwk, instance.privateJwk, other.privateJwk])

    clientAttestationJwt = await createClientAttestationJwt({
      callbacks: { signJwt },
      clientId: 'wallet',
      confirmation: { jwk: instance.publicJwk },
      expiresAt: new Date(Date.now() + 3600 * 1000),
      signer: { method: 'jwk', alg: 'ES256', publicJwk: attester.publicJwk },
    })
  })

  describe('clientAuthenticationClientAttestationJwtDpop', () => {
    test('emits the attestation + a single DPoP proof (no separate PoP header)', async () => {
      const headers = new Headers()
      await clientAuthenticationClientAttestationJwtDpop({
        clientAttestationJwt,
        callbacks: { signJwt, generateRandom: callbacks.generateRandom, hash: callbacks.hash },
        challenge: 'challenge-123',
      })({
        authorizationServerMetadata,
        url: authorizationServerMetadata.token_endpoint,
        method: 'POST',
        headers,
        contentType: ContentType.XWwwFormUrlencoded,
        body: {},
      })

      expect(headers.get(oauthClientAttestationHeader)).toBe(clientAttestationJwt)
      expect(headers.get(oauthClientAttestationPopHeader)).toBeNull()

      const dpop = headers.get('DPoP')
      expect(dpop).not.toBeNull()
      const { header, payload } = decodeDpop(dpop as string)
      expect(header.typ).toBe('dpop+jwt')
      expect(header.jwk).toEqual(instance.publicJwk)
      expect(payload.htu).toBe(authorizationServerMetadata.token_endpoint)
      expect(payload.htm).toBe('POST')
      expect(payload.nonce).toBe('challenge-123')
    })

    test('prefers a server-provided attestationChallenge over the static challenge', async () => {
      const headers = new Headers()
      await clientAuthenticationClientAttestationJwtDpop({
        clientAttestationJwt,
        callbacks: { signJwt, generateRandom: callbacks.generateRandom, hash: callbacks.hash },
        challenge: 'static-challenge',
      })({
        authorizationServerMetadata,
        url: authorizationServerMetadata.token_endpoint,
        method: 'POST',
        headers,
        contentType: ContentType.XWwwFormUrlencoded,
        body: {},
        attestationChallenge: 'server-challenge',
      })

      const { payload } = decodeDpop(headers.get('DPoP') as string)
      expect(payload.nonce).toBe('server-challenge')
    })
  })

  describe('authorization server verification', () => {
    async function createCombinedDpopProof(signerJwk: { privateJwk: Jwk; publicJwk: Jwk }, nonce?: string) {
      return createDpopJwt({
        callbacks: { ...callbacks, signJwt },
        request,
        signer: { method: 'jwk', alg: 'ES256', publicJwk: signerJwk.publicJwk },
        nonce,
      })
    }

    function verify(dpopJwt: string, extra?: { expectedNonce?: string }) {
      return verifyPreAuthorizedCodeAccessTokenRequest({
        authorizationServerMetadata,
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'code-123',
        },
        grant: { grantType: preAuthorizedCodeGrantIdentifier, preAuthorizedCode: 'code-123' },
        callbacks,
        expectedPreAuthorizedCode: 'code-123',
        request,
        dpop: { required: true, jwt: dpopJwt, allowedSigningAlgs: ['ES256'], expectedNonce: extra?.expectedNonce },
        clientAttestation: { required: true, clientAttestationJwt },
      })
    }

    test('verifies a combined-mode request and returns no separate PoP', async () => {
      const dpopJwt = await createCombinedDpopProof(instance)

      const result = await verify(dpopJwt)

      expect(result.clientAttestation?.clientAttestation.payload.sub).toBe('wallet')
      expect(result.clientAttestation?.clientAttestationPop).toBeUndefined()
      expect(result.dpop?.jwkThumbprint).toEqual(expect.any(String))
    })

    test('rejects when the DPoP key does not match the attestation cnf jwk', async () => {
      const dpopJwt = await createCombinedDpopProof(other)

      await expect(verify(dpopJwt)).rejects.toThrow('match the JWK thumbprint of the client attestation')
    })

    test('rejects a combined-mode attestation without a DPoP proof', async () => {
      await expect(
        verifyPreAuthorizedCodeAccessTokenRequest({
          authorizationServerMetadata,
          accessTokenRequest: {
            grant_type: preAuthorizedCodeGrantIdentifier,
            'pre-authorized_code': 'code-123',
          },
          grant: { grantType: preAuthorizedCodeGrantIdentifier, preAuthorizedCode: 'code-123' },
          callbacks,
          expectedPreAuthorizedCode: 'code-123',
          request,
          clientAttestation: { required: true, clientAttestationJwt },
        })
      ).rejects.toThrow('requires a DPoP proof')
    })

    test('rejects when the expected challenge does not match the DPoP nonce', async () => {
      const dpopJwt = await createCombinedDpopProof(instance, 'the-challenge')

      await expect(verify(dpopJwt, { expectedNonce: 'a-different-challenge' })).rejects.toThrow()
    })
  })
})
