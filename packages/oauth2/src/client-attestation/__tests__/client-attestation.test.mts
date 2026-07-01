import * as jose from 'jose'
import { beforeAll, describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../../tests/util.mjs'
import type { Jwk } from '../../common/jwk/z-jwk'
import { decodeJwt } from '../../common/jwt/decode-jwt'
import { createClientAttestationJwt } from '../client-attestation'
import { createClientAttestationPopJwt, verifyClientAttestationPopJwt } from '../client-attestation-pop'
import {
  zClientAttestationJwtHeader,
  zClientAttestationJwtPayload,
  zClientAttestationPopJwtHeader,
  zClientAttestationPopJwtPayload,
} from '../z-client-attestation'

const authorizationServer = 'https://oauth2-auth-server.com'

async function generateEs256Key() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return {
    privateJwk: (await jose.exportJWK(privateKey)) as Jwk,
    publicJwk: (await jose.exportJWK(publicKey)) as Jwk,
  }
}

describe('Client (Wallet) Attestation', () => {
  // Attester signs the client attestation; the client instance holds the `cnf` key and signs the PoP.
  let attester: Awaited<ReturnType<typeof generateEs256Key>>
  let instance: Awaited<ReturnType<typeof generateEs256Key>>
  let signJwt: ReturnType<typeof getSignJwtCallback>
  let clientAttestationJwt: string
  let clientAttestation: ReturnType<
    typeof decodeJwt<typeof zClientAttestationJwtHeader, typeof zClientAttestationJwtPayload>
  >

  beforeAll(async () => {
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

    clientAttestation = decodeJwt({
      jwt: clientAttestationJwt,
      headerSchema: zClientAttestationJwtHeader,
      payloadSchema: zClientAttestationJwtPayload,
    })
  })

  test('creates a draft-09 Client Attestation JWT without an `iss` claim', () => {
    expect(clientAttestation.payload.iss).toBeUndefined()
    expect(clientAttestation.payload.sub).toBe('wallet')
    expect(clientAttestation.payload.cnf.jwk).toEqual(instance.publicJwk)
  })

  test('creates a draft-09 PoP JWT (no `iss`, no `exp`, uses `challenge`) that verifies', async () => {
    const clientAttestationPopJwt = await createClientAttestationPopJwt({
      callbacks: { signJwt, generateRandom: callbacks.generateRandom },
      authorizationServer,
      clientAttestation: clientAttestationJwt,
      challenge: 'challenge-123',
    })

    const { payload } = decodeJwt({
      jwt: clientAttestationPopJwt,
      headerSchema: zClientAttestationPopJwtHeader,
      payloadSchema: zClientAttestationPopJwtPayload,
    })
    expect(payload.iss).toBeUndefined()
    expect(payload.exp).toBeUndefined()
    expect(payload.nonce).toBeUndefined()
    expect(payload.challenge).toBe('challenge-123')
    expect(payload.aud).toBe(authorizationServer)
    expect(payload.jti).toEqual(expect.any(String))

    await expect(
      verifyClientAttestationPopJwt({
        callbacks: { verifyJwt: callbacks.verifyJwt },
        authorizationServer,
        clientAttestation,
        clientAttestationPopJwt,
        expectedChallenge: 'challenge-123',
      })
    ).resolves.toBeDefined()
  })

  test('verifies a legacy (<= draft 07) PoP JWT carrying `iss` and `nonce`', async () => {
    const now = Math.floor(Date.now() / 1000)
    const { jwt: legacyPopJwt } = await signJwt(
      { method: 'jwk', alg: 'ES256', publicJwk: instance.publicJwk },
      {
        header: { typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' },
        payload: {
          iss: 'wallet',
          aud: authorizationServer,
          iat: now,
          exp: now + 300,
          jti: 'legacy-jti',
          nonce: 'legacy-nonce',
        },
      }
    )

    await expect(
      verifyClientAttestationPopJwt({
        callbacks: { verifyJwt: callbacks.verifyJwt },
        authorizationServer,
        clientAttestation,
        clientAttestationPopJwt: legacyPopJwt,
        // `expectedNonce` is the deprecated alias for `expectedChallenge`
        expectedNonce: 'legacy-nonce',
      })
    ).resolves.toBeDefined()
  })

  test('rejects a legacy PoP JWT whose `iss` does not match the attestation `sub`', async () => {
    const now = Math.floor(Date.now() / 1000)
    const { jwt: legacyPopJwt } = await signJwt(
      { method: 'jwk', alg: 'ES256', publicJwk: instance.publicJwk },
      {
        header: { typ: 'oauth-client-attestation-pop+jwt', alg: 'ES256' },
        payload: {
          iss: 'not-wallet',
          aud: authorizationServer,
          iat: now,
          jti: 'legacy-jti',
        },
      }
    )

    await expect(
      verifyClientAttestationPopJwt({
        callbacks: { verifyJwt: callbacks.verifyJwt },
        authorizationServer,
        clientAttestation,
        clientAttestationPopJwt: legacyPopJwt,
      })
    ).rejects.toThrow("'iss'")
  })
})
