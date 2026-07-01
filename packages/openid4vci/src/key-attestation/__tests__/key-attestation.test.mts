import type { Jwk } from '@openid4vc/oauth2'
import * as jose from 'jose'
import { beforeAll, describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../../../oauth2/tests/util.mjs'
import { createKeyAttestationJwt, parseKeyAttestationJwt, verifyKeyAttestationJwt } from '../key-attestation'
import { zKeyAttestationJwtHeader, zKeyAttestationJwtPayloadForUse } from '../z-key-attestation'

async function generateEs256Key() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true })
  return {
    privateJwk: (await jose.exportJWK(privateKey)) as Jwk,
    publicJwk: (await jose.exportJWK(publicKey)) as Jwk,
  }
}

describe('Key Attestation', () => {
  let attester: Awaited<ReturnType<typeof generateEs256Key>>
  let attested: Awaited<ReturnType<typeof generateEs256Key>>
  let signJwt: ReturnType<typeof getSignJwtCallback>

  beforeAll(async () => {
    attester = await generateEs256Key()
    attested = await generateEs256Key()
    signJwt = getSignJwtCallback([attester.privateJwk])
  })

  test('creates a key attestation with the spec `key-attestation+jwt` typ', async () => {
    const keyAttestationJwt = await createKeyAttestationJwt({
      callbacks: { signJwt },
      attestedKeys: [attested.publicJwk],
      expiresAt: new Date(Date.now() + 500 * 1000),
      use: 'proof_type.jwt',
      signer: { method: 'jwk', alg: 'ES256', publicJwk: attester.publicJwk },
    })

    const { header } = parseKeyAttestationJwt({ keyAttestationJwt })
    expect(header.typ).toBe('key-attestation+jwt')

    await expect(
      verifyKeyAttestationJwt({
        callbacks: { verifyJwt: callbacks.verifyJwt },
        keyAttestationJwt,
        use: 'proof_type.jwt',
      })
    ).resolves.toBeDefined()
  })

  test('verifies a legacy `keyattestation+jwt` key attestation', async () => {
    const now = Math.floor(Date.now() / 1000)
    const { jwt: legacyKeyAttestationJwt } = await signJwt(
      { method: 'jwk', alg: 'ES256', publicJwk: attester.publicJwk },
      {
        header: { typ: 'keyattestation+jwt', alg: 'ES256', jwk: attester.publicJwk },
        payload: { iat: now, exp: now + 500, attested_keys: [attested.publicJwk] },
      }
    )

    await expect(
      verifyKeyAttestationJwt({
        callbacks: { verifyJwt: callbacks.verifyJwt },
        keyAttestationJwt: legacyKeyAttestationJwt,
        use: 'proof_type.jwt',
      })
    ).resolves.toBeDefined()
  })

  test('accepts a header with both `trust_chain` and `kid`, rejects `trust_chain` without `kid`', () => {
    const base = { typ: 'key-attestation+jwt', alg: 'ES256' } as const

    expect(zKeyAttestationJwtHeader.safeParse({ ...base, trust_chain: ['chain'], kid: '1' }).success).toBe(true)
    expect(zKeyAttestationJwtHeader.safeParse({ ...base, trust_chain: ['chain'] }).success).toBe(false)
  })

  test('rejects an empty `attested_keys` array', () => {
    const now = Math.floor(Date.now() / 1000)
    const result = zKeyAttestationJwtPayloadForUse('proof_type.jwt').safeParse({
      iat: now,
      exp: now + 500,
      attested_keys: [],
    })
    expect(result.success).toBe(false)
  })

  test('allows an attestation-proof key attestation without `nonce`', () => {
    const now = Math.floor(Date.now() / 1000)
    const result = zKeyAttestationJwtPayloadForUse('proof_type.attestation').safeParse({
      iat: now,
      attested_keys: [attested.publicJwk],
    })
    expect(result.success).toBe(true)
  })
})
