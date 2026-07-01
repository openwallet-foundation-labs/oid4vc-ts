import type { Jwk } from '@openid4vc/oauth2'
import { describe, expect, test } from 'vitest'
import { verifyCredentialRequestDiVpProof } from '../di-vp-proof-type'

const credentialIssuer = 'https://issuer.com'
const signerJwk = { kty: 'OKP', crv: 'Ed25519', x: 'some-x' } satisfies Jwk

function validVp(overrides: Record<string, unknown> = {}) {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
    proof: {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-2022',
      proofPurpose: 'authentication',
      verificationMethod: 'did:key:z6Mk...#z6Mk...',
      domain: credentialIssuer,
      challenge: 'some-nonce',
      proofValue: 'z5hrbHzZ...',
      ...overrides,
    },
  }
}

describe('verifyCredentialRequestDiVpProof', () => {
  test('verifies a valid di_vp proof and returns the signer jwk', async () => {
    const result = await verifyCredentialRequestDiVpProof({
      vp: validVp(),
      expectedNonce: 'some-nonce',
      credentialIssuer,
      callbacks: {
        verifyDataIntegrityProof: () => ({ verified: true, signerJwk }),
      },
    })

    expect(result.signerJwk).toStrictEqual(signerJwk)
  })

  test('throws when the nonce has expired', async () => {
    await expect(
      verifyCredentialRequestDiVpProof({
        vp: validVp(),
        expectedNonce: 'some-nonce',
        nonceExpiresAt: new Date(Date.now() - 1000),
        credentialIssuer,
        callbacks: {
          verifyDataIntegrityProof: () => ({ verified: true, signerJwk }),
        },
      })
    ).rejects.toThrow('Nonce used for credential request proof expired')
  })

  test('throws when proofPurpose is not authentication', async () => {
    await expect(
      verifyCredentialRequestDiVpProof({
        vp: validVp({ proofPurpose: 'assertionMethod' }),
        expectedNonce: 'some-nonce',
        credentialIssuer,
        callbacks: {
          verifyDataIntegrityProof: () => ({ verified: true, signerJwk }),
        },
      })
    ).rejects.toThrow(`proof.proofPurpose' must be 'authentication'`)
  })

  test('throws when domain does not match the credential issuer', async () => {
    await expect(
      verifyCredentialRequestDiVpProof({
        vp: validVp({ domain: 'https://other-issuer.com' }),
        expectedNonce: 'some-nonce',
        credentialIssuer,
        callbacks: {
          verifyDataIntegrityProof: () => ({ verified: true, signerJwk }),
        },
      })
    ).rejects.toThrow(`proof.domain' does not match the credential issuer identifier`)
  })

  test('throws when challenge does not match the expected nonce', async () => {
    await expect(
      verifyCredentialRequestDiVpProof({
        vp: validVp({ challenge: 'wrong-nonce' }),
        expectedNonce: 'some-nonce',
        credentialIssuer,
        callbacks: {
          verifyDataIntegrityProof: () => ({ verified: true, signerJwk }),
        },
      })
    ).rejects.toThrow(`proof.challenge' does not match the expected nonce`)
  })

  test('throws when challenge is present but no nonce was expected', async () => {
    await expect(
      verifyCredentialRequestDiVpProof({
        vp: validVp(),
        credentialIssuer,
        callbacks: {
          verifyDataIntegrityProof: () => ({ verified: true, signerJwk }),
        },
      })
    ).rejects.toThrow(`proof.challenge' must not be present when no nonce was issued`)
  })

  test('throws when cryptosuite is missing', async () => {
    await expect(
      verifyCredentialRequestDiVpProof({
        vp: validVp({ cryptosuite: undefined }),
        expectedNonce: 'some-nonce',
        credentialIssuer,
        callbacks: {
          verifyDataIntegrityProof: () => ({ verified: true, signerJwk }),
        },
      })
    ).rejects.toThrow(`missing required 'proof.cryptosuite'`)
  })

  test('throws when verificationMethod is missing', async () => {
    await expect(
      verifyCredentialRequestDiVpProof({
        vp: validVp({ verificationMethod: undefined }),
        expectedNonce: 'some-nonce',
        credentialIssuer,
        callbacks: {
          verifyDataIntegrityProof: () => ({ verified: true, signerJwk }),
        },
      })
    ).rejects.toThrow(`missing required 'proof.verificationMethod'`)
  })

  test('throws when the proof entry is missing', async () => {
    await expect(
      verifyCredentialRequestDiVpProof({
        vp: { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiablePresentation'] },
        expectedNonce: 'some-nonce',
        credentialIssuer,
        callbacks: {
          verifyDataIntegrityProof: () => ({ verified: true, signerJwk }),
        },
      })
    ).rejects.toThrow(`di_vp proof is missing a 'proof' entry`)
  })

  test('throws when no verifyDataIntegrityProof callback is configured', async () => {
    await expect(
      verifyCredentialRequestDiVpProof({
        vp: validVp(),
        expectedNonce: 'some-nonce',
        credentialIssuer,
        callbacks: {},
      })
    ).rejects.toThrow('no verifyDataIntegrityProof callback configured')
  })

  test('throws when the callback reports the proof as not verified', async () => {
    await expect(
      verifyCredentialRequestDiVpProof({
        vp: validVp(),
        expectedNonce: 'some-nonce',
        credentialIssuer,
        callbacks: {
          verifyDataIntegrityProof: () => ({ verified: false }),
        },
      })
    ).rejects.toThrow('Error verifying credential request di_vp proof')
  })
})
