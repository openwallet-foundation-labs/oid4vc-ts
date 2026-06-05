import type { JweEncryptor } from '@openid4vc/oauth2'
import { describe, expect, test } from 'vitest'
import { createCredentialResponse } from '../src/credential-request/credential-response'
import { zCredentialResponseEncryption } from '../src/credential-request/z-credential-request-common'

const jwkWithAlg = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', alg: 'ECDH-ES' }
const jwkWithoutAlg = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }

function captureEncryptor() {
  const captured: { encryptor?: JweEncryptor } = {}
  return {
    captured,
    callbacks: {
      encryptJwe: async (encryptor: JweEncryptor) => {
        captured.encryptor = encryptor
        return { encryptionJwk: encryptor.publicJwk, jwe: 'JWE' }
      },
    },
  }
}

const baseOptions = {
  // Minimal request stub: createCredentialResponse only reads `credentialRequest.format?.format`.
  credentialRequest: {} as never,
  credential: 'credential-jwt',
}

describe('credential_response_encryption', () => {
  describe('schema', () => {
    test('parses without a top-level `alg` (it lives in the jwk)', () => {
      const result = zCredentialResponseEncryption.safeParse({ jwk: jwkWithAlg, enc: 'A128GCM' })
      expect(result.success).toBe(true)
    })

    test('accepts the optional `zip` parameter', () => {
      const parsed = zCredentialResponseEncryption.parse({ jwk: jwkWithAlg, enc: 'A128GCM', zip: 'DEF' })
      expect(parsed.zip).toBe('DEF')
    })

    test('still accepts a top-level `alg` (draft 14/15 wallets)', () => {
      const parsed = zCredentialResponseEncryption.parse({ jwk: jwkWithoutAlg, alg: 'ECDH-ES', enc: 'A128GCM' })
      expect(parsed.alg).toBe('ECDH-ES')
    })
  })

  describe('createCredentialResponse encryption', () => {
    test('sources `alg` from the jwk', async () => {
      const { captured, callbacks } = captureEncryptor()
      const { credentialResponseJwt } = await createCredentialResponse({
        ...baseOptions,
        credentialResponseEncryption: { jwk: jwkWithAlg, enc: 'A128GCM' },
        callbacks,
      })

      expect(credentialResponseJwt).toBe('JWE')
      expect(captured.encryptor?.alg).toBe('ECDH-ES')
      expect(captured.encryptor?.enc).toBe('A128GCM')
      expect(captured.encryptor?.publicJwk).toEqual(jwkWithAlg)
    })

    test('falls back to a sibling `alg` when the jwk has none', async () => {
      const { captured, callbacks } = captureEncryptor()
      await createCredentialResponse({
        ...baseOptions,
        credentialResponseEncryption: { jwk: jwkWithoutAlg, alg: 'ECDH-ES', enc: 'A128GCM' },
        callbacks,
      })

      expect(captured.encryptor?.alg).toBe('ECDH-ES')
    })

    test('throws when no `alg` is present in the jwk or as a sibling', async () => {
      const { callbacks } = captureEncryptor()
      await expect(
        createCredentialResponse({
          ...baseOptions,
          credentialResponseEncryption: { jwk: jwkWithoutAlg, enc: 'A128GCM' },
          callbacks,
        })
      ).rejects.toThrow(/missing the required 'alg'/)
    })
  })
})
