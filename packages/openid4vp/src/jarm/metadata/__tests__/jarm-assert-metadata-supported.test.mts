import { describe, expect, test } from 'vitest'
import { jarmAssertMetadataSupported } from '../jarm-assert-metadata-supported.js'

const serverMetadata = {
  authorization_signing_alg_values_supported: [],
  authorization_encryption_alg_values_supported: ['ECDH-ES'],
  authorization_encryption_enc_values_supported: ['A128GCM', 'A256GCM', 'A128CBC-HS256'],
}

describe('jarmAssertMetadataSupported', () => {
  test('does not assert enc when client metadata omits authorization_encrypted_response_enc', () => {
    // Verifiers may combine the pre-27 `authorization_encrypted_response_alg` with the draft 28
    // `encrypted_response_enc_values_supported`, leaving the legacy `enc` param out entirely.
    expect(
      jarmAssertMetadataSupported({
        clientMetadata: { authorization_encrypted_response_alg: 'ECDH-ES' },
        serverMetadata,
      })
    ).toEqual({
      type: 'encrypt',
      client_metadata: { authorization_encrypted_response_alg: 'ECDH-ES' },
    })
  })

  test('asserts enc when client metadata includes authorization_encrypted_response_enc', () => {
    expect(() =>
      jarmAssertMetadataSupported({
        clientMetadata: {
          authorization_encrypted_response_alg: 'ECDH-ES',
          authorization_encrypted_response_enc: 'A192GCM',
        },
        serverMetadata,
      })
    ).toThrow('Invalid authorization_encryption_enc')
  })
})
