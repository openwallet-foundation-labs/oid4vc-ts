import { describe, expect, test } from 'vitest'
import { createOpenid4vpAuthorizationResponse } from '../create-authorization-response.js'

const encJwk = {
  kty: 'EC',
  alg: 'ECDH-ES',
  crv: 'P-256',
  x: 'PHVtfGzwfShN50aP1Vqw9PW2y1Hwe_lvprL2Ev-Kzbg',
  y: 'qCj6yA31O3Sr6FCOGb1SO5XdpfVySG1uk5cMr6zmq9c',
  kid: '5DFw7cUedUNDAjmqUpZFVE66Tx45rg2sRfp3YV4ykLtF',
  use: 'enc',
} as const

// Mirrors what the Credo holder advertises
const serverMetadata = {
  authorization_signing_alg_values_supported: [],
  authorization_encryption_alg_values_supported: ['ECDH-ES'],
  authorization_encryption_enc_values_supported: ['A128GCM', 'A256GCM', 'A128CBC-HS256'],
}

async function createResponse(clientMetadata: Record<string, unknown>) {
  let encryptor: { alg: string; enc: string } | undefined

  await createOpenid4vpAuthorizationResponse({
    // biome-ignore lint/suspicious/noExplicitAny: test fixture
    authorizationRequestPayload: {
      response_type: 'vp_token',
      response_mode: 'dc_api.jwt',
      client_id: 'x509_hash:vNyA8UYcjZBBewa_AMzAV3Bs3B1Ql9yH01xQhQVXN7o',
      nonce: 'HVI5aa23NzijX-AMlQ3jDJMMCx8nkdlSdnji44Zq1-c',
      expected_origins: ['https://verify.trinsic.id'],
      client_metadata: { jwks: { keys: [encJwk] }, ...clientMetadata },
    } as any,
    origin: 'https://verify.trinsic.id',
    authorizationResponsePayload: { vp_token: { cred: ['abc'] } },
    jarm: { encryption: { nonce: 'response-nonce' }, serverMetadata },
    callbacks: {
      // biome-ignore lint/suspicious/noExplicitAny: test fixture
      encryptJwe: (jweEncryptor: any) => {
        encryptor = { alg: jweEncryptor.alg, enc: jweEncryptor.enc }
        return { encryptionJwk: encJwk, jwe: 'jwe' }
      },
      signJwt: () => {
        throw new Error('Not implemented')
      },
      fetch,
      getJwks: () => {
        throw new Error('Not implemented')
      },
      // biome-ignore lint/suspicious/noExplicitAny: test fixture
    } as any,
  })

  return encryptor
}

describe('createOpenid4vpAuthorizationResponse response encryption metadata', () => {
  test('ignores a leftover legacy alg when the 1.0 enc values are present', async () => {
    // Shape sent by the Trinsic verifier: a 1.0 request that still carries the pre-27
    // `authorization_encrypted_response_alg`, but no longer the matching `_enc`.
    await expect(
      createResponse({
        authorization_encrypted_response_alg: 'ECDH-ES',
        encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
      })
    ).resolves.toEqual({ alg: 'ECDH-ES', enc: 'A128GCM' })
  })

  test('ignores legacy enc we do not support when the 1.0 enc values are present', async () => {
    await expect(
      createResponse({
        authorization_encrypted_response_alg: 'ECDH-ES',
        authorization_encrypted_response_enc: 'A192GCM',
        encrypted_response_enc_values_supported: ['A256GCM'],
      })
    ).resolves.toEqual({ alg: 'ECDH-ES', enc: 'A256GCM' })
  })

  test('still validates legacy metadata when the 1.0 enc values are absent', async () => {
    await expect(
      createResponse({
        authorization_encrypted_response_alg: 'ECDH-ES',
        authorization_encrypted_response_enc: 'A192GCM',
      })
    ).rejects.toThrow('Invalid authorization_encryption_enc')
  })

  test('defaults enc when a pre-27 verifier only sends the legacy alg', async () => {
    await expect(createResponse({ authorization_encrypted_response_alg: 'ECDH-ES' })).resolves.toEqual({
      alg: 'ECDH-ES',
      enc: 'A128GCM',
    })
  })
})
