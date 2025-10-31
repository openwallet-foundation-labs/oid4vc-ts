import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../../../tests/util.mjs'
import type { Jwk } from '../../jwk/z-jwk.js'
import { jwtHeaderFromJwtSigner } from '../decode-jwt.js'
import { verifyJwt } from '../verify-jwt.js'
import type { JwtSigner } from '../z-jwt.js'

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

describe('Verify JWT', () => {
  describe(`string 'aud' property`, async () => {
    const header = {
      ...jwtHeaderFromJwtSigner(signer),
      alg: 'ES256',
      typ: 'JWT',
    }

    const payload = {
      aud: 'foo',
    }

    const { jwt } = await signJwt(signer, {
      header,
      payload,
    })

    test('rejects when audience is not expected', async () => {
      await expect(
        verifyJwt({
          compact: jwt,
          expectedAudience: 'poisson',
          signer,
          header,
          payload,
          verifyJwtCallback: callbacks.verifyJwt,
        })
      ).rejects.toThrow(`jwt 'aud' does not match expected value`)
    })

    test('resolves when audience is expected', async () => {
      await expect(
        verifyJwt({
          compact: jwt,
          expectedAudience: 'foo',
          signer,
          header,
          payload,
          verifyJwtCallback: callbacks.verifyJwt,
        })
      ).resolves.toBeDefined()
    })
  })

  describe(`array 'aud' property`, async () => {
    const header = {
      ...jwtHeaderFromJwtSigner(signer),
      alg: 'ES256',
      typ: 'JWT',
    }

    const payload = {
      aud: ['foo', 'bar'],
    }

    const { jwt } = await signJwt(signer, {
      header,
      payload,
    })

    test('rejects when audience is not expected', async () => {
      await expect(
        verifyJwt({
          compact: jwt,
          expectedAudience: 'poisson',
          signer,
          header,
          payload,
          verifyJwtCallback: callbacks.verifyJwt,
        })
      ).rejects.toThrow(`jwt 'aud' does not match expected value`)
    })

    test('resolves when audience is expected', async () => {
      await expect(
        verifyJwt({
          compact: jwt,
          expectedAudience: 'bar',
          signer,
          header,
          payload,
          verifyJwtCallback: callbacks.verifyJwt,
        })
      ).resolves.toBeDefined()
    })
  })
})
