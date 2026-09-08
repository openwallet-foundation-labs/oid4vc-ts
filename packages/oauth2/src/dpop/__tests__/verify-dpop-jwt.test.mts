import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../../tests/util.mjs'
import { HashAlgorithm } from '../../callbacks'
import { calculateJwkThumbprint } from '../../common/jwk/jwk-thumbprint'
import type { Jwk } from '../../common/jwk/z-jwk'
import { createDpopJwt, verifyDpopJwt } from '../dpop'

const request = {
  method: 'POST',
  url: 'https://authorization-server.com/token',
  headers: new Headers(),
} as const

const dpopSignerJwk = {
  kty: 'EC',
  d: 'UxBOEoXuH9qlZ0Bo2E1sCuZDkAzVl99eenarvWMrgH0',
  crv: 'P-256',
  x: 'BvowcNvKitnPOIU7EQSP6mvHG46mqJp1iVEeaHRkzMQ',
  y: 'h2kx9opNMxfK1_mcx2t5SIPf-kg4oNXS77tBxDvy1TM',
} satisfies Jwk

const otherSignerJwk = {
  kty: 'EC',
  d: '6xn3gj1pQisseLDhd1qtGbBr9oWBwxxvAMBSDerbSzk',
  crv: 'P-256',
  x: 'CQHN_Jmxy4yDZzDmudBArRip9DtU8bpNDdtya7yj6f4',
  y: 'sDsPt93iLO7eZdt0-qVwD3bRAaG1V_3wmYdw3dr_lfs',
} satisfies Jwk

const { d: _, ...dpopSignerPublicJwk } = dpopSignerJwk
const { d: __, ...otherSignerPublicJwk } = otherSignerJwk

describe('verifyDpopJwt', () => {
  test('verifies a valid proof with matching expected jwk thumbprint', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    const expectedJwkThumbprint = await calculateJwkThumbprint({
      hashAlgorithm: HashAlgorithm.Sha256,
      hashCallback: callbacks.hash,
      jwk: dpopSignerPublicJwk,
    })

    const result = await verifyDpopJwt({
      callbacks,
      dpopJwt,
      request,
      expectedJwkThumbprint,
      allowedSigningAlgs: ['ES256'],
    })

    expect(result.jwkThumbprint).toBe(expectedJwkThumbprint)
  })

  test('rejects proofs signed by the wrong key', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    const expectedJwkThumbprint = await calculateJwkThumbprint({
      hashAlgorithm: HashAlgorithm.Sha256,
      hashCallback: callbacks.hash,
      jwk: otherSignerPublicJwk,
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        expectedJwkThumbprint,
      })
    ).rejects.toThrow('expect jwk thumbprint value')
  })

  test('rejects proofs with wrong HTTP method', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request: {
          ...request,
          method: 'GET',
        },
      })
    ).rejects.toThrow("expected htm value 'GET'")
  })

  test('rejects proofs with wrong URL', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request: {
          ...request,
          url: 'https://authorization-server.com/another-endpoint',
        },
      })
    ).rejects.toThrow("expected htu value 'https://authorization-server.com/another-endpoint'")
  })

  test('rejects stale proofs when maxProofAgeSeconds is exceeded', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
      issuedAt: new Date('2024-01-01T00:00:00.000Z'),
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        now: new Date('2024-01-01T00:02:00.000Z'),
        maxProofAgeSeconds: 30,
      })
    ).rejects.toThrow('Dpop jwt is too old')
  })

  test('rejects replayed jti values when uniqueness callback indicates replay', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    const seenJti = new Set<string>()
    const assertJtiUniqueness = ({
      header,
      payload,
      compact,
    }: {
      header: { typ: string }
      payload: { jti: string }
      compact: string
    }) => {
      expect(header.typ).toBe('dpop+jwt')
      expect(compact).toBe(dpopJwt)

      if (seenJti.has(payload.jti)) return false
      seenJti.add(payload.jti)
      return true
    }

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        assertJtiUniqueness,
      })
    ).resolves.toBeDefined()

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        assertJtiUniqueness,
      })
    ).rejects.toThrow('already been used')
  })

  test('rejects missing nonce when nonce is expected', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        expectedNonce: 'nonce-1',
      })
    ).rejects.toThrow('does not have a nonce value')
  })

  test('rejects invalid nonce values', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
      nonce: 'actual-nonce',
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        expectedNonce: 'different-nonce',
      })
    ).rejects.toThrow('but expected nonce value')
  })

  test('rejects unsupported proof algorithms', async () => {
    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopSignerJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerPublicJwk,
      },
    })

    await expect(
      verifyDpopJwt({
        callbacks,
        dpopJwt,
        request,
        allowedSigningAlgs: ['ES384'],
      })
    ).rejects.toThrow('allowed dpop signging alg values are ES384')
  })
})
