import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../../tests/util.mjs'
import type { Jwk } from '../../common/jwk/z-jwk'
import { decodeJwt } from '../../common/jwt/decode-jwt'
import { retrieveAuthorizationCodeAccessToken } from '../retrieve-access-token'

const dpopSignerJwk = {
  kty: 'EC',
  d: '6xn3gj1pQisseLDhd1qtGbBr9oWBwxxvAMBSDerbSzk',
  crv: 'P-256',
  x: 'CQHN_Jmxy4yDZzDmudBArRip9DtU8bpNDdtya7yj6f4',
  y: 'sDsPt93iLO7eZdt0-qVwD3bRAaG1V_3wmYdw3dr_lfs',
} satisfies Jwk

const { d: _, ...dpopSignerJwkPublic } = dpopSignerJwk

describe('retrieveAuthorizationCodeAccessToken', () => {
  test('retries use_dpop_nonce with a fresh proof', async () => {
    const dpopProofs: string[] = []
    let callCount = 0

    const fetchMock: typeof fetch = async (input, init) => {
      const request = new Request(input, init)
      const dpop = request.headers.get('DPoP')
      if (dpop) dpopProofs.push(dpop)
      callCount++

      if (callCount === 1) {
        return new Response(JSON.stringify({ error: 'use_dpop_nonce' }), {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'DPoP-Nonce': 'server-nonce',
          },
        })
      }

      return new Response(
        JSON.stringify({
          access_token: 'access-token-value',
          token_type: 'DPoP',
          expires_in: 300,
        }),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
        }
      )
    }

    const result = await retrieveAuthorizationCodeAccessToken({
      authorizationServerMetadata: {
        issuer: 'https://authorization-server.com',
        token_endpoint: 'https://authorization-server.com/token',
      },
      authorizationCode: 'auth-code',
      callbacks: {
        ...callbacks,
        fetch: fetchMock,
        signJwt: getSignJwtCallback([dpopSignerJwk]),
      },
      dpop: {
        signer: {
          method: 'jwk',
          alg: 'ES256',
          publicJwk: dpopSignerJwkPublic,
        },
      },
    })

    expect(result.accessTokenResponse).toEqual({
      access_token: 'access-token-value',
      token_type: 'DPoP',
      expires_in: 300,
    })

    expect(callCount).toBe(2)
    expect(dpopProofs).toHaveLength(2)

    const firstProof = decodeJwt({ jwt: dpopProofs[0] }).payload
    const secondProof = decodeJwt({ jwt: dpopProofs[1] }).payload

    expect(firstProof.jti).not.toEqual(secondProof.jti)
    expect(firstProof.nonce).toBeUndefined()
    expect(secondProof.nonce).toBe('server-nonce')
  })
})
