import { describe, expect, test } from 'vitest'
import { getSignJwtCallback, callbacks as partialCallbacks } from '../../tests/util'
import { Oauth2AuthorizationServer } from '../Oauth2AuthorizationServer'
import type { Jwk } from '../common/jwk/z-jwk'
import { decodeJwt } from '../common/jwt/decode-jwt'
import { createDpopJwt } from '../dpop/dpop'
import { PkceCodeChallengeMethod, createPkce } from '../pkce'
import { authorizationCodeGrantIdentifier, preAuthorizedCodeGrantIdentifier } from '../z-grant-type'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'

const dpopSignerJwk = {
  kty: 'EC',
  d: '6xn3gj1pQisseLDhd1qtGbBr9oWBwxxvAMBSDerbSzk',
  crv: 'P-256',
  x: 'CQHN_Jmxy4yDZzDmudBArRip9DtU8bpNDdtya7yj6f4',
  y: 'sDsPt93iLO7eZdt0-qVwD3bRAaG1V_3wmYdw3dr_lfs',
} satisfies Jwk
const { d: _, ...dpopSignerJwkPublic } = dpopSignerJwk

const accessTokenSignerJwk = {
  kty: 'EC',
  d: 'V_ksBfnmJBl9vU-GLs3LiNxgA3PV8he5u7NOYqcDWfo',
  crv: 'P-256',
  x: 'rQbiDHRutR4YcJaWRV54Dx-sx81VlK7xuohm4-RXRT0',
  y: 'YM4MRy90G9PW59wKcawyrHDCPp7QsE6l5QT-H2Koz_M',
} satisfies Jwk

const authorizationServerMetadata = {
  issuer: 'https://server.com',
  token_endpoint: 'https://server.com/token',
} satisfies AuthorizationServerMetadata

const { d: __, ...accessTokenSignerJwkPublic } = accessTokenSignerJwk

describe('Oauth2AuthorizationServer', () => {
  test('parse, verify and grant pre authorized code access token request', async () => {
    const callbacks = {
      ...partialCallbacks,
      signJwt: getSignJwtCallback([dpopSignerJwk, accessTokenSignerJwk]),
    }

    const createdDpopJwt = await createDpopJwt({
      callbacks,
      request: {
        method: 'POST',
        url: 'https://authorization-server.com/token',
      },
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerJwkPublic,
      },
    })

    const authorizationServer = new Oauth2AuthorizationServer({
      callbacks,
    })

    const request = {
      headers: new Headers({
        DPoP: createdDpopJwt,
      }),
      method: 'POST',
      url: 'https://authorization-server.com/token',
    } as const

    const {
      accessTokenRequest,
      grant,
      dpop: dpopReturn,
      pkceCodeVerifier,
    } = authorizationServer.parseAccessTokenRequest({
      request,
      accessTokenRequest: {
        grant_type: preAuthorizedCodeGrantIdentifier,
        'pre-authorized_code': 'something',
        tx_code: 'some-tx-coe',
      },
    })

    expect(dpopReturn?.jwt).toEqual(createdDpopJwt)
    expect(pkceCodeVerifier).toEqual(undefined)
    expect(accessTokenRequest).toEqual({
      grant_type: preAuthorizedCodeGrantIdentifier,
      'pre-authorized_code': 'something',
      tx_code: 'some-tx-coe',
    })
    expect(grant).toEqual({
      grantType: preAuthorizedCodeGrantIdentifier,
      preAuthorizedCode: 'something',
      txCode: 'some-tx-coe',
    })

    if (grant.grantType !== preAuthorizedCodeGrantIdentifier) {
      throw new Error('expected grant to be pre-auth')
    }

    const { dpop } = await authorizationServer.verifyPreAuthorizedCodeAccessTokenRequest({
      grant,
      accessTokenRequest,
      request,
      dpop: {
        jwt: dpopReturn?.jwt,
      },

      authorizationServerMetadata,

      expectedPreAuthorizedCode: grant.preAuthorizedCode,
      expectedTxCode: grant.txCode,

      now: new Date('2024-01-01'),
      preAuthorizedCodeExpiresAt: new Date('2024-01-02'),
    })

    expect(dpop?.jwk).toEqual(dpopSignerJwkPublic)

    const accessTokenResponse = await authorizationServer.createAccessTokenResponse({
      audience: 'https://credential-issuer.com',
      authorizationServer: 'https://authorization-server.com',
      expiresInSeconds: 300,
      // We bind the access token to the pre-auth_code
      subject: grant.preAuthorizedCode,
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: accessTokenSignerJwkPublic,
      },
      cNonce: '0f1c8dec-26d5-4014-a570-19225a3e00ae',
      cNonceExpiresIn: 300,
      dpop,
    })

    expect(accessTokenResponse).toEqual({
      access_token: expect.any(String),
      c_nonce: '0f1c8dec-26d5-4014-a570-19225a3e00ae',
      c_nonce_expires_in: 300,
      expires_in: 300,
      token_type: 'DPoP',
    })

    expect(
      decodeJwt({
        jwt: accessTokenResponse.access_token,
      })
    ).toEqual({
      header: {
        alg: 'ES256',
        jwk: {
          crv: 'P-256',
          kty: 'EC',
          x: 'rQbiDHRutR4YcJaWRV54Dx-sx81VlK7xuohm4-RXRT0',
          y: 'YM4MRy90G9PW59wKcawyrHDCPp7QsE6l5QT-H2Koz_M',
        },
        typ: 'at+jwt',
      },
      payload: {
        aud: 'https://credential-issuer.com',
        cnf: {
          jkt: '-ROyTPYQqpxRbFqDVzNZrt_U0-zeAz0Wxmpv4TxlgLM',
        },
        exp: expect.any(Number),
        iat: expect.any(Number),
        iss: 'https://authorization-server.com',
        jti: expect.any(String),
        sub: 'something',
      },
      signature: expect.any(String),
    })
  })

  test('parse, verify and grant authorization code access token request', async () => {
    const callbacks = {
      ...partialCallbacks,
      signJwt: getSignJwtCallback([dpopSignerJwk, accessTokenSignerJwk]),
    }

    const pkce = await createPkce({
      callbacks,
      allowedCodeChallengeMethods: [PkceCodeChallengeMethod.S256],
    })

    const createdDpopJwt = await createDpopJwt({
      callbacks,
      request: {
        method: 'POST',
        url: 'https://authorization-server.com/token',
      },
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: dpopSignerJwkPublic,
      },
    })

    const authorizationServer = new Oauth2AuthorizationServer({
      callbacks,
    })

    const request = {
      headers: new Headers({
        DPoP: createdDpopJwt,
      }),
      method: 'POST',
      url: 'https://authorization-server.com/token',
    } as const

    const {
      accessTokenRequest,
      grant,
      dpop: dpopReturn,
      pkceCodeVerifier,
    } = authorizationServer.parseAccessTokenRequest({
      request,
      accessTokenRequest: {
        grant_type: authorizationCodeGrantIdentifier,
        code: 'something-something',
        code_verifier: pkce.codeVerifier,
      },
    })

    expect(pkceCodeVerifier).toEqual(pkce.codeVerifier)
    expect(dpopReturn?.jwt).toEqual(createdDpopJwt)
    expect(accessTokenRequest).toEqual({
      grant_type: authorizationCodeGrantIdentifier,
      code: 'something-something',
      code_verifier: pkce.codeVerifier,
    })
    expect(grant).toEqual({
      grantType: authorizationCodeGrantIdentifier,
      code: 'something-something',
    })

    if (grant.grantType !== authorizationCodeGrantIdentifier) {
      throw new Error('expected grant to be auth')
    }

    const { dpop } = await authorizationServer.verifyAuthorizationCodeAccessTokenRequest({
      grant,
      accessTokenRequest,
      request,
      dpop: {
        jwt: dpopReturn?.jwt,
      },
      authorizationServerMetadata,

      expectedCode: grant.code,

      pkce: {
        ...pkce,
        codeVerifier: pkceCodeVerifier,
      },

      now: new Date('2024-01-01'),
      codeExpiresAt: new Date('2024-01-02'),
    })

    expect(dpop?.jwk).toEqual(dpopSignerJwkPublic)

    const accessTokenResponse = await authorizationServer.createAccessTokenResponse({
      audience: 'https://credential-issuer.com',
      authorizationServer: 'https://authorization-server.com',
      expiresInSeconds: 300,
      subject: 'a9ad80ef-18b6-4087-9b88-55f5b14a33da',
      signer: {
        method: 'jwk',
        alg: 'ES256',
        publicJwk: accessTokenSignerJwkPublic,
      },
      cNonce: '0f1c8dec-26d5-4014-a570-19225a3e00ae',
      cNonceExpiresIn: 300,
      dpop,
    })

    expect(accessTokenResponse).toEqual({
      access_token: expect.any(String),
      c_nonce: '0f1c8dec-26d5-4014-a570-19225a3e00ae',
      c_nonce_expires_in: 300,
      expires_in: 300,
      token_type: 'DPoP',
    })

    expect(
      decodeJwt({
        jwt: accessTokenResponse.access_token,
      })
    ).toEqual({
      header: {
        alg: 'ES256',
        jwk: {
          crv: 'P-256',
          kty: 'EC',
          x: 'rQbiDHRutR4YcJaWRV54Dx-sx81VlK7xuohm4-RXRT0',
          y: 'YM4MRy90G9PW59wKcawyrHDCPp7QsE6l5QT-H2Koz_M',
        },
        typ: 'at+jwt',
      },
      payload: {
        aud: 'https://credential-issuer.com',
        cnf: {
          jkt: '-ROyTPYQqpxRbFqDVzNZrt_U0-zeAz0Wxmpv4TxlgLM',
        },
        exp: expect.any(Number),
        iat: expect.any(Number),
        iss: 'https://authorization-server.com',
        jti: expect.any(String),
        sub: 'a9ad80ef-18b6-4087-9b88-55f5b14a33da',
      },
      signature: expect.any(String),
    })
  })
})
