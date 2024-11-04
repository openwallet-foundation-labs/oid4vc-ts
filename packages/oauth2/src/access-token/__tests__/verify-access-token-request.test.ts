import { describe, expect, test } from 'vitest'
import { callbacks, getSignJwtCallback } from '../../../tests/util'
import { createDpopJwt } from '../../dpop/dpop'
import { PkceCodeChallengeMethod } from '../../pkce'
import { authorizationCodeGrantIdentifier, preAuthorizedCodeGrantIdentifier } from '../../v-grant-type'
import {
  verifyAuthorizationCodeAccessTokenRequest,
  verifyPreAuthorizedCodeAccessTokenRequest,
} from '../verify-access-token-request'

const request = {
  headers: new Headers(),
  method: 'POST',
  url: 'https://request.com/token',
} as const

describe('Verify Pre Auhthorized Code Access Token Request', () => {
  test('handles pre authorized code not matching', async () => {
    await expect(
      verifyPreAuthorizedCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'hello2',
        },
        grant: {
          grantType: preAuthorizedCodeGrantIdentifier,
          preAuthorizedCode: 'hello2',
        },
        callbacks,
        expectedPreAuthorizedCode: 'hello',
        request,
      })
    ).rejects.toThrow(`Invalid 'pre-authorized_code' provided`)
  })

  test('handles tx code not expected but provided', async () => {
    await expect(
      verifyPreAuthorizedCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'hello2',
          tx_code: 'not-expected',
        },
        grant: {
          grantType: preAuthorizedCodeGrantIdentifier,
          preAuthorizedCode: 'hello2',
          txCode: 'not-expected',
        },
        callbacks,
        expectedPreAuthorizedCode: 'hello2',
        request,
      })
    ).rejects.toThrow(`Request contains 'tx_code' that was not expected`)
  })

  test('handles tx code not provided but expected', async () => {
    await expect(
      verifyPreAuthorizedCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'hello2',
        },
        grant: {
          grantType: preAuthorizedCodeGrantIdentifier,
          preAuthorizedCode: 'hello2',
        },
        callbacks,
        expectedPreAuthorizedCode: 'hello2',
        expectedTxCode: 'expected',
        request,
      })
    ).rejects.toThrow(`Missing required 'tx_code' in request`)
  })

  test('handles tx code provided and expected but not matching', async () => {
    await expect(
      verifyPreAuthorizedCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'hello2',
          tx_code: 'provided-tx-code',
        },
        grant: {
          grantType: preAuthorizedCodeGrantIdentifier,
          preAuthorizedCode: 'hello2',
          txCode: 'provided-tx-code',
        },
        callbacks,
        expectedPreAuthorizedCode: 'hello2',
        expectedTxCode: 'expected',
        request,
      })
    ).rejects.toThrow(`Invalid 'tx_code' provided`)
  })

  test('handles pre authorized code expired', async () => {
    const now = new Date()
    await expect(
      verifyPreAuthorizedCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'hello2',
        },
        grant: {
          grantType: preAuthorizedCodeGrantIdentifier,
          preAuthorizedCode: 'hello2',
        },
        callbacks,
        expectedPreAuthorizedCode: 'hello2',
        request,
        preAuthorizedCodeExpiresAt: new Date(now.getTime() - 100),
        now,
      })
    ).rejects.toThrow(`Expired 'pre-authorized_code' provided`)
  })

  test('handles code_verifier expected but not provided', async () => {
    await expect(
      verifyPreAuthorizedCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'hello2',
        },
        grant: {
          grantType: preAuthorizedCodeGrantIdentifier,
          preAuthorizedCode: 'hello2',
        },
        callbacks,
        expectedPreAuthorizedCode: 'hello2',
        request,
        pkce: {
          codeChallenge: 'someting',
          codeChallengeMethod: PkceCodeChallengeMethod.Plain,
        },
      })
    ).rejects.toThrow(`Missing required 'code_verifier' in access token request`)
  })

  test('handles code_verifier expected but not provided', async () => {
    await expect(
      verifyPreAuthorizedCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'hello2',
        },
        grant: {
          grantType: preAuthorizedCodeGrantIdentifier,
          preAuthorizedCode: 'hello2',
        },
        callbacks,
        expectedPreAuthorizedCode: 'hello2',
        request,
        pkce: {
          codeChallenge: 'someting',
          codeChallengeMethod: PkceCodeChallengeMethod.Plain,
        },
      })
    ).rejects.toThrow(`Missing required 'code_verifier' in access token request`)
  })

  test('handles code_verifier not matching with code_challenge', async () => {
    await expect(
      verifyPreAuthorizedCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'hello2',
        },
        grant: {
          grantType: preAuthorizedCodeGrantIdentifier,
          preAuthorizedCode: 'hello2',
        },
        callbacks,
        expectedPreAuthorizedCode: 'hello2',
        request,
        pkce: {
          codeVerifier: 'something',
          codeChallenge: 'something-else',
          codeChallengeMethod: PkceCodeChallengeMethod.Plain,
        },
      })
    ).rejects.toThrow(
      `Derived code challenge 'something' from code_verifier 'something' using code challenge method 'plain' does not match the expected code challenge.`
    )
  })

  test('handles dpop expected but not provided', async () => {
    await expect(
      verifyPreAuthorizedCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'hello2',
        },
        grant: {
          grantType: preAuthorizedCodeGrantIdentifier,
          preAuthorizedCode: 'hello2',
        },
        callbacks,
        expectedPreAuthorizedCode: 'hello2',
        request,
        dpop: {
          required: true,
        },
      })
    ).rejects.toThrow('Missing required DPoP proof')
  })

  test('handles dpop provided but not valid', async () => {
    await expect(
      verifyPreAuthorizedCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'hello2',
        },
        grant: {
          grantType: preAuthorizedCodeGrantIdentifier,
          preAuthorizedCode: 'hello2',
        },
        callbacks,
        expectedPreAuthorizedCode: 'hello2',
        request: {
          ...request,
          headers: new Headers({
            DPoP: 'ey',
          }),
        },
        dpop: {
          required: true,
          jwt: 'ey',
        },
      })
    ).rejects.toThrow('Jwt is not a valid jwt, unable to decode')
  })

  test('handles valid pre-authorized code access token request', async () => {
    const dpopPrivateJwk = {
      kty: 'EC',
      d: 'UxBOEoXuH9qlZ0Bo2E1sCuZDkAzVl99eenarvWMrgH0',
      crv: 'P-256',
      x: 'BvowcNvKitnPOIU7EQSP6mvHG46mqJp1iVEeaHRkzMQ',
      y: 'h2kx9opNMxfK1_mcx2t5SIPf-kg4oNXS77tBxDvy1TM',
    }
    const { d, ...dpopPublicJwk } = dpopPrivateJwk

    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopPrivateJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        publicJwk: dpopPublicJwk,
        alg: 'ES256',
      },
    })
    const now = new Date()

    const { dpopJwk } = await verifyPreAuthorizedCodeAccessTokenRequest({
      accessTokenRequest: {
        grant_type: preAuthorizedCodeGrantIdentifier,
        code: 'hello2',
        code_verifier: 'something',
        tx_code: 'some-tx-code',
      },
      grant: {
        grantType: preAuthorizedCodeGrantIdentifier,
        preAuthorizedCode: 'hello2',
        txCode: 'some-tx-code',
      },
      callbacks,
      expectedPreAuthorizedCode: 'hello2',
      expectedTxCode: 'some-tx-code',
      // 1 minute
      preAuthorizedCodeExpiresAt: new Date(now.getTime() + 60000),
      now,
      request: {
        ...request,
        headers: new Headers({
          DPoP: dpopJwt,
        }),
      },
      dpop: {
        required: true,
        jwt: dpopJwt,
        allowedSigningAlgs: ['ES256'],
      },
      pkce: {
        codeChallenge: 'something',
        codeVerifier: 'something',
        codeChallengeMethod: PkceCodeChallengeMethod.Plain,
      },
    })

    expect(dpopJwk).toEqual(dpopPublicJwk)
  })
})

describe('Verify Authorization Code Access Token Request', () => {
  test('handles authorization code not matching', async () => {
    await expect(
      verifyAuthorizationCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        grant: {
          grantType: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        callbacks,
        expectedCode: 'hello',
        request,
      })
    ).rejects.toThrow(`Invalid 'code' provided`)
  })

  test('handles authorization code expired', async () => {
    const now = new Date()
    await expect(
      verifyAuthorizationCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        grant: {
          grantType: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        callbacks,
        expectedCode: 'hello2',
        request,
        codeExpiresAt: new Date(now.getTime() - 100),
        now,
      })
    ).rejects.toThrow(`Expired 'code' provided`)
  })

  test('handles code_verifier expected but not provided', async () => {
    await expect(
      verifyAuthorizationCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        grant: {
          grantType: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        callbacks,
        expectedCode: 'hello2',
        request,
        pkce: {
          codeChallenge: 'someting',
          codeChallengeMethod: PkceCodeChallengeMethod.Plain,
        },
      })
    ).rejects.toThrow(`Missing required 'code_verifier' in access token request`)
  })

  test('handles code_verifier expected but not provided', async () => {
    await expect(
      verifyAuthorizationCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        grant: {
          grantType: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        callbacks,
        expectedCode: 'hello2',
        request,
        pkce: {
          codeChallenge: 'someting',
          codeChallengeMethod: PkceCodeChallengeMethod.Plain,
        },
      })
    ).rejects.toThrow(`Missing required 'code_verifier' in access token request`)
  })

  test('handles code_verifier not matching with code_challenge', async () => {
    await expect(
      verifyAuthorizationCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        grant: {
          grantType: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        callbacks,
        expectedCode: 'hello2',
        request,
        pkce: {
          codeVerifier: 'something',
          codeChallenge: 'something-else',
          codeChallengeMethod: PkceCodeChallengeMethod.Plain,
        },
      })
    ).rejects.toThrow(
      `Derived code challenge 'something' from code_verifier 'something' using code challenge method 'plain' does not match the expected code challenge.`
    )
  })

  test('handles dpop expected but not provided', async () => {
    await expect(
      verifyAuthorizationCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        grant: {
          grantType: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        callbacks,
        expectedCode: 'hello2',
        request,
        dpop: {
          required: true,
        },
      })
    ).rejects.toThrow('Missing required DPoP proof')
  })

  test('handles dpop provided but not valid', async () => {
    await expect(
      verifyAuthorizationCodeAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        grant: {
          grantType: authorizationCodeGrantIdentifier,
          code: 'hello2',
        },
        callbacks,
        expectedCode: 'hello2',
        request: {
          ...request,
          headers: new Headers({
            DPoP: 'ey',
          }),
        },
        dpop: {
          required: true,
          jwt: 'ey',
        },
      })
    ).rejects.toThrow('Jwt is not a valid jwt, unable to decode')
  })

  test('handles valid autohrization code request', async () => {
    const dpopPrivateJwk = {
      kty: 'EC',
      d: 'UxBOEoXuH9qlZ0Bo2E1sCuZDkAzVl99eenarvWMrgH0',
      crv: 'P-256',
      x: 'BvowcNvKitnPOIU7EQSP6mvHG46mqJp1iVEeaHRkzMQ',
      y: 'h2kx9opNMxfK1_mcx2t5SIPf-kg4oNXS77tBxDvy1TM',
    }
    const { d, ...dpopPublicJwk } = dpopPrivateJwk

    const dpopJwt = await createDpopJwt({
      callbacks: {
        ...callbacks,
        signJwt: getSignJwtCallback([dpopPrivateJwk]),
      },
      request,
      signer: {
        method: 'jwk',
        publicJwk: dpopPublicJwk,
        alg: 'ES256',
      },
    })

    const now = new Date()

    const { dpopJwk } = await verifyAuthorizationCodeAccessTokenRequest({
      accessTokenRequest: {
        grant_type: authorizationCodeGrantIdentifier,
        code: 'hello2',
        code_verifier: 'something',
      },
      grant: {
        grantType: authorizationCodeGrantIdentifier,
        code: 'hello2',
      },
      callbacks,
      expectedCode: 'hello2',
      request: {
        ...request,
        headers: new Headers({
          DPoP: dpopJwt,
        }),
      },
      // 1 minute
      codeExpiresAt: new Date(now.getTime() + 60000),
      now,
      dpop: {
        required: true,
        jwt: dpopJwt,
        allowedSigningAlgs: ['ES256'],
      },
      pkce: {
        codeChallenge: 'something',
        codeVerifier: 'something',
        codeChallengeMethod: PkceCodeChallengeMethod.Plain,
      },
    })

    expect(dpopJwk).toEqual(dpopPublicJwk)
  })
})
