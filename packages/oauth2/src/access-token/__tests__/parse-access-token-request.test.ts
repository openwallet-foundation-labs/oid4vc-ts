import { describe, expect, test } from 'vitest'
import { authorizationCodeGrantIdentifier, preAuthorizedCodeGrantIdentifier } from '../../z-grant-type'
import { parseAccessTokenRequest } from '../parse-access-token-request'

describe('Parse Access Token Request', () => {
  test('handles invalid structure', () => {
    expect(() =>
      parseAccessTokenRequest({
        accessTokenRequest: {},
        request: {
          headers: new Headers(),
          method: 'POST',
          url: 'https://request.com/token',
        },
      })
    ).toThrow('Error occured during validation of authorization request.')
  })

  test('handles unknown grant_type', () => {
    expect(() =>
      parseAccessTokenRequest({
        accessTokenRequest: {
          grant_type: 'something',
        },
        request: {
          headers: new Headers(),
          method: 'POST',
          url: 'https://request.com/token',
        },
      })
    ).toThrow(`The grant type 'something' is not supported`)
  })

  test('handles unknown grant_type', () => {
    expect(() =>
      parseAccessTokenRequest({
        accessTokenRequest: {
          grant_type: 'something',
        },
        request: {
          headers: new Headers(),
          method: 'POST',
          url: 'https://request.com/token',
        },
      })
    ).toThrow(`The grant type 'something' is not supported`)
  })

  test('handles mising pre-authorized_code for pre-auth grant_type', () => {
    expect(() =>
      parseAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
        },
        request: {
          headers: new Headers(),
          method: 'POST',
          url: 'https://request.com/token',
        },
      })
    ).toThrow(`Missing required 'pre-authorized_code' for grant type '${preAuthorizedCodeGrantIdentifier}'`)
  })

  test('handles mising code for authorization_code grant_type', () => {
    expect(() =>
      parseAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
        },
        request: {
          headers: new Headers(),
          method: 'POST',
          url: 'https://request.com/token',
        },
      })
    ).toThrow(`Missing required 'code' for grant type '${authorizationCodeGrantIdentifier}'`)
  })

  test('handles invalid DPoP header value', () => {
    expect(() =>
      parseAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
          code: 'something',
        },
        request: {
          headers: new Headers({
            DPoP: ['ey.ey.S', 'ey.ey.S'] as unknown as string,
          }),
          method: 'POST',
          url: 'https://request.com/token',
        },
      })
    ).toThrow(`Request contains a 'DPoP' header, but the value is not a valid DPoP jwt`)
  })

  test('handles pre authorized code grant', () => {
    expect(
      parseAccessTokenRequest({
        accessTokenRequest: {
          grant_type: preAuthorizedCodeGrantIdentifier,
          'pre-authorized_code': 'pre-auth',
          tx_code: 'tx-code-value',
        },
        request: {
          headers: new Headers({}),
          method: 'POST',
          url: 'https://request.com/token',
        },
      })
    ).toEqual({
      accessTokenRequest: {
        grant_type: preAuthorizedCodeGrantIdentifier,
        'pre-authorized_code': 'pre-auth',
        tx_code: 'tx-code-value',
      },
      grant: {
        grantType: preAuthorizedCodeGrantIdentifier,
        preAuthorizedCode: 'pre-auth',
        txCode: 'tx-code-value',
      },
      dpopJwt: undefined,
      pkceCodeVerifier: undefined,
    })
  })

  test('handles authorized code grant', () => {
    expect(
      parseAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
          code: 'auth-code',
          code_verifier: 'hello',
        },
        request: {
          headers: new Headers({
            DPoP: 'dpop-jwt',
          }),
          method: 'POST',
          url: 'https://request.com/token',
        },
      })
    ).toEqual({
      accessTokenRequest: {
        grant_type: authorizationCodeGrantIdentifier,
        code: 'auth-code',
        code_verifier: 'hello',
      },
      grant: {
        grantType: authorizationCodeGrantIdentifier,
        code: 'auth-code',
      },
      dpopJwt: 'dpop-jwt',
      pkceCodeVerifier: 'hello',
    })
  })
})
