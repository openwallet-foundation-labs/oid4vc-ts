import { describe, expect, test } from 'vitest'
import { Oauth2ServerErrorResponseError } from '../../error/Oauth2ServerErrorResponseError.js'
import {
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
  refreshTokenGrantIdentifier,
} from '../../z-grant-type.js'
import { parseAccessTokenRequest } from '../parse-access-token-request.js'

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
    ).toThrow('Error occurred during validation of authorization request.')
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

  test('handles missing pre-authorized_code for pre-auth grant_type', () => {
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

  test('handles missing code for authorization_code grant_type', () => {
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
            DPoP: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.dpop',
            'OAuth-Client-Attestation':
              'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.client-attestation',
            'OAuth-Client-Attestation-PoP':
              'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.client-attestation-pop',
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
      clientAttestation: {
        clientAttestationJwt:
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.client-attestation',
        clientAttestationPopJwt:
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.client-attestation-pop',
      },
      dpop: {
        jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.dpop',
      },
      pkceCodeVerifier: 'hello',
    })
  })

  test('handles refresh token grant', () => {
    expect(
      parseAccessTokenRequest({
        accessTokenRequest: {
          grant_type: refreshTokenGrantIdentifier,
          refresh_token: 'mamma-mia',
        },
        request: {
          headers: new Headers({}),
          method: 'POST',
          url: 'https://request.com/token',
        },
      })
    ).toEqual({
      accessTokenRequest: {
        grant_type: refreshTokenGrantIdentifier,
        refresh_token: 'mamma-mia',
      },
      grant: {
        grantType: refreshTokenGrantIdentifier,
        refreshToken: 'mamma-mia',
      },
      dpopJwt: undefined,
      pkceCodeVerifier: undefined,
    })
  })

  test('handles invalid dpop jwt', () =>
    expect(() =>
      parseAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
          code: 'auth-code',
          code_verifier: 'hello',
        },
        request: {
          headers: new Headers({
            DPoP: 'random',
            'OAuth-Client-Attestation':
              'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.client-attestation',
            'OAuth-Client-Attestation-PoP':
              'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.client-attestation-pop',
          }),
          method: 'POST',
          url: 'https://request.com/token',
        },
      })
    ).toThrow(
      new Oauth2ServerErrorResponseError({
        error: 'invalid_dpop_proof',
        error_description: `Request contains a 'DPoP' header, but the value is not a valid DPoP jwt`,
      })
    ))

  test('handles invalid client attestation jwt', () =>
    expect(() =>
      parseAccessTokenRequest({
        accessTokenRequest: {
          grant_type: authorizationCodeGrantIdentifier,
          code: 'auth-code',
          code_verifier: 'hello',
        },
        request: {
          headers: new Headers({
            'OAuth-Client-Attestation': 'something',
            'OAuth-Client-Attestation-PoP':
              'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.client-attestation-pop',
          }),
          method: 'POST',
          url: 'https://request.com/token',
        },
      })
    ).toThrow(
      new Oauth2ServerErrorResponseError({
        error: 'invalid_client',
        error_description:
          'Request contains client attestation header, but the values are not valid client attestation and client attestation PoP header.',
      })
    ))
})
