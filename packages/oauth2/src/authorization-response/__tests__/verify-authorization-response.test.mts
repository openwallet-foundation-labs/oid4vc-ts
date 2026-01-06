import { describe, expect, test } from 'vitest'
import { Oauth2ErrorCodes } from '../../common/z-oauth2-error.js'
import { Oauth2ServerErrorResponseError } from '../../error/Oauth2ServerErrorResponseError.js'
import { verifyAuthorizationResponse } from '../verify-authorization-response.js'

describe('verifyAuthorizationResponseIssuer', () => {
  const baseMetadata = {
    issuer: 'https://authorization-server.example.com',
    authorization_endpoint: 'https://authorization-server.example.com/authorize',
    token_endpoint: 'https://authorization-server.example.com/token',
  }

  test('succeeds when iss parameter matches issuer and authorization_response_iss_parameter_supported is true', () => {
    expect(() =>
      verifyAuthorizationResponse({
        authorizationServerMetadata: {
          ...baseMetadata,
          authorization_response_iss_parameter_supported: true,
        },
        authorizationResponse: {
          code: 'something',
          iss: 'https://authorization-server.example.com',
        },
      })
    ).not.toThrow()
  })

  test('succeeds when iss parameter matches issuer and authorization_response_iss_parameter_supported is false', () => {
    expect(() =>
      verifyAuthorizationResponse({
        authorizationServerMetadata: {
          ...baseMetadata,
          authorization_response_iss_parameter_supported: false,
        },
        authorizationResponse: {
          code: 'something',
          iss: 'https://authorization-server.example.com',
        },
      })
    ).not.toThrow()
  })

  test('succeeds when iss parameter matches issuer and authorization_response_iss_parameter_supported is undefined', () => {
    expect(() =>
      verifyAuthorizationResponse({
        authorizationServerMetadata: baseMetadata,
        authorizationResponse: {
          code: 'something',
          iss: 'https://authorization-server.example.com',
        },
      })
    ).not.toThrow()
  })

  test('succeeds when iss parameter is missing and authorization_response_iss_parameter_supported is false', () => {
    expect(() =>
      verifyAuthorizationResponse({
        authorizationServerMetadata: {
          ...baseMetadata,
          authorization_response_iss_parameter_supported: false,
        },
        authorizationResponse: {
          code: 'something',
        },
      })
    ).not.toThrow()
  })

  test('succeeds when iss parameter is missing and authorization_response_iss_parameter_supported is undefined', () => {
    expect(() =>
      verifyAuthorizationResponse({
        authorizationServerMetadata: baseMetadata,
        authorizationResponse: {
          code: 'something',
        },
      })
    ).not.toThrow()
  })

  test('throws when iss parameter is required but missing', () => {
    expect(() =>
      verifyAuthorizationResponse({
        authorizationServerMetadata: {
          ...baseMetadata,
          authorization_response_iss_parameter_supported: true,
        },
        authorizationResponse: {
          code: 'something',
        },
      })
    ).toThrow(Oauth2ServerErrorResponseError)

    try {
      verifyAuthorizationResponse({
        authorizationServerMetadata: {
          ...baseMetadata,
          authorization_response_iss_parameter_supported: true,
        },
        authorizationResponse: {
          code: 'something',
        },
      })
    } catch (error) {
      expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
      if (error instanceof Oauth2ServerErrorResponseError) {
        expect(error.errorResponse.error).toBe(Oauth2ErrorCodes.InvalidRequest)
        expect(error.errorResponse.error_description).toContain(
          "Authorization server requires 'iss' parameter in authorization response"
        )
      }
    }
  })

  test('throws when iss parameter does not match issuer', () => {
    expect(() =>
      verifyAuthorizationResponse({
        authorizationServerMetadata: baseMetadata,
        authorizationResponse: {
          code: 'something',
          iss: 'https://malicious-server.example.com',
        },
      })
    ).toThrow(Oauth2ServerErrorResponseError)

    try {
      verifyAuthorizationResponse({
        authorizationServerMetadata: baseMetadata,
        authorizationResponse: {
          code: 'something',
          iss: 'https://malicious-server.example.com',
        },
      })
    } catch (error) {
      expect(error).toBeInstanceOf(Oauth2ServerErrorResponseError)
      if (error instanceof Oauth2ServerErrorResponseError) {
        expect(error.errorResponse.error).toBe(Oauth2ErrorCodes.InvalidRequest)
        expect(error.errorResponse.error_description).toContain(
          "The 'iss' value in the authorization response does not match the expected 'issuer' value"
        )
      }
    }
  })

  test('throws when iss parameter has different casing', () => {
    expect(() =>
      verifyAuthorizationResponse({
        authorizationServerMetadata: baseMetadata,
        authorizationResponse: {
          code: 'something',
          iss: 'HTTPS://AUTHORIZATION-SERVER.EXAMPLE.COM',
        },
      })
    ).toThrow(Oauth2ServerErrorResponseError)
  })

  test('throws when iss parameter has trailing slash difference', () => {
    expect(() =>
      verifyAuthorizationResponse({
        authorizationServerMetadata: baseMetadata,
        authorizationResponse: {
          code: 'something',
          iss: 'https://authorization-server.example.com/',
        },
      })
    ).toThrow(Oauth2ServerErrorResponseError)
  })
})
