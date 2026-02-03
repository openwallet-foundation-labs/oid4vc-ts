import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'
import type { AuthorizationServerMetadata } from '../metadata/authorization-server/z-authorization-server-metadata'
import type { AuthorizationErrorResponse, AuthorizationResponse } from './z-authorization-response'

export interface VerifyAuthorizationResponseOptions {
  authorizationServerMetadata: AuthorizationServerMetadata
  authorizationResponse: AuthorizationResponse | AuthorizationErrorResponse
}

/**
 * Verifies an authorization (error) response.
 *
 * Currently it only verifies that the 'iss' value in an authorization (error) response matches the 'issuer' value of the authorization server metadata
 * according to RFC 9207.
 *
 * You can call this method after calling `parseAuthorizationResponse` and having fetched the associated session/authorization server
 * for the authorization response, to be able to verify the issuer
 */
export function verifyAuthorizationResponse({
  authorizationResponse,
  authorizationServerMetadata,
}: VerifyAuthorizationResponseOptions) {
  const expectedIssuer = authorizationServerMetadata.issuer
  const responseIssuer = authorizationResponse.iss

  if (authorizationServerMetadata.authorization_response_iss_parameter_supported && !responseIssuer) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description:
        "Authorization server requires 'iss' parameter in authorization response (authorization_response_iss_parameter_supported), but no 'iss' parameter is present in the authorization response.",
    })
  }

  if (responseIssuer && responseIssuer !== expectedIssuer) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description:
        "The 'iss' value in the authorization response does not match the expected 'issuer' value from the authorization server metadata.",
    })
  }
}
