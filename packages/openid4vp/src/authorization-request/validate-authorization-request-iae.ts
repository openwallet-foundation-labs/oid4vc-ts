import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import type { Openid4vpAuthorizationRequestIae } from './z-authorization-request-iae'

export interface ValidateOpenid4vpAuthorizationRequestIaePayloadOptions {
  params: Openid4vpAuthorizationRequestIae
  isJarRequest: boolean
  /** The URL of the endpoint that will receive the response (for validating expected_url) */
  expectedUrl?: string

  disableExpectedUrlValidation?: boolean
}

/**
 * Validate the OpenId4Vp Authorization Request parameters for the IAE (Interactive Authorization Endpoint) response mode
 *
 * The IAE flow is part of OpenID4VCI 1.1 and is used when the authorization server needs to
 * interact directly with the wallet during the authorization process.
 *
 * Key validation rules:
 * - For signed requests (JAR), expected_url parameter is validated against the actual endpoint URL
 * - expected_url is used instead of expected_origins to prevent replay attacks
 * - dcql_query must be present
 */
export const validateOpenid4vpAuthorizationRequestIaePayload = (
  options: ValidateOpenid4vpAuthorizationRequestIaePayloadOptions
) => {
  const { params, isJarRequest, expectedUrl, disableExpectedUrlValidation } = options

  // OpenID4VCI 1.1 IAE: expected_url validation for signed requests
  if (isJarRequest && !params.expected_url) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `The 'expected_url' parameter MUST be present when using the iae_post response mode in combination with jar.`,
    })
  }

  if (!params.dcql_query) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: 'dcql_query MUST be present when using iae_post response mode.',
    })
  }

  if (params.expected_url && !disableExpectedUrlValidation) {
    if (!expectedUrl) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Failed to validate the 'expected_url' of the authorization request. The 'expectedUrl' was not provided for validation.`,
      })
    }

    if (params.expected_url !== expectedUrl) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `The 'expected_url' parameter does not match the follow-up request URL. This prevents replay attacks from malicious verifiers.`,
      })
    }
  }
}
