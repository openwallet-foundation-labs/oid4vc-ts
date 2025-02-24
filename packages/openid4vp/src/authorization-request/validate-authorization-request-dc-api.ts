import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import type { Openid4vpAuthorizationRequestDcApi } from './z-authorization-request-dc-api'

export interface ValidateOpenid4vpAuthorizationRequestDcApiPayloadOptions {
  params: Openid4vpAuthorizationRequestDcApi
  isJarRequest: boolean
  omitOriginValidation?: boolean
  origin?: string
}

/**
 * Validate the OpenId4Vp Authorization Request parameters for the dc_api response mode
 */
export const validateOpenid4vpAuthorizationRequestDcApiPayload = (
  options: ValidateOpenid4vpAuthorizationRequestDcApiPayloadOptions
) => {
  const { params, isJarRequest, omitOriginValidation, origin } = options

  if (isJarRequest && !params.expected_origins) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description: `The 'expected_origins' parameter MUST be present when using the dc_api response mode in combinaction with jar.`,
    })
  }

  if ([params.presentation_definition, params.dcql_query].filter(Boolean).length > 1) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequest,
      error_description:
        'Exactly one of the following parameters MUST be present in the Authorization Request: dcql_query, presentation_definition, presentation_definition_uri, or a scope value representing a Presentation Definition.',
    })
  }

  if (params.expected_origins && !omitOriginValidation) {
    if (!origin) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `Failed to validate the 'origin' of the authorization request. The 'origin' was not provided.`,
      })
    }

    if (params.expected_origins && !params.expected_origins.includes(origin)) {
      throw new Oauth2ServerErrorResponseError({
        error: Oauth2ErrorCodes.InvalidRequest,
        error_description: `The 'expected_origins' parameter MUST include the origin of the authorization request. Current: ${params.expected_origins.join(', ')}`,
      })
    }
  }
}
