import { Oauth2Error } from '@openid4vc/oauth2'
import type { Openid4vpAuthorizationRequestDcApi } from './z-authorization-request-dc-api'

export interface ValidateOpenid4vpAuthorizationRequestDcApiPayloadOptions {
  params: Openid4vpAuthorizationRequestDcApi
  isJarRequest: boolean
  omitOriginValidation?: boolean
  origin?: string
}

/**
 * Validate the OpenId4Vp Authorization Request parameters
 */
export const validateOpenid4vpAuthorizationRequestDcApiPayload = (
  options: ValidateOpenid4vpAuthorizationRequestDcApiPayloadOptions
) => {
  const { params, isJarRequest, omitOriginValidation, origin } = options

  if (isJarRequest && !params.expected_origins) {
    throw new Oauth2Error(
      `The 'expected_origins' parameter MUST be present when using the dc_api response mode in combinaction with jar.`
    )
  }

  if (params.expected_origins && !omitOriginValidation) {
    if (!origin) {
      throw new Oauth2Error(
        `The 'origin' validation parameter MUST be present when resolving an openid4vp dc_api authorization request.`
      )
    }

    if (params.expected_origins && !params.expected_origins.includes(origin)) {
      throw new Oauth2Error(
        `The 'expected_origins' parameter MUST include the origin of the authorization request. Current: ${params.expected_origins}`
      )
    }
  }

  if (params.client_id && !params.client_id.startsWith('web-origin:')) {
    throw new Oauth2Error(
      `The 'client_id' parameter MUST start with 'web-origin:' when using the dc_api response mode.`
    )
  }
}
