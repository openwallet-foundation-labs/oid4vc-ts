import { Oauth2Error } from '@openid4vc/oauth2'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import { parseDcqlVpToken, parsePexVpToken } from '../vp-token/parse-vp-token'
import type { ValidateOpenid4VpAuthorizationResponseResult } from './validate-authorization-response-result'
import type { Openid4vpAuthorizationResponse } from './z-authorization-response'

export interface ValidateOpenid4vpAuthorizationResponseOptions {
  requestPayload: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  responsePayload: Openid4vpAuthorizationResponse
}

/**
 * The following steps need to be performed outside of this library
 * - verifying the presentations
 * - validating the presentations against the presentation definition
 * - checking the revocation status of the presentations
 * - checking the nonce of the presentations matches the nonce of the request (for mdoc's)
 */
export function validateOpenid4vpAuthorizationResponsePayload(
  options: ValidateOpenid4vpAuthorizationResponseOptions
): ValidateOpenid4VpAuthorizationResponseResult {
  const { requestPayload, responsePayload } = options

  if ('state' in requestPayload && requestPayload.state !== responsePayload.state) {
    throw new Oauth2Error('OpenId4Vp Authorization Response state mismatch.')
  }

  // TODO: implement id_token handling
  if (responsePayload.id_token) {
    throw new Oauth2Error('OpenId4Vp Authorization Response id_token is not supported.')
  }

  if (responsePayload.presentation_submission) {
    if (!requestPayload.presentation_definition) {
      throw new Oauth2Error('OpenId4Vp Authorization Request is missing the required presentation_definition.')
    }

    return {
      type: 'pex',
      pex:
        'scope' in requestPayload && requestPayload.scope
          ? {
              scope: requestPayload.scope,
              presentationSubmission: responsePayload.presentation_submission,
              presentations: parsePexVpToken(responsePayload.vp_token),
            }
          : {
              presentationDefinition: requestPayload.presentation_definition,
              presentationSubmission: responsePayload.presentation_submission,
              presentations: parsePexVpToken(responsePayload.vp_token),
            },
    }
  }

  if (requestPayload.dcql_query) {
    const presentations = parseDcqlVpToken(responsePayload.vp_token)

    return {
      type: 'dcql',
      dcql:
        'scope' in requestPayload && requestPayload.scope
          ? {
              scope: requestPayload.scope,
              presentations,
            }
          : {
              query: requestPayload.dcql_query,
              presentations,
            },
    }
  }

  throw new Oauth2Error(
    'Invalid OpenId4Vp Authorization Response. Response neither contains a presentation_submission nor request contains a dcql_query.'
  )
}
