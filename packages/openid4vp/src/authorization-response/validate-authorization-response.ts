import { Oauth2Error } from '@openid4vc/oauth2'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import {
  parseDcqlPresentationFromVpToken,
  parsePresentationsFromVpToken,
} from '../vp-token/parse-presentations-from-vp-token'
import type { ValidateOpenid4VpAuthorizationResponseResult } from './validate-authorization-response-result'
import type { Openid4vpAuthorizationResponse } from './z-authorization-response'
import type { Openid4vpAuthorizationResponseDcApi } from './z-authorization-response-dc-api'

export interface ValidateOpenid4vpAuthorizationResponseOptions {
  authorizationRequest: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
  authorizationResponse: Openid4vpAuthorizationResponse | Openid4vpAuthorizationResponseDcApi['data']
}

/**
 * The following steps need to be performed outside of this library
 * - verifying the presentations
 * - validating the presentations against the presentation definition
 * - checking the revocation status of the presentations
 * - checking the nonce of the presentations matches the nonce of the request (for mdoc's)
 */
export function validateOpenid4vpAuthorizationResponse(
  options: ValidateOpenid4vpAuthorizationResponseOptions
): ValidateOpenid4VpAuthorizationResponseResult {
  const { authorizationRequest, authorizationResponse } = options
  // todo i think the response prarms  should also contain a nonce
  if (!authorizationResponse.vp_token) {
    throw new Oauth2Error('Failed to verify OpenId4Vp Authorization Response. vp_token is missing.')
  }

  if ('state' in authorizationRequest && authorizationRequest.state !== authorizationResponse.state) {
    throw new Oauth2Error('OpenId4Vp Authorization Response state mismatch.')
  }

  // TODO: implement id_token handling
  if (authorizationResponse.id_token) {
    throw new Oauth2Error('OpenId4Vp Authorization Response id_token is not supported.')
  }

  if (authorizationResponse.presentation_submission) {
    if (!authorizationRequest.presentation_definition) {
      throw new Oauth2Error('OpenId4Vp Authorization Request is missing the required presentation_definition.')
    }

    // TODO: ENABLE THIS CHECK ALL THE TIME ONCE WE KNOW HOW TO GET THE NONCE FOR MDOCS AND ANONCREDS
    const presentations = parsePresentationsFromVpToken({ vpToken: authorizationResponse.vp_token })
    if (presentations.every((p) => p.nonce) && !presentations.every((p) => p.nonce === authorizationRequest.nonce)) {
      throw new Oauth2Error(
        'Presentation nonce mismatch. The nonce of some presentations does not match the nonce of the request.'
      )
    }

    return {
      type: 'pex',
      pex:
        'scope' in authorizationRequest && authorizationRequest.scope
          ? {
              scope: authorizationRequest.scope,
              presentationSubmission: authorizationResponse.presentation_submission,
              presentations,
            }
          : {
              presentationDefinition: authorizationRequest.presentation_definition,
              presentationSubmission: authorizationResponse.presentation_submission,
              presentations,
            },
    }
  }

  if (authorizationRequest.dcql_query) {
    if (Array.isArray(authorizationResponse.vp_token)) {
      throw new Oauth2Error(
        'The OpenId4Vp Authorization Response contains multiple vp_token values. In combination with dcql this is not possible.'
      )
    }

    if (typeof authorizationResponse.vp_token !== 'string' && typeof authorizationResponse.vp_token !== 'object') {
      throw new Oauth2Error('If DCQL was used the vp_token must be a JSON-encoded object.')
    }

    const presentation = parseDcqlPresentationFromVpToken({ vpToken: authorizationResponse.vp_token })
    // TODO: CHECK ALL THE NONCES ONCE WE KNOW HOW TO GET THE NONCE FOR MDOCS AND ANONCREDS

    return {
      type: 'dcql',
      dcql:
        'scope' in authorizationRequest && authorizationRequest.scope
          ? {
              scope: authorizationRequest.scope,
              presentation,
            }
          : {
              query: authorizationRequest.dcql_query,
              presentation,
            },
    }
  }

  throw new Oauth2Error(
    'Invalid OpenId4Vp Authorization Response. Response neither contains a presentation_submission nor a dcql presentation.'
  )
}
