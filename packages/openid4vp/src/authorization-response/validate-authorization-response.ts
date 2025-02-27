import { Oauth2Error } from '@openid4vc/oauth2'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'
import {
  parseDcqlPresentationFromVpToken,
  parsePresentationsFromVpToken,
} from '../vp-token/parse-presentations-from-vp-token'
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
export function validateOpenid4vpAuthorizationResponse(
  options: ValidateOpenid4vpAuthorizationResponseOptions
): ValidateOpenid4VpAuthorizationResponseResult {
  const { requestPayload, responsePayload } = options
  if (!responsePayload.vp_token) {
    throw new Oauth2Error('Failed to verify OpenId4Vp Authorization Response. vp_token is missing.')
  }

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

    // TODO: ENABLE THIS CHECK ALL THE TIME ONCE WE KNOW HOW TO GET THE NONCE FOR MDOCS AND ANONCREDS
    const presentations = parsePresentationsFromVpToken({ vpToken: responsePayload.vp_token })
    if (presentations.every((p) => p.nonce) && !presentations.every((p) => p.nonce === requestPayload.nonce)) {
      throw new Oauth2Error(
        'Presentation nonce mismatch. The nonce of some presentations does not match the nonce of the request.'
      )
    }

    return {
      type: 'pex',
      pex:
        'scope' in requestPayload && requestPayload.scope
          ? {
              scope: requestPayload.scope,
              presentationSubmission: responsePayload.presentation_submission,
              presentations,
            }
          : {
              presentationDefinition: requestPayload.presentation_definition,
              presentationSubmission: responsePayload.presentation_submission,
              presentations,
            },
    }
  }

  if (requestPayload.dcql_query) {
    if (Array.isArray(responsePayload.vp_token)) {
      throw new Oauth2Error(
        'The OpenId4Vp Authorization Response contains multiple vp_token values. In combination with dcql this is not possible.'
      )
    }

    if (typeof responsePayload.vp_token !== 'string' && typeof responsePayload.vp_token !== 'object') {
      throw new Oauth2Error('With DCQL the vp_token must be a JSON-encoded object.')
    }

    const presentation = parseDcqlPresentationFromVpToken({ vpToken: responsePayload.vp_token })

    // TODO: CHECK ALL THE NONCES ONCE WE KNOW HOW TO GET THE NONCE FOR MDOCS AND ANONCREDS
    if (
      Object.values(presentation).every((p) => p.nonce) &&
      !Object.values(presentation).every((p) => p.nonce === requestPayload.nonce)
    ) {
      throw new Oauth2Error(
        'Presentation nonce mismatch. The nonce of some presentations does not match the nonce of the request.'
      )
    }

    return {
      type: 'dcql',
      dcql:
        'scope' in requestPayload && requestPayload.scope
          ? {
              scope: requestPayload.scope,
              presentation,
            }
          : {
              query: requestPayload.dcql_query,
              presentation,
            },
    }
  }

  throw new Oauth2Error(
    'Invalid OpenId4Vp Authorization Response. Response neither contains a presentation_submission nor a dcql_query.'
  )
}
