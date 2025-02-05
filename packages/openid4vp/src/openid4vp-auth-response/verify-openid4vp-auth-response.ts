import { Oauth2Error } from '@openid4vc/oauth2'
import type { Openid4vpAuthRequest } from '../openid4vp-auth-request/z-openid4vp-auth-request'
import {
  parseDcqlPresentationFromVpToken,
  parsePresentationsFromVpToken,
} from '../vp-token/parse-presentations-from-vp-token'
import type { VerifyOpenid4VpAuthorizationResponseResult } from './verify-openid4vp-auth-response-result'
import type { Openid4vpAuthResponse } from './z-openid4vp-auth-response'

/**
 * The following steps need to be done manually
    // validating the id token
    // verifying the presentations
    // validating the presentations against the presentation definition
    // checking the revocation status of the presentations
    // checking the nonce of the presentations matches the nonce of the request
 */
export function verifyOpenid4vpAuthorizationResponse(options: {
  requestParams: Openid4vpAuthRequest
  responseParams: Openid4vpAuthResponse
}): VerifyOpenid4VpAuthorizationResponseResult {
  const { requestParams, responseParams } = options
  // todo i think the response prarms  should also contain a nonce
  if (!responseParams.vp_token) {
    throw new Oauth2Error('Failed to verify OpenId4Vp Authorization Response. vp_token is missing.')
  }

  if (requestParams.state !== responseParams.state) {
    throw new Oauth2Error('OpenId4Vp Authorization Response state mismatch.')
  }

  // TODO: implement id_token handling
  if (responseParams.id_token) {
    throw new Oauth2Error('OpenId4Vp Authorization Response id_token is not supported.')
  }

  if (responseParams.presentation_submission) {
    if (!requestParams.presentation_definition) {
      throw new Oauth2Error('OpenId4Vp Authorization Request is missing the required presentation_definition.')
    }

    // TODO: ENABLE THIS CHECK ALL THE TIME ONCE WE KNOW HOW TO GET THE NONCE FOR MDOCS AND ANONCREDS
    const presentations = parsePresentationsFromVpToken({ vpToken: responseParams.vp_token })
    if (presentations.every((p) => p.nonce) && !presentations.every((p) => p.nonce === requestParams.nonce)) {
      throw new Oauth2Error(
        'Presentation nonce mismatch. The nonce of some presentations does not match the nonce of the request.'
      )
    }

    return {
      type: 'pex',
      pex: requestParams.scope
        ? {
            scope: requestParams.scope,
            presentationSubmission: responseParams.presentation_submission,
            presentations,
          }
        : {
            presentationDefinition: requestParams.presentation_definition,
            presentationSubmission: responseParams.presentation_submission,
            presentations,
          },
    }
  }

  if (requestParams.dcql_query) {
    if (Array.isArray(responseParams.vp_token)) {
      throw new Oauth2Error(
        'The OpenId4Vp Authorization Response contains multiple vp_token values. In combination with dcql this is not possible.'
      )
    }

    if (typeof responseParams.vp_token !== 'string') {
      throw new Oauth2Error('If DCQL was used the vp_token must be a JSON-encoded object.')
    }

    const presentation = parseDcqlPresentationFromVpToken({ vpToken: responseParams.vp_token, path: '$' })
    // TODO: CHECK ALL THE NONCES ONCE WE KNOW HOW TO GET THE NONCE FOR MDOCS AND ANONCREDS

    return {
      type: 'dcql',
      dcql: requestParams.scope
        ? {
            scope: requestParams.scope,
            presentation,
          }
        : {
            query: requestParams.dcql_query,
            presentation,
          },
    }
  }

  throw new Oauth2Error(
    'Invalid OpenId4Vp Authorization Response. Response neither contains a presentation_submission nor a dcql presentation.'
  )
}
