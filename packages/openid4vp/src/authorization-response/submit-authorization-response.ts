import { type CallbackContext, Oauth2Error } from '@openid4vc/oauth2'
import { ContentType, defaultFetcher } from '@openid4vc/utils'
import { objectToQueryParams } from '@openid4vc/utils'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import { jarmAuthResponseSend } from '../jarm/jarm-auth-response-send'
import type { Openid4vpAuthorizationResponse } from './z-authorization-response'

export interface SubmitOpenid4vpAuthorizationResponseOptions {
  requestPayload: Pick<Openid4vpAuthorizationRequest, 'response_uri'>
  responsePayload: Openid4vpAuthorizationResponse
  jarm?: { responseJwt: string }
  callbacks: Pick<CallbackContext, 'fetch'>
}

export async function submitOpenid4vpAuthorizationResponse(options: SubmitOpenid4vpAuthorizationResponseOptions) {
  const { requestPayload, responsePayload, jarm, callbacks } = options
  const url = requestPayload.response_uri

  if (jarm) {
    return jarmAuthResponseSend({
      authRequest: requestPayload,
      jarmAuthResponseJwt: jarm.responseJwt,
      callbacks,
    })
  }

  if (!url) {
    throw new Oauth2Error(
      'Failed to submit OpenId4Vp Authorization Response. No redirect_uri or response_uri provided.'
    )
  }

  const fetch = callbacks.fetch ?? defaultFetcher
  const encodedResponse = objectToQueryParams(responsePayload)
  const submissionResponse = await fetch(url, {
    method: 'POST',
    body: encodedResponse,
    headers: {
      'Content-Type': ContentType.XWwwFormUrlencoded,
    },
  })

  return {
    responseMode: 'direct_post',
    response: submissionResponse,
  }
}
