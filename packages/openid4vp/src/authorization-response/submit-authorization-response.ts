import type { CallbackContext } from '@openid4vc/oauth2'
import { ContentType, defaultFetcher } from '@openid4vc/utils'
import { objectToQueryParams } from '@openid4vc/utils'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import { jarmAuthResponseSend } from '../jarm/jarm-auth-response-send'
import type { Openid4vpAuthorizationResponse } from './z-authorization-response'

export interface SubmitOpenid4vpAuthorizationResponseOptions {
  request: Pick<Openid4vpAuthorizationRequest, 'response_uri'>
  response: Openid4vpAuthorizationResponse
  jarm?: { responseJwt: string }
  callbacks: Pick<CallbackContext, 'fetch'>
}

export async function submitOpenid4vpAuthorizationResponse(options: SubmitOpenid4vpAuthorizationResponseOptions) {
  const { request, response, jarm, callbacks } = options
  const url = request.response_uri

  if (jarm) {
    return jarmAuthResponseSend({
      authRequest: request,
      jarmAuthResponseJwt: jarm.responseJwt,
      callbacks,
    })
  }

  if (!url) {
    throw new Error('No redirect_uri or response_uri provided')
  }

  const fetch = callbacks.fetch ?? defaultFetcher
  const encodedResponse = objectToQueryParams(response)
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
