import type { CallbackContext } from '@openid4vc/oauth2'
import { ContentType, defaultFetcher } from '@openid4vc/utils'
import { xWwwFormUrlEncodeObject } from '@openid4vc/utils'
import { jarmAuthResponseSend } from '../jarm/jarm-auth-response-send'
import type { Openid4vpAuthRequest } from '../openid4vp-auth-request/v-openid4vp-auth-request'
import type { Openid4vpAuthResponse } from './v-openid4vp-auth-response'

export async function submitOpenid4vpAuthorizationResponse(input: {
  request: Pick<Openid4vpAuthRequest, 'redirect_uri' | 'response_uri'>
  response: Openid4vpAuthResponse
  jarm?: { responseJwt: string }
  callbacks: Pick<CallbackContext, 'fetch'>
}) {
  const { request, response, jarm, callbacks } = input
  const url = request.redirect_uri ?? request.response_uri

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
  const encodedResponse = xWwwFormUrlEncodeObject(response)
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
