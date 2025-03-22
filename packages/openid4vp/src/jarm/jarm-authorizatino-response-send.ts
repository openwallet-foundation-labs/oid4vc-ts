import { type CallbackContext, Oauth2Error } from '@openid4vc/oauth2'
import { ContentType, URL, createFetcher } from '@openid4vc/utils'

interface JarmAuthorizationResponseSendOptions {
  authorizationRequestPayload: {
    response_uri?: string
    redirect_uri?: string
  }
  jarmAuthorizationResponseJwt: string
  callbacks: Pick<CallbackContext, 'fetch'>
}

export const jarmAuthorizationResponseSend = (options: JarmAuthorizationResponseSendOptions) => {
  const { authorizationRequestPayload, jarmAuthorizationResponseJwt, callbacks } = options

  const responseEndpoint = authorizationRequestPayload.response_uri ?? authorizationRequestPayload.redirect_uri
  if (!responseEndpoint) {
    throw new Oauth2Error(`Either 'response_uri' or 'redirect_uri' MUST  be present in the authorization request`)
  }

  const responseEndpointUrl = new URL(responseEndpoint)
  return handleDirectPostJwt(responseEndpointUrl, jarmAuthorizationResponseJwt, callbacks)
}

async function handleDirectPostJwt(
  responseEndpoint: URL,
  responseJwt: string,
  callbacks: Pick<CallbackContext, 'fetch'>
) {
  const response = await createFetcher(callbacks.fetch)(responseEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': ContentType.XWwwFormUrlencoded },
    body: `response=${responseJwt}`,
  })

  return {
    responseMode: 'direct_post.jwt',
    response,
  } as const
}
