import { type CallbackContext, Oauth2Error } from '@openid4vc/oauth2'
import { ContentType, URL, defaultFetcher } from '@openid4vc/utils'

interface JarmAuthResponseSendOptions {
  authRequest: {
    response_uri?: string
    redirect_uri?: string
  }
  jarmAuthResponseJwt: string
  callbacks: Pick<CallbackContext, 'fetch'>
}

export const jarmAuthResponseSend = (options: JarmAuthResponseSendOptions) => {
  const { authRequest, jarmAuthResponseJwt, callbacks } = options

  const responseEndpoint = authRequest.response_uri ?? authRequest.redirect_uri
  if (!responseEndpoint) {
    throw new Oauth2Error('response_uri or redirect_uri is required')
  }

  const responseEndpointUrl = new URL(responseEndpoint)
  return handleDirectPostJwt(responseEndpointUrl, jarmAuthResponseJwt, callbacks)
}

async function handleDirectPostJwt(
  responseEndpoint: URL,
  responseJwt: string,
  callbacks: Pick<CallbackContext, 'fetch'>
) {
  const response = await (callbacks.fetch ?? defaultFetcher)(responseEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': ContentType.XWwwFormUrlencoded },
    body: `response=${responseJwt}`,
  })

  return {
    responseMode: 'direct_post.jwt',
    response,
  } as const
}
