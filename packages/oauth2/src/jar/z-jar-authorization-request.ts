import { zHttpsUrl } from '@openid4vc/utils'
import { z } from 'zod'
import { Oauth2ErrorCodes } from '../common/z-oauth2-error'
import { Oauth2ServerErrorResponseError } from '../error/Oauth2ServerErrorResponseError'

export const zJarAuthorizationRequest = z
  .object({
    request: z.optional(z.string()),
    request_uri: z.optional(zHttpsUrl),
    client_id: z.optional(z.string()),
  })
  .loose()
export type JarAuthorizationRequest = z.infer<typeof zJarAuthorizationRequest>

export function validateJarRequestParams(options: {
  jarRequestParams: JarAuthorizationRequest
  allowRequestUri?: boolean
}) {
  const { jarRequestParams, allowRequestUri = true } = options

  if (jarRequestParams.request && jarRequestParams.request_uri) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'request and request_uri cannot both be present in a JAR request',
    })
  }

  if (!jarRequestParams.request && !jarRequestParams.request_uri) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'request or request_uri must be present',
    })
  }

  if (jarRequestParams.request_uri && !allowRequestUri) {
    throw new Oauth2ServerErrorResponseError({
      error: Oauth2ErrorCodes.InvalidRequestObject,
      error_description: 'request_uri is not allowed',
    })
  }

  return jarRequestParams as JarAuthorizationRequest &
    ({ request_uri: string; request?: never } | { request: string; request_uri?: never })
}

export function isJarAuthorizationRequest(request: JarAuthorizationRequest): request is JarAuthorizationRequest {
  return 'request' in request || 'request_uri' in request
}
