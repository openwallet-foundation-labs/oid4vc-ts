import { Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { zHttpsUrl } from '@openid4vc/utils'
import { z } from 'zod'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'

export const zJarAuthorizationRequest = z
  .object({
    request: z.optional(z.string()),
    request_uri: z.optional(zHttpsUrl),
    request_uri_method: z.optional(z.string()),
    client_id: z.optional(z.string()),
  })
  .passthrough()
export type JarAuthorizationRequest = z.infer<typeof zJarAuthorizationRequest>

export function validateJarRequestParams(options: { jarRequestParams: JarAuthorizationRequest }) {
  const { jarRequestParams } = options

  if (jarRequestParams.request && jarRequestParams.request_uri) {
    throw new Oauth2ServerErrorResponseError({
      error: 'invalid_request_object',
      error_description: 'request and request_uri cannot both be present in a JAR request',
    })
  }

  if (!jarRequestParams.request && !jarRequestParams.request_uri) {
    throw new Oauth2ServerErrorResponseError({
      error: 'invalid_request_object',
      error_description: 'request or request_uri must be present',
    })
  }

  return jarRequestParams as JarAuthorizationRequest &
    ({ request_uri: string; request?: never } | { request: string; request_uri?: never })
}

export function isJarAuthorizationRequest(
  request: Openid4vpAuthorizationRequest | JarAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
): request is JarAuthorizationRequest {
  return 'request' in request || 'request_uri' in request
}
