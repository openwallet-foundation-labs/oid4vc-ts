import { zJarAuthorizationRequest } from '@openid4vc/oauth2'
import { z } from 'zod'
import type { Openid4vpAuthorizationRequest } from '../authorization-request/z-authorization-request'
import type { Openid4vpAuthorizationRequestDcApi } from '../authorization-request/z-authorization-request-dc-api'

export const zOpenid4vpJarAuthorizationRequest = zJarAuthorizationRequest.merge(
  z
    .object({
      request_uri_method: z.optional(z.string()),
    })
    .loose()
)
export type Openid4vpJarAuthorizationRequest = z.infer<typeof zOpenid4vpJarAuthorizationRequest>

export function isJarAuthorizationRequest(
  request: Openid4vpAuthorizationRequest | Openid4vpJarAuthorizationRequest | Openid4vpAuthorizationRequestDcApi
): request is Openid4vpJarAuthorizationRequest {
  return 'request' in request || 'request_uri' in request
}
