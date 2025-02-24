import { z } from 'zod'
import type { JarAuthRequest } from '../jar/z-jar-auth-request'
import { type Openid4vpAuthorizationRequest, zOpenid4vpAuthorizationRequest } from './z-authorization-request'

export const zOpenid4vpAuthorizationRequestDcApi = zOpenid4vpAuthorizationRequest
  .pick({
    client_id: true,
    response_type: true,
    response_mode: true,
    nonce: true,
    presentation_definition: true,
    client_metadata: true,
    transaction_data: true,
    dcql_query: true,
  })
  .extend({
    client_id: z.optional(z.string()),
    expected_origins: z.array(z.string()).optional(),
    response_mode: z.enum(['dc_api', 'dc_api.jwt']),
  })
  .strip()

export type Openid4vpAuthorizationRequestDcApi = z.infer<typeof zOpenid4vpAuthorizationRequestDcApi>

export function isOpenid4vpAuthorizationRequestDcApi(
  request: Openid4vpAuthorizationRequest | JarAuthRequest | Openid4vpAuthorizationRequestDcApi
): request is Openid4vpAuthorizationRequestDcApi {
  return request.response_mode === 'dc_api' || request.response_mode === 'dc_api.jwt'
}
