import { z } from 'zod'
import { type Openid4vpAuthorizationResponse, zOpenid4vpAuthorizationResponse } from './z-authorization-response'

export const zOpenid4vpAuthorizationResponseDcApi = z
  .object({
    protocol: z.literal('openid4vp'),
    data: zOpenid4vpAuthorizationResponse,
  })
  .passthrough()
export type Openid4vpAuthorizationResponseDcApi = z.infer<typeof zOpenid4vpAuthorizationResponseDcApi>

export function isOpenid4vpAuthorizationResponseDcApi(
  response: Openid4vpAuthorizationResponse | Openid4vpAuthorizationResponseDcApi
): response is Openid4vpAuthorizationResponseDcApi {
  return 'protocol' in response && 'data' in response
}
