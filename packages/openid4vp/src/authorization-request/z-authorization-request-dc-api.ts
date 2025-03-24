import { z } from 'zod'
import type { JarAuthorizationRequest } from '../jar/z-jar-authorization-request'
import { type Openid4vpAuthorizationRequest, zOpenid4vpAuthorizationRequest } from './z-authorization-request'

const zOpenid4vpResponseModeDcApi = z.enum(['dc_api', 'dc_api.jwt', 'w3c_dc_api.jwt', 'w3c_dc_api'])
export const zOpenid4vpAuthorizationRequestDcApi = zOpenid4vpAuthorizationRequest
  .pick({
    response_type: true,
    nonce: true,
    presentation_definition: true,
    client_metadata: true,
    transaction_data: true,
    dcql_query: true,
    trust_chain: true,
    state: true,
  })
  .extend({
    client_id: z.optional(z.string()),
    expected_origins: z.array(z.string()).optional(),
    response_mode: zOpenid4vpResponseModeDcApi,

    // Not allowed with dc_api, but added to make working with interfaces easier
    client_id_scheme: z.never().optional(),
    scope: z.never().optional(),

    // TODO: should we disallow any properties specifically, such as redirect_uri and response_uri?
  })

export type Openid4vpAuthorizationRequestDcApi = z.infer<typeof zOpenid4vpAuthorizationRequestDcApi>

export function isOpenid4vpResponseModeDcApi(
  responseMode: unknown
): responseMode is Openid4vpAuthorizationRequestDcApi['response_mode'] {
  return (
    responseMode !== undefined &&
    zOpenid4vpResponseModeDcApi.options.includes(responseMode as Openid4vpAuthorizationRequestDcApi['response_mode'])
  )
}

export function isOpenid4vpAuthorizationRequestDcApi(
  request: Openid4vpAuthorizationRequest | Openid4vpAuthorizationRequestDcApi | JarAuthorizationRequest
): request is Openid4vpAuthorizationRequestDcApi {
  return isOpenid4vpResponseModeDcApi(request.response_mode)
}
