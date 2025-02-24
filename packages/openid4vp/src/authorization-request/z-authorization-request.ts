import { zHttpsUrl } from '@openid4vc/utils'
import { z } from 'zod'
import { zClientMetadata } from '../models/z-client-metadata'

export const zOpenid4vpAuthorizationRequest = z
  .object({
    response_type: z.literal('vp_token'),
    client_id: z.string(),
    redirect_uri: zHttpsUrl.optional(),
    response_uri: zHttpsUrl.optional(),
    request_uri: zHttpsUrl.optional(),
    request_uri_method: z.optional(z.string()),
    response_mode: z.enum(['direct_post', 'direct_post.jwt']).optional(),
    nonce: z.string(),
    wallet_nonce: z.string().optional(),
    scope: z.string().optional(),
    presentation_definition: z.record(z.any()).optional(),
    presentation_definition_uri: zHttpsUrl.optional(),
    dcql_query: z.record(z.any()).optional(),
    client_metadata: zClientMetadata.optional(),
    state: z.string().optional(),
    transaction_data: z.array(z.string()).optional(),
    trust_chain: z.unknown().optional(),
  })
  .passthrough()

export type Openid4vpAuthorizationRequest = z.infer<typeof zOpenid4vpAuthorizationRequest>
