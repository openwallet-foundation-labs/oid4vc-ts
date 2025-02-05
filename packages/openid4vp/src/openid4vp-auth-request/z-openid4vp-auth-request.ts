import { z } from 'zod'
import { zClientMetadata } from '../models/z-client-metadata'

export const zOpenid4vpAuthRequest = z
  .object({
    response_type: z.literal('vp_token'),
    client_id: z.string(),
    redirect_uri: z.string().optional(),
    response_uri: z.string().optional(),
    request_uri: z.string().optional(),
    request_uri_method: z.enum(['post', 'get']).optional(),
    response_mode: z.enum(['direct_post', 'direct_post.jwt', 'query', 'fragment']).optional().default('fragment'),
    nonce: z.string(),
    wallet_nonce: z.string().optional(),
    scope: z.string().optional(),
    presentation_definition: z.object({}).passthrough().optional(),
    presentation_definition_uri: z.string().optional(),
    dcql_query: z.object({}).passthrough().optional(),
    client_metadata: zClientMetadata.optional(),
    state: z.string().optional(),
    transaction_data: z.array(z.string()).optional(),
    trust_chain: z.unknown().optional(),
  })
  .passthrough()

export type Openid4vpAuthRequest = z.infer<typeof zOpenid4vpAuthRequest>
