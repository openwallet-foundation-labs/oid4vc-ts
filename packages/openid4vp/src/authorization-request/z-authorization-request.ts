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
    client_metadata_uri: zHttpsUrl.optional(),
    state: z.string().optional(),
    transaction_data: z.array(z.string()).optional(),
    trust_chain: z.unknown().optional(),
    client_id_scheme: z
      .enum([
        'pre-registered',
        'redirect_uri',
        'entity_id',
        'did',
        'verifier_attestation',
        'x509_san_dns',
        'x509_san_uri',
      ])
      .optional(),
  })
  .passthrough()

export type Openid4vpAuthorizationRequest = z.infer<typeof zOpenid4vpAuthorizationRequest>
