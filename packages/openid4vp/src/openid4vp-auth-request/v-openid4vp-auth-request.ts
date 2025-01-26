import * as v from 'valibot'
import { vClientMetadata } from '../models/v-client-metadata'

export const vOpenid4vpAuthRequest = v.looseObject({
  response_type: v.literal('vp_token'),
  client_id: v.string(),
  redirect_uri: v.optional(v.string()),
  response_uri: v.optional(v.string()),
  request_uri: v.optional(v.string()),
  request_uri_method: v.optional(v.picklist(['post', 'get'])),
  response_mode: v.optional(v.picklist(['direct_post', 'direct_post.jwt', 'query', 'fragment']), 'fragment'),
  nonce: v.string(),
  wallet_nonce: v.optional(v.string()),
  scope: v.optional(v.string()),
  presentation_definition: v.optional(v.looseObject({})),
  presentation_definition_uri: v.optional(v.string()),
  dcql_query: v.optional(v.looseObject({})),
  client_metadata: v.optional(vClientMetadata),
  state: v.optional(v.string()),
  transaction_data: v.optional(v.array(v.string())),
  trust_chain: v.optional(v.unknown()),
})

export type Openid4vpAuthRequest = v.InferOutput<typeof vOpenid4vpAuthRequest>
