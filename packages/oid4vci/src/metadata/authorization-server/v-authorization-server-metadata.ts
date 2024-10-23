import * as v from 'valibot'
import { vHttpsUrl } from '../../common/validation/v-common'

export const vAuthorizationServerIdentifier = vHttpsUrl

export const vAuthorizationServerMetadata = v.looseObject({
  issuer: vAuthorizationServerIdentifier,
  token_endpoint: vHttpsUrl,
  authorization_endpoint: v.optional(vHttpsUrl),

  code_challenge_methods_supported: v.optional(v.array(v.string())),

  // RFC9449
  dpop_signing_alg_values_supported: v.optional(v.array(v.string())),

  // RFC9126
  require_pushed_authorization_requests: v.optional(v.boolean()),
  pushed_authorization_request_endpoint: v.optional(vHttpsUrl),

  // From OID4VCI specification
  'pre-authorized_grant_anonymous_access_supported': v.optional(v.boolean()),
})

export type AuthorizationServerMetadata = v.InferOutput<typeof vAuthorizationServerMetadata>
