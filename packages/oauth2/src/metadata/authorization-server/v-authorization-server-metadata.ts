import { vHttpsUrl } from '@openid4vc/utils'
import z from 'zod'
import { vAlgValueNotNone } from '../../common/v-common'

export const vAuthorizationServerMetadata = z
  .object({
    issuer: vHttpsUrl,
    token_endpoint: vHttpsUrl,
    token_endpoint_auth_methods_supported: z.optional(z.array(z.string())),
    authorization_endpoint: z.optional(vHttpsUrl),
    jwks_uri: z.optional(vHttpsUrl),

    // RFC7636
    code_challenge_methods_supported: z.optional(z.array(z.string())),

    // RFC9449
    dpop_signing_alg_values_supported: z.optional(z.array(z.string())),

    // RFC9126
    require_pushed_authorization_requests: z.optional(z.boolean()),
    pushed_authorization_request_endpoint: z.optional(vHttpsUrl),

    // RFC9068
    introspection_endpoint: z.optional(vHttpsUrl),
    introspection_endpoint_auth_methods_supported: z.optional(
      z.array(z.union([z.literal('client_secret_jwt'), z.literal('private_key_jwt'), z.string()]))
    ),
    introspection_endpoint_auth_signing_alg_values_supported: z.optional(z.array(vAlgValueNotNone)),

    // FiPA (no RFC yet)
    authorization_challenge_endpoint: z.optional(vHttpsUrl),

    // From OID4VCI specification
    pre_authorized_grant_anonymous_access_supported: z.optional(z.boolean()),
  })
  .passthrough()
  .refine(
    ({
      introspection_endpoint_auth_methods_supported: methodsSupported,
      introspection_endpoint_auth_signing_alg_values_supported: algValuesSupported,
    }) => {
      if (!methodsSupported) return true
      if (!methodsSupported.includes('private_key_jwt') && !methodsSupported.includes('client_secret_jwt')) return true

      return algValuesSupported !== undefined && algValuesSupported.length > 0
    },
    `Metadata value 'introspection_endpoint_auth_signing_alg_values_supported' must be defined if metadata 'introspection_endpoint_auth_methods_supported' value contains values 'private_key_jwt' or 'client_secret_jwt'`
  )

export type AuthorizationServerMetadata = z.infer<typeof vAuthorizationServerMetadata>
