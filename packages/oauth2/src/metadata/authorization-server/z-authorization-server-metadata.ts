import { zHttpsUrl } from '@openid4vc/utils'
import z from 'zod'
import { zAlgValueNotNone } from '../../common/z-common'

const knownClientAuthenticationMethod = z.enum([
  'client_secret_basic',
  'client_secret_post',
  'attest_jwt_client_auth',
  'client_secret_jwt',
  'private_key_jwt',
])

export const zAuthorizationServerMetadata = z
  .object({
    issuer: zHttpsUrl,
    token_endpoint: zHttpsUrl,
    token_endpoint_auth_methods_supported: z.optional(z.array(z.union([knownClientAuthenticationMethod, z.string()]))),
    authorization_endpoint: z.optional(zHttpsUrl),
    jwks_uri: z.optional(zHttpsUrl),

    // RFC7636
    code_challenge_methods_supported: z.optional(z.array(z.string())),

    // RFC9449
    dpop_signing_alg_values_supported: z.optional(z.array(z.string())),

    // RFC9126
    require_pushed_authorization_requests: z.optional(z.boolean()),
    pushed_authorization_request_endpoint: z.optional(zHttpsUrl),

    // RFC9068
    introspection_endpoint: z.optional(zHttpsUrl),
    introspection_endpoint_auth_methods_supported: z.optional(
      z.array(z.union([knownClientAuthenticationMethod, z.string()]))
    ),
    introspection_endpoint_auth_signing_alg_values_supported: z.optional(z.array(zAlgValueNotNone)),

    // FiPA (no RFC yet)
    authorization_challenge_endpoint: z.optional(zHttpsUrl),

    // From OpenID4VCI specification
    pre_authorized_grant_anonymous_access_supported: z.optional(z.boolean()),

    // Attestation Based Client Auth (draft 5)
    client_attestation_pop_nonce_required: z.boolean().optional(),
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

export type AuthorizationServerMetadata = z.infer<typeof zAuthorizationServerMetadata>
