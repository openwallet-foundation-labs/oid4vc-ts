import { vHttpsUrl } from '@animo-id/oauth2-utils'
import * as v from 'valibot'
import { vAlgValueNotNone } from '../../common/v-common'

export const vAuthorizationServerMetadata = v.pipe(
  v.looseObject({
    issuer: vHttpsUrl,

    token_endpoint: vHttpsUrl,
    token_endpoint_auth_methods_supported: v.optional(v.array(v.string())),

    authorization_endpoint: v.optional(vHttpsUrl),

    jwks_uri: v.optional(vHttpsUrl),

    // RFC7636
    code_challenge_methods_supported: v.optional(v.array(v.string())),

    // RFC9449
    dpop_signing_alg_values_supported: v.optional(v.array(v.string())),

    // RFC9126
    require_pushed_authorization_requests: v.optional(v.boolean()),
    pushed_authorization_request_endpoint: v.optional(vHttpsUrl),

    // RFC9068
    introspection_endpoint: v.optional(vHttpsUrl),
    introspection_endpoint_auth_methods_supported: v.optional(
      v.array(v.union([v.literal('client_secret_jwt'), v.literal('private_key_jwt'), v.string()]))
    ),
    introspection_endpoint_auth_signing_alg_values_supported: v.optional(v.array(vAlgValueNotNone)),

    // FiPA (no RFC yet)
    authorization_challenge_endpoint: v.optional(vHttpsUrl),

    // From OID4VCI specification
    'pre-authorized_grant_anonymous_access_supported': v.optional(v.boolean()),
  }),
  v.check(
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
)

export type AuthorizationServerMetadata = v.InferOutput<typeof vAuthorizationServerMetadata>
