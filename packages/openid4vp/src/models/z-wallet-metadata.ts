import { z } from 'zod'
import { zClientIdPrefix, zUniformClientIdPrefix } from '../client-identifier-prefix/z-client-id-prefix'
import { zLegacyVpFormats, zVpFormatsSupported } from './z-vp-formats-supported'

export const zWalletMetadata = z.object({
  presentation_definition_uri_supported: z.optional(z.boolean()),

  // Up until draft 26 the legacy format was used
  vp_formats_supported: z.optional(zVpFormatsSupported.or(zLegacyVpFormats)),

  client_id_schemes_supported: z.optional(
    // client_id_schemes_supported was from before decentralized_identifier and openid_federation were defined
    z.array(zClientIdPrefix.exclude(['decentralized_identifier', 'openid_federation']))
  ),

  client_id_prefixes_supported: z.optional(z.array(zUniformClientIdPrefix)),

  request_object_signing_alg_values_supported: z.optional(z.array(z.string())),
  authorization_encryption_alg_values_supported: z.optional(z.array(z.string())),
  authorization_encryption_enc_values_supported: z.optional(z.array(z.string())),
})

export type WalletMetadata = z.infer<typeof zWalletMetadata>
