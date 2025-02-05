import { z } from 'zod'
import { zClientIdScheme } from '../client-identifier-scheme/z-client-id-scheme'
import { zVpFormatsSupported } from './z-vp-formats-supported'

export const zWalletMetadata = z.object({
  presentation_definition_uri_supported: z.optional(z.boolean()),
  vp_formats_supported: zVpFormatsSupported,
  client_id_schemes_supported: z.optional(z.array(zClientIdScheme)),
  request_object_signing_alg_values_supported: z.optional(z.array(z.string())),
  authorization_encryption_alg_values_supported: z.optional(z.array(z.string())),
  authorization_encryption_enc_values_supported: z.optional(z.array(z.string())),
})

export type WalletMetadata = z.infer<typeof zWalletMetadata>
