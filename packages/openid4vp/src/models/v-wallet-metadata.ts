import * as v from 'valibot'
import { vClientIdScheme } from '../client-identifier-scheme/v-client-id-scheme'
import { vVpFormatsSupported } from './v-vp-formats-supported'

export const vWalletMetadata = v.looseObject({
  presentation_definition_uri_supported: v.optional(v.boolean(), true),
  vp_formats_supported: vVpFormatsSupported,
  client_id_schemes_supported: v.optional(v.array(vClientIdScheme)),
  request_object_signing_alg_values_supported: v.optional(v.array(v.string())),
  authorization_encryption_alg_values_supported: v.optional(v.array(v.string())),
  authorization_encryption_enc_values_supported: v.optional(v.array(v.string())),
})

export type WalletMetadata = v.InferOutput<typeof vWalletMetadata>
