import { zJwkSet } from '@openid4vc/oauth2'
import { zDataUrl, zHttpsUrl } from '@openid4vc/utils'
import { z } from 'zod'
import { zJarmClientMetadata } from '../jarm/metadata/z-jarm-client-metadata'
import { zLegacyVpFormats, zVpFormatsSupported } from './z-vp-formats-supported'

// Authoritative data the Wallet is able to obtain about the Client from other sources,
// for example those from an OpenID Federation Entity Statement, take precedence over the values passed in client_metadata.
export const zClientMetadata = z
  .object({
    // Up until draft 22
    jwks_uri: z.url().optional(),
    jwks: z.optional(zJwkSet),

    // Up until draft 26
    vp_formats: z.optional(zLegacyVpFormats),

    // From draft 27
    vp_formats_supported: z.optional(zVpFormatsSupported),

    // From draft 28
    encrypted_response_enc_values_supported: z.optional(z.array(z.string())),

    ...zJarmClientMetadata.shape,

    logo_uri: zHttpsUrl.or(zDataUrl).optional(),
    client_name: z.string().optional(),
  })
  .loose()
export type ClientMetadata = z.infer<typeof zClientMetadata>
