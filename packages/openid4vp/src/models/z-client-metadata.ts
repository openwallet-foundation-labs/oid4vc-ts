import { zJwkSet } from '@openid4vc/oauth2'
import { zHttpsUrl } from '@openid4vc/utils'
import { z } from 'zod'
import { zJarmClientMetadata } from '../jarm/metadata/z-jarm-client-metadata'
import { zVpFormatsSupported } from './z-vp-formats-supported'

// Authoritative data the Wallet is able to obtain about the Client from other sources,
// for example those from an OpenID Federation Entity Statement, take precedence over the values passed in client_metadata.
export const zClientMetadata = z
  .object({
    jwks: z.optional(zJwkSet),
    vp_formats: z.optional(zVpFormatsSupported),
    ...zJarmClientMetadata.shape,
    logo_uri: zHttpsUrl.optional(),
    client_name: z.string().optional(),
  })
  .passthrough()
export type ClientMetadata = z.infer<typeof zClientMetadata>
