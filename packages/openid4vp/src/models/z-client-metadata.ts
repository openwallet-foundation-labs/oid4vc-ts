import { zJwkSet } from '@openid4vc/oauth2'
import { z } from 'zod'
import { zJarmClientMetadata } from '../jarm/metadata/z-jarm-dcr-metadata'
import { zVpFormats } from './z-vp-formats'

// Authoritative data the Wallet is able to obtain about the Client from other sources,
// for example those from an OpenID Federation Entity Statement, take precedence over the values passed in client_metadata.
export const zClientMetadata = z
  .object({
    jwks: z.optional(zJwkSet),
    vp_formats: z.optional(zVpFormats),
    ...zJarmClientMetadata.shape,
  })
  .passthrough()
export type ClientMetadata = z.infer<typeof zClientMetadata>
