import { zJwtHeader, zJwtPayload } from '@openid4vc/oauth2'
import { zNumericDate } from '@openid4vc/utils'
import z from 'zod'
import { zCredentialIssuerMetadataDraft14Draft15V1 } from './z-credential-issuer-metadata'

export const zSignedCredentialIssuerMetadataHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: z.literal('openidvci-issuer-metadata+jwt'),
  })
  .loose()

export type SignedCredentialIssuerMetadataHeader = z.infer<typeof zSignedCredentialIssuerMetadataHeader>

export const zSignedCredentialIssuerMetadataPayload = z
  .object({
    ...zJwtPayload.shape,
    iat: zNumericDate,
    sub: z.string(),

    // NOTE: we don't support older drafts below 14 for signed metadata
    ...zCredentialIssuerMetadataDraft14Draft15V1.shape,
  })
  .loose()

export type SignedCredentialIssuerMetadataPayload = z.infer<typeof zSignedCredentialIssuerMetadataPayload>
