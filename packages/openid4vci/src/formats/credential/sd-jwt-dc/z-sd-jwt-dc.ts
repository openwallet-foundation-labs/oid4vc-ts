import z from 'zod'
import { zIssuerMetadataClaimsDescription } from '../../../metadata/credential-issuer/z-claims-description'

export const zSdJwtDcFormatIdentifier = z.literal('dc+sd-jwt')
export type SdJwtDcFormatIdentifier = z.infer<typeof zSdJwtDcFormatIdentifier>

export const zSdJwtDcCredentialIssuerMetadata = z.object({
  vct: z.string(),
  format: zSdJwtDcFormatIdentifier,
  claims: z.array(zIssuerMetadataClaimsDescription).optional(),
})
