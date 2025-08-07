import z from 'zod'
import { zIssuerMetadataClaimsDescription } from '../../../metadata/credential-issuer/z-claims-description'
import { zCredentialConfigurationSupportedCommonCredentialMetadata } from '../../../metadata/credential-issuer/z-credential-configuration-supported-common'

export const zSdJwtDcFormatIdentifier = z.literal('dc+sd-jwt')
export type SdJwtDcFormatIdentifier = z.infer<typeof zSdJwtDcFormatIdentifier>

export const zSdJwtDcCredentialIssuerMetadata = z.object({
  vct: z.string(),
  format: zSdJwtDcFormatIdentifier,
  credential_metadata: zCredentialConfigurationSupportedCommonCredentialMetadata
    .extend({
      claims: z.array(zIssuerMetadataClaimsDescription).optional(),
    })
    .optional(),
})

export const zSdJwtDcCredentialIssuerMetadataDraft15 = z.object({
  vct: z.string(),
  format: zSdJwtDcFormatIdentifier,
  claims: z.array(zIssuerMetadataClaimsDescription).optional(),
})
