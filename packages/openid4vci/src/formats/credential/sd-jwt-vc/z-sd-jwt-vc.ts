import z from 'zod'
import { zCredentialConfigurationSupportedClaimsDraft14 } from '../../../metadata/credential-issuer/z-claims-description'
import {
  zCredentialConfigurationSupportedCommon,
  zCredentialConfigurationSupportedCommonCredentialMetadata,
  zCredentialConfigurationSupportedCommonDraft15,
} from '../../../metadata/credential-issuer/z-credential-configuration-supported-common'

export const zSdJwtVcFormatIdentifier = z.literal('vc+sd-jwt')
export type SdJwtVcFormatIdentifier = z.infer<typeof zSdJwtVcFormatIdentifier>

// This format no longer exists in Draft 16, but we need to keep it for compatibility
// with the new credential_metadata structure. Otherwise, we would be outputting very
// inconsistent metadata.
export const zSdJwtVcCredentialIssuerMetadataDraft16 = zCredentialConfigurationSupportedCommon.extend({
  vct: z.string(),
  format: zSdJwtVcFormatIdentifier,
  order: z.optional(z.array(z.string())),
  credential_metadata: zCredentialConfigurationSupportedCommonCredentialMetadata
    .extend({
      claims: z.array(zCredentialConfigurationSupportedClaimsDraft14).optional(),
    })
    .optional(),
  credential_definition: z.optional(z.never()),
})

export const zSdJwtVcCredentialIssuerMetadataDraft14 = zCredentialConfigurationSupportedCommonDraft15.extend({
  vct: z.string(),
  format: zSdJwtVcFormatIdentifier,
  claims: z.optional(zCredentialConfigurationSupportedClaimsDraft14),
  order: z.optional(z.array(z.string())),
  credential_definition: z.optional(z.never()),
})

export const zSdJwtVcCredentialRequestFormatDraft14 = z.object({
  format: zSdJwtVcFormatIdentifier,
  vct: z.string(),
  claims: z.optional(zCredentialConfigurationSupportedClaimsDraft14),
  credential_definition: z.optional(z.never()),
})
