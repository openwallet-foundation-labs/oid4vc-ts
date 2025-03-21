import z from 'zod'
import { zCredentialConfigurationSupportedClaimsDraft14 } from '../../../metadata/credential-issuer/z-claims-description'

export const zSdJwtVcFormatIdentifier = z.literal('vc+sd-jwt')
export type SdJwtVcFormatIdentifier = z.infer<typeof zSdJwtVcFormatIdentifier>

export const zSdJwtVcCredentialIssuerMetadataDraft14 = z.object({
  vct: z.string(),
  format: zSdJwtVcFormatIdentifier,
  claims: z.optional(zCredentialConfigurationSupportedClaimsDraft14),
  order: z.optional(z.array(z.string())),
})

export const zSdJwtVcCredentialRequestFormatDraft14 = z.object({
  format: zSdJwtVcFormatIdentifier,
  vct: z.string(),
  claims: z.optional(zCredentialConfigurationSupportedClaimsDraft14),
})
