import z from 'zod'
import { zCredentialConfigurationSupportedClaims } from '../../../metadata/credential-issuer/z-credential-configuration-supported-common'

export const zSdJwtVcFormatIdentifier = z.literal('vc+sd-jwt')
export type SdJwtVcFormatIdentifier = z.infer<typeof zSdJwtVcFormatIdentifier>

export const zSdJwtVcCredentialIssuerMetadata = z.object({
  vct: z.string(),
  format: zSdJwtVcFormatIdentifier,
  claims: z.optional(zCredentialConfigurationSupportedClaims),
  order: z.optional(z.array(z.string())),
})

export const zSdJwtVcCredentialRequestFormat = z.object({
  format: zSdJwtVcFormatIdentifier,
  vct: z.string(),
  claims: z.optional(zCredentialConfigurationSupportedClaims),
})
