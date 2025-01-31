import z from 'zod'
import { vCredentialConfigurationSupportedClaims } from '../../../metadata/credential-issuer/v-credential-configuration-supported-common'

export const vSdJwtVcFormatIdentifier = z.literal('vc+sd-jwt')
export type SdJwtVcFormatIdentifier = z.infer<typeof vSdJwtVcFormatIdentifier>

export const vSdJwtVcCredentialIssuerMetadata = z.object({
  vct: z.string(),
  format: vSdJwtVcFormatIdentifier,
  claims: z.optional(vCredentialConfigurationSupportedClaims),
  order: z.optional(z.array(z.string())),
})

export const vSdJwtVcCredentialRequestFormat = z.object({
  format: vSdJwtVcFormatIdentifier,
  vct: z.string(),
  claims: z.optional(vCredentialConfigurationSupportedClaims),
})
