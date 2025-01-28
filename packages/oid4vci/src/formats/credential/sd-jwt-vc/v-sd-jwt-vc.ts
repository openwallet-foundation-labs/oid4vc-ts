import { vCredentialConfigurationSupportedClaims } from '../../../metadata/credential-issuer/v-credential-configuration-supported-common'
import z from 'zod'

// export const vSdJwtVcFormatIdentifier = v.literal('vc+sd-jwt')
// export type SdJwtVcFormatIdentifier = v.InferOutput<typeof vSdJwtVcFormatIdentifier>

// export const vSdJwtVcCredentialIssuerMetadata = v.object({
//   vct: v.string(),
//   format: vSdJwtVcFormatIdentifier,
//   claims: v.optional(vCredentialConfigurationSupportedClaims),
//   order: v.optional(v.array(v.string())),
// })

// export const vSdJwtVcCredentialRequestFormat = v.object({
//   format: vSdJwtVcFormatIdentifier,
//   vct: v.string(),
//   claims: v.optional(vCredentialConfigurationSupportedClaims),
// })

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
