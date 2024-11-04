import * as v from 'valibot'
import { vCredentialConfigurationSupportedClaims } from '../../../metadata/credential-issuer/v-credential-configuration-supported-common'

export const vSdJwtVcFormatIdentifier = v.literal('vc+sd-jwt')
export type SdJwtVcFormatIdentifier = v.InferOutput<typeof vSdJwtVcFormatIdentifier>

export const vSdJwtVcCredentialIssuerMetadata = v.object({
  vct: v.string(),
  format: vSdJwtVcFormatIdentifier,
  claims: v.optional(vCredentialConfigurationSupportedClaims),
  order: v.optional(v.array(v.string())),
})

export const vSdJwtVcCredentialRequestFormat = v.object({
  format: vSdJwtVcFormatIdentifier,
  vct: v.string(),
  claims: v.optional(vCredentialConfigurationSupportedClaims),
})
