import * as v from 'valibot'
import { vCredentialConfigurationSupportedCommon } from '../../../metadata/credential-issuer/v-credential-configuration-supported-common'
import { vW3cVcCredentialSubject } from './v-w3c-vc-common'

const vW3cVcJsonLdCredentialDefinition = v.looseObject({
  '@context': v.array(v.string()),
  type: v.array(v.string()),
  credentialSubject: v.optional(vW3cVcCredentialSubject),
})

export const vLdpVcFormatIdentifier = v.literal('ldp_vc')
export type LdpVcFormatIdentifier = v.InferOutput<typeof vLdpVcFormatIdentifier>

export const vLdpVcCredentialIssuerMetadata = v.looseObject({
  ...vCredentialConfigurationSupportedCommon.entries,
  format: vLdpVcFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
  order: v.optional(v.array(v.string())),
})

export const vLdpVcCredentialRequestFormat = v.looseObject({
  format: vLdpVcFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
})

export const vJwtVcJsonLdFormatIdentifier = v.literal('jwt_vc_json-ld')
export type JwtVcJsonLdFormatIdentifier = v.InferOutput<typeof vJwtVcJsonLdFormatIdentifier>

export const vJwtVcJsonLdCredentialIssuerMetadata = v.looseObject({
  ...vCredentialConfigurationSupportedCommon.entries,
  format: vJwtVcJsonLdFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
  order: v.optional(v.array(v.string())),
})

export const vJwtVcJsonLdCredentialRequestFormat = v.looseObject({
  format: vJwtVcJsonLdFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
})
