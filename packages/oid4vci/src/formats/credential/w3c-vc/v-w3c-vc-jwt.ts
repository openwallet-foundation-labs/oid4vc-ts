import * as v from 'valibot'
import { vCredentialConfigurationSupportedCommon } from '../../../metadata/credential-issuer/v-credential-configuration-supported-common'
import { vW3cVcCredentialSubject } from './v-w3c-vc-common'

export const vJwtVcJsonFormatIdentifier = v.literal('jwt_vc_json')
export type JwtVcJsonFormatIdentifier = v.InferOutput<typeof vJwtVcJsonFormatIdentifier>

const vJwtVcJsonCredentialDefinition = v.looseObject({
  type: v.array(v.string()),
  credentialSubject: v.optional(vW3cVcCredentialSubject),
})

export const vJwtVcJsonCredentialIssuerMetadata = v.looseObject({
  ...vCredentialConfigurationSupportedCommon.entries,
  format: vJwtVcJsonFormatIdentifier,
  credential_definition: vJwtVcJsonCredentialDefinition,
  order: v.optional(v.array(v.string())),
})

export const vJwtVcJsonCredentialRequestFormat = v.looseObject({
  format: vJwtVcJsonFormatIdentifier,
  credential_definition: vJwtVcJsonCredentialDefinition,
})
