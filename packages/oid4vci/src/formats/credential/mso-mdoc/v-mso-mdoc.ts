import * as v from 'valibot'
import { vCredentialConfigurationSupportedClaims } from '../../../metadata/credential-issuer/v-credential-configuration-supported-common'

export const vMsoMdocFormatIdentifier = v.literal('mso_mdoc')
export type MsoMdocFormatIdentifier = v.InferOutput<typeof vMsoMdocFormatIdentifier>

export const vMsoMdocCredentialIssuerMetadata = v.object({
  format: vMsoMdocFormatIdentifier,
  doctype: v.string(),
  claims: v.optional(vCredentialConfigurationSupportedClaims),
  order: v.optional(v.array(v.pipe(v.string(), v.includes('~')))),
})

export const vMsoMdocCredentialRequestFormat = v.object({
  format: vMsoMdocFormatIdentifier,
  doctype: v.string(),
  claims: v.optional(vCredentialConfigurationSupportedClaims),
})
