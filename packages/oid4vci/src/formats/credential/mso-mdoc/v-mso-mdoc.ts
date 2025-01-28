import z from 'zod'
import { vCredentialConfigurationSupportedClaims } from '../../../metadata/credential-issuer/v-credential-configuration-supported-common'

export const vMsoMdocFormatIdentifier = z.literal('mso_mdoc')
export type MsoMdocFormatIdentifier = z.infer<typeof vMsoMdocFormatIdentifier>

export const vMsoMdocCredentialIssuerMetadata = z.object({
  format: vMsoMdocFormatIdentifier,
  doctype: z.string(),
  claims: z.optional(vCredentialConfigurationSupportedClaims),
  order: z.optional(z.array(z.string())),
})

export const vMsoMdocCredentialRequestFormat = z.object({
  format: vMsoMdocFormatIdentifier,
  doctype: z.string(),
  claims: z.optional(vCredentialConfigurationSupportedClaims),
})
