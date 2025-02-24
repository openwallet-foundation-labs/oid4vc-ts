import z from 'zod'
import { zCredentialConfigurationSupportedClaims } from '../../../metadata/credential-issuer/z-credential-configuration-supported-common'

export const zMsoMdocFormatIdentifier = z.literal('mso_mdoc')
export type MsoMdocFormatIdentifier = z.infer<typeof zMsoMdocFormatIdentifier>

export const zMsoMdocCredentialIssuerMetadata = z.object({
  format: zMsoMdocFormatIdentifier,
  doctype: z.string(),
  claims: z.optional(zCredentialConfigurationSupportedClaims),
  order: z.optional(z.array(z.string())),
})

export const zMsoMdocCredentialRequestFormat = z.object({
  format: zMsoMdocFormatIdentifier,
  doctype: z.string(),
  claims: z.optional(zCredentialConfigurationSupportedClaims),
})
