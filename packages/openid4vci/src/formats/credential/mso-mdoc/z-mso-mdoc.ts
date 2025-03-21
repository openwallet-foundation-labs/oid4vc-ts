import z from 'zod'
import {
  zCredentialConfigurationSupportedClaimsDraft14,
  zMsoMdocIssuerMetadataClaimsDescription,
} from '../../../metadata/credential-issuer/z-claims-description'

export const zMsoMdocFormatIdentifier = z.literal('mso_mdoc')
export type MsoMdocFormatIdentifier = z.infer<typeof zMsoMdocFormatIdentifier>

export const zMsoMdocCredentialIssuerMetadata = z.object({
  format: zMsoMdocFormatIdentifier,
  doctype: z.string(),
  claims: z.array(zMsoMdocIssuerMetadataClaimsDescription).optional(),
})

export const zMsoMdocCredentialIssuerMetadataDraft14 = z.object({
  format: zMsoMdocFormatIdentifier,
  doctype: z.string(),
  claims: zCredentialConfigurationSupportedClaimsDraft14.optional(),
  order: z.optional(z.array(z.string())),
})

export const zMsoMdocCredentialRequestFormatDraft14 = z.object({
  format: zMsoMdocFormatIdentifier,
  doctype: z.string(),
  // Format based request is removed in Draft 15, so only old claims syntax supported.
  claims: z.optional(zCredentialConfigurationSupportedClaimsDraft14),
})
