import z from 'zod'

// Used up to draft 14
export const zCredentialConfigurationSupportedClaimsDescriptionDraft14 = z
  .object({
    mandatory: z.boolean().optional(),
    value_type: z.string().optional(),
    display: z
      .array(
        z
          .object({
            name: z.string().optional(),
            locale: z.string().optional(),
          })
          .loose()
      )
      .optional(),
  })
  .loose()

export type CredentialConfigurationSupportedClaimsDraft14 = {
  [key: string]:
    | z.infer<typeof zCredentialConfigurationSupportedClaimsDescriptionDraft14>
    | CredentialConfigurationSupportedClaimsDraft14
}

export const zCredentialConfigurationSupportedClaimsDraft14: z.ZodType<CredentialConfigurationSupportedClaimsDraft14> =
  z.record(
    z.string(),
    z.union([
      zCredentialConfigurationSupportedClaimsDescriptionDraft14,
      z.lazy(() => zCredentialConfigurationSupportedClaimsDraft14),
    ])
  )

const zClaimDescriptionPathValue = z.union([z.string(), z.number().int().nonnegative(), z.null()])
const zClaimsDescriptionPath = z.tuple([zClaimDescriptionPathValue], zClaimDescriptionPathValue)
export type ClaimsDescriptionPath = z.infer<typeof zClaimsDescriptionPath>

const zMsoMdocClaimsDescriptionPath = z.tuple([z.string(), z.string()], z.string(), {
  message:
    'mso_mdoc claims description path MUST be an array with at least two string elements, pointing to the namespace and element identifier within an mdoc credential',
})
export type MsoMdocClaimsDescriptionPath = z.infer<typeof zMsoMdocClaimsDescriptionPath>

export const zIssuerMetadataClaimsDescription = z
  .object({
    path: zClaimsDescriptionPath,
    mandatory: z.boolean().optional(),
    display: z
      .array(
        z
          .object({
            name: z.string().optional(),
            locale: z.string().optional(),
          })
          .loose()
      )
      .optional(),
  })
  .loose()
export type IssuerMetadataClaimsDescription = z.infer<typeof zIssuerMetadataClaimsDescription>

export const zMsoMdocIssuerMetadataClaimsDescription = zIssuerMetadataClaimsDescription.extend({
  path: zMsoMdocClaimsDescriptionPath,
})
export type MsoMdocIssuerMetadataClaimsDescription = z.infer<typeof zMsoMdocIssuerMetadataClaimsDescription>
