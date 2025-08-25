import z from 'zod'

const zCredentialSubjectLeafTypeDraft14 = z
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
          .passthrough()
      )
      .optional(),
  })
  .passthrough()

const zClaimValueSchemaDraft14 = z.union([
  z.array(z.any()),
  z.record(z.string(), z.any()),
  zCredentialSubjectLeafTypeDraft14,
])

export const zW3cVcCredentialSubjectDraft14 = z.record(z.string(), zClaimValueSchemaDraft14)

export const zW3cVcJsonLdCredentialDefinition = z
  .object({
    '@context': z.array(z.string()),
    type: z.array(z.string()).nonempty(),
  })
  .passthrough()

export const zW3cVcJsonLdCredentialDefinitionDraft14 = zW3cVcJsonLdCredentialDefinition.extend({
  credentialSubject: zW3cVcCredentialSubjectDraft14.optional(),
})
