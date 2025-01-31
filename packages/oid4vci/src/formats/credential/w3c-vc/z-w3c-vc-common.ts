import z from 'zod'

const zCredentialSubjectLeafType = z
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

const zClaimValueSchema = z.union([z.array(z.any()), z.record(z.string(), z.any()), zCredentialSubjectLeafType])

export const zW3cVcCredentialSubject = z.record(z.string(), zClaimValueSchema)

export const zW3cVcJsonLdCredentialDefinition = z
  .object({
    '@context': z.array(z.string()),
    type: z.array(z.string()),
    credentialSubject: zW3cVcCredentialSubject.optional(),
  })
  .passthrough()
