import z from 'zod'

const vCredentialSubjectLeafType = z
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

const vClaimValueSchema = z.union([z.array(z.any()), z.record(z.string(), z.any()), vCredentialSubjectLeafType])

export const vW3cVcCredentialSubject = z.record(z.string(), vClaimValueSchema)

export const vW3cVcJsonLdCredentialDefinition = z
  .object({
    '@context': z.array(z.string()),
    type: z.array(z.string()),
    credentialSubject: vW3cVcCredentialSubject.optional(),
  })
  .passthrough()
