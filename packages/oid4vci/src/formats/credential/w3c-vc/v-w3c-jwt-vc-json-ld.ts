import { vW3cVcCredentialSubject, vW3cVcJsonLdCredentialDefinition } from './v-w3c-vc-common'
import z from 'zod'

export const vJwtVcJsonLdFormatIdentifier = z.literal('jwt_vc_json-ld')
export type JwtVcJsonLdFormatIdentifier = z.infer<typeof vJwtVcJsonLdFormatIdentifier>

export const vJwtVcJsonLdCredentialIssuerMetadata = z.object({
  format: vJwtVcJsonLdFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
  order: z.optional(z.array(z.string())),
})

export const vJwtVcJsonLdCredentialIssuerMetadataDraft11 = z
  .object({
    order: z.array(z.string()).optional(),
    format: vJwtVcJsonLdFormatIdentifier,
    // Credential definition was spread on top level instead of a separatey property in v11
    // As well as using types instead of type
    '@context': z.array(z.string()),
    types: z.array(z.string()),
    credentialSubject: vW3cVcCredentialSubject.optional(),
  })
  .passthrough()

export const vJwtVcJsonLdCredentialIssuerMetadataDraft11To14 = vJwtVcJsonLdCredentialIssuerMetadataDraft11.transform(
  ({ '@context': context, types, credentialSubject, ...rest }) => ({
    ...rest,
    credential_definition: {
      '@context': context,
      type: types,
      // Prevent weird typing issue with optional vs undefined
      ...(credentialSubject ? { credentialSubject } : {}),
    },
  })
)

export const vJwtVcJsonLdCredentialIssuerMetadataDraft14To11 = vJwtVcJsonLdCredentialIssuerMetadata
  .passthrough()
  .transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    ...credentialDefinition,
    types: type,
  }))
  .and(vJwtVcJsonLdCredentialIssuerMetadataDraft11)

export const vJwtVcJsonLdCredentialRequestFormat = z.object({
  format: vJwtVcJsonLdFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
})

export const vJwtVcJsonLdCredentialRequestDraft11 = z
  .object({
    format: vJwtVcJsonLdFormatIdentifier,
    credential_definition: z
      .object({
        '@context': z.array(z.string()),
        // credential_definition was using types instead of type in v11
        types: z.array(z.string()),
        credentialSubject: z.optional(vW3cVcCredentialSubject),
      })
      .passthrough(),
  })
  .passthrough()

export const vJwtVcJsonLdCredentialRequestDraft11To14 = vJwtVcJsonLdCredentialRequestDraft11.transform(
  ({ credential_definition: { types, ...restCredentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...restCredentialDefinition,
      type: types,
    },
  })
)

export const vJwtVcJsonLdCredentialRequestDraft14To11 = vJwtVcJsonLdCredentialRequestFormat
  .passthrough()
  .transform(({ credential_definition: { type, ...restCredentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...restCredentialDefinition,
      types: type,
    },
  }))
  .and(vJwtVcJsonLdCredentialRequestDraft11)
