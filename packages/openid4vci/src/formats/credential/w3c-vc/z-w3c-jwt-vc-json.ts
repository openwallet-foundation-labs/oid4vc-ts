import z from 'zod'
import { zW3cVcCredentialSubject } from './z-w3c-vc-common'

export const zJwtVcJsonFormatIdentifier = z.literal('jwt_vc_json')
export type JwtVcJsonFormatIdentifier = z.infer<typeof zJwtVcJsonFormatIdentifier>

const zJwtVcJsonCredentialDefinition = z
  .object({
    type: z.array(z.string()),
    credentialSubject: zW3cVcCredentialSubject.optional(),
  })
  .passthrough()

export const zJwtVcJsonCredentialIssuerMetadata = z.object({
  format: zJwtVcJsonFormatIdentifier,
  credential_definition: zJwtVcJsonCredentialDefinition,
  order: z.array(z.string()).optional(),
})

export const zJwtVcJsonCredentialIssuerMetadataDraft11 = z
  .object({
    format: zJwtVcJsonFormatIdentifier,
    order: z.array(z.string()).optional(),
    // Credential definition was spread on top level instead of a separatey property in v11
    // As well as using types instead of type
    types: z.array(z.string()),
    credentialSubject: zW3cVcCredentialSubject.optional(),
  })
  .passthrough()

export const zJwtVcJsonCredentialIssuerMetadataDraft11To14 = zJwtVcJsonCredentialIssuerMetadataDraft11.transform(
  ({ types, credentialSubject, ...rest }) => ({
    ...rest,
    credential_definition: {
      type: types,
      // Prevent weird typing issue with optional vs undefined
      ...(credentialSubject ? { credentialSubject } : {}),
    },
  })
)

export const zJwtVcJsonCredentialIssuerMetadataDraft14To11 = zJwtVcJsonCredentialIssuerMetadata
  .passthrough()
  .transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    types: type,
    ...credentialDefinition,
  }))
  .and(zJwtVcJsonCredentialIssuerMetadataDraft11)

export const zJwtVcJsonCredentialRequestFormat = z.object({
  format: zJwtVcJsonFormatIdentifier,
  credential_definition: zJwtVcJsonCredentialDefinition,
})

export const zJwtVcJsonCredentialRequestDraft11 = z
  .object({
    format: zJwtVcJsonFormatIdentifier,
    // Credential definition was spread on top level instead of a separatey property in v11
    // As well as using types instead of type
    types: z.array(z.string()),
    credentialSubject: z.optional(zW3cVcCredentialSubject),
  })
  .passthrough()

export const zJwtVcJsonCredentialRequestDraft11To14 = zJwtVcJsonCredentialRequestDraft11.transform(
  ({ types, credentialSubject, ...rest }) => {
    return {
      ...rest,
      credential_definition: {
        type: types,
        // Prevent weird typing issue with optional vs undefined
        ...(credentialSubject ? { credentialSubject } : {}),
      },
    }
  }
)

export const zJwtVcJsonCredentialRequestDraft14To11 = zJwtVcJsonCredentialRequestFormat
  .passthrough()
  .transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    types: type,
    ...credentialDefinition,
  }))
  .and(zJwtVcJsonCredentialRequestDraft11)
