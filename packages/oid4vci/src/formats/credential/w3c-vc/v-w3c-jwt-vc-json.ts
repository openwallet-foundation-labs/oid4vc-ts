import { vW3cVcCredentialSubject } from './v-w3c-vc-common'
import z from 'zod'

export const vJwtVcJsonFormatIdentifier = z.literal('jwt_vc_json')
export type JwtVcJsonFormatIdentifier = z.infer<typeof vJwtVcJsonFormatIdentifier>

const vJwtVcJsonCredentialDefinition = z
  .object({
    type: z.array(z.string()),
    credentialSubject: vW3cVcCredentialSubject.optional(),
  })
  .passthrough()

export const vJwtVcJsonCredentialIssuerMetadata = z.object({
  format: vJwtVcJsonFormatIdentifier,
  credential_definition: vJwtVcJsonCredentialDefinition,
  order: z.array(z.string()).optional(),
})

export const vJwtVcJsonCredentialIssuerMetadataDraft11 = z
  .object({
    format: vJwtVcJsonFormatIdentifier,
    order: z.array(z.string()).optional(),
    // Credential definition was spread on top level instead of a separatey property in v11
    // As well as using types instead of type
    types: z.array(z.string()),
    credentialSubject: vW3cVcCredentialSubject.optional(),
  })
  .passthrough()

export const vJwtVcJsonCredentialIssuerMetadataDraft11To14 = vJwtVcJsonCredentialIssuerMetadataDraft11.transform(
  ({ types, credentialSubject, ...rest }) => ({
    ...rest,
    credential_definition: {
      type: types,
      // Prevent weird typing issue with optional vs undefined
      ...(credentialSubject ? { credentialSubject } : {}),
    },
  })
)

export const vJwtVcJsonCredentialIssuerMetadataDraft14To11 = vJwtVcJsonCredentialIssuerMetadata
  .passthrough()
  .transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    types: type,
    ...credentialDefinition,
  }))
  .and(vJwtVcJsonCredentialIssuerMetadataDraft11)

export const vJwtVcJsonCredentialRequestFormat = z.object({
  format: vJwtVcJsonFormatIdentifier,
  credential_definition: vJwtVcJsonCredentialDefinition,
})

export const vJwtVcJsonCredentialRequestDraft11 = z
  .object({
    format: vJwtVcJsonFormatIdentifier,
    // Credential definition was spread on top level instead of a separatey property in v11
    // As well as using types instead of type
    types: z.array(z.string()),
    credentialSubject: z.optional(vW3cVcCredentialSubject),
  })
  .passthrough()

export const vJwtVcJsonCredentialRequestDraft11To14 = vJwtVcJsonCredentialRequestDraft11.transform(
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

export const vJwtVcJsonCredentialRequestDraft14To11 = vJwtVcJsonCredentialRequestFormat
  .passthrough()
  .transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    types: type,
    ...credentialDefinition,
  }))
  .and(vJwtVcJsonCredentialRequestDraft11)
