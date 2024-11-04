import * as v from 'valibot'
import { vW3cVcCredentialSubject } from './v-w3c-vc-common'

export const vJwtVcJsonFormatIdentifier = v.literal('jwt_vc_json')
export type JwtVcJsonFormatIdentifier = v.InferOutput<typeof vJwtVcJsonFormatIdentifier>

const vJwtVcJsonCredentialDefinition = v.object({
  type: v.array(v.string()),
  credentialSubject: v.optional(vW3cVcCredentialSubject),
})

export const vJwtVcJsonCredentialIssuerMetadata = v.object({
  format: vJwtVcJsonFormatIdentifier,
  credential_definition: vJwtVcJsonCredentialDefinition,
  order: v.optional(v.array(v.string())),
})

export const vJwtVcJsonCredentialIssuerMetadataDraft11 = v.looseObject({
  format: vJwtVcJsonFormatIdentifier,
  order: v.optional(v.array(v.string())),
  // Credential definition was spread on top level instead of a separatey property in v11
  // As well as using types instead of type
  types: v.array(v.string()),
  credentialSubject: v.optional(vW3cVcCredentialSubject),
})

export const vJwtVcJsonCredentialIssuerMetadataDraft11To14 = v.pipe(
  vJwtVcJsonCredentialIssuerMetadataDraft11,
  v.transform(({ types, credentialSubject, ...rest }) => ({
    ...rest,
    credential_definition: {
      type: types,
      // Prevent weird typing issue with optional vs undefined
      ...(credentialSubject ? { credentialSubject } : {}),
    },
  }))
)

export const vJwtVcJsonCredentialIssuerMetadataDraft14To11 = v.pipe(
  v.looseObject({ ...vJwtVcJsonCredentialIssuerMetadata.entries }),
  v.transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    types: type,
    ...credentialDefinition,
  })),
  vJwtVcJsonCredentialIssuerMetadataDraft11
)

export const vJwtVcJsonCredentialRequestFormat = v.object({
  format: vJwtVcJsonFormatIdentifier,
  credential_definition: vJwtVcJsonCredentialDefinition,
})

export const vJwtVcJsonCredentialRequestDraft11 = v.looseObject({
  format: vJwtVcJsonFormatIdentifier,
  // Credential definition was spread on top level instead of a separatey property in v11
  // As well as using types instead of type
  types: v.array(v.string()),
  credentialSubject: v.optional(vW3cVcCredentialSubject),
})

export const vJwtVcJsonCredentialRequestDraft11To14 = v.pipe(
  vJwtVcJsonCredentialRequestDraft11,
  v.transform(({ types, credentialSubject, ...rest }) => ({
    ...rest,
    credential_definition: {
      type: types,
      // Prevent weird typing issue with optional vs undefined
      ...(credentialSubject ? { credentialSubject } : {}),
    },
  }))
)

export const vJwtVcJsonCredentialRequestDraft14To11 = v.pipe(
  v.looseObject({ ...vJwtVcJsonCredentialRequestFormat.entries }),
  v.transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    types: type,
    ...credentialDefinition,
  })),
  vJwtVcJsonCredentialRequestDraft11
)
