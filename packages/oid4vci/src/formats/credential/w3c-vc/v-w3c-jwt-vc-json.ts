import * as v from 'valibot'
import { vW3cVcCredentialSubject } from './v-w3c-vc-common'

export const vJwtVcJsonFormatIdentifier = v.literal('jwt_vc_json')
export type JwtVcJsonFormatIdentifier = v.InferOutput<typeof vJwtVcJsonFormatIdentifier>

const vJwtVcJsonCredentialDefinition = v.looseObject({
  type: v.array(v.string()),
  credentialSubject: v.optional(vW3cVcCredentialSubject),
})

export const vJwtVcJsonCredentialIssuerMetadata = v.looseObject({
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
  })),
  vJwtVcJsonCredentialIssuerMetadata
)

export const vJwtVcJsonCredentialRequestFormat = v.looseObject({
  format: vJwtVcJsonFormatIdentifier,
  credential_definition: vJwtVcJsonCredentialDefinition,
})

export const vJwtVcJsonCredentialRequestDraft11To14 = v.pipe(
  v.looseObject({
    format: vJwtVcJsonFormatIdentifier,
    // Credential definition was spread on top level instead of a separatey property in v11
    // As well as using types instead of type
    types: v.array(v.string()),
    credentialSubject: v.optional(vW3cVcCredentialSubject),
  }),
  v.transform(({ types, credentialSubject, ...rest }) => ({
    ...rest,
    credential_definition: {
      type: types,
      // Prevent weird typing issue with optional vs undefined
      ...(credentialSubject ? { credentialSubject } : {}),
    },
  })),
  vJwtVcJsonCredentialRequestFormat
)
