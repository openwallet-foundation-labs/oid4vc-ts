import * as v from 'valibot'

import { vW3cVcCredentialSubject, vW3cVcJsonLdCredentialDefinition } from './v-w3c-vc-common'

export const vJwtVcJsonLdFormatIdentifier = v.literal('jwt_vc_json-ld')
export type JwtVcJsonLdFormatIdentifier = v.InferOutput<typeof vJwtVcJsonLdFormatIdentifier>

export const vJwtVcJsonLdCredentialIssuerMetadata = v.object({
  format: vJwtVcJsonLdFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
  order: v.optional(v.array(v.string())),
})

export const vJwtVcJsonLdCredentialIssuerMetadataDraft11 = v.looseObject({
  order: v.optional(v.array(v.string())),
  format: vJwtVcJsonLdFormatIdentifier,

  // Credential definition was spread on top level instead of a separatey property in v11
  // As well as using types instead of type
  '@context': v.array(v.string()),
  types: v.array(v.string()),
  credentialSubject: v.optional(vW3cVcCredentialSubject),
})

export const vJwtVcJsonLdCredentialIssuerMetadataDraft11To14 = v.pipe(
  vJwtVcJsonLdCredentialIssuerMetadataDraft11,
  v.transform(({ '@context': context, types, credentialSubject, ...rest }) => ({
    ...rest,
    credential_definition: {
      '@context': context,
      type: types,
      // Prevent weird typing issue with optional vs undefined
      ...(credentialSubject ? { credentialSubject } : {}),
    },
  }))
)

export const vJwtVcJsonLdCredentialIssuerMetadataDraft14To11 = v.pipe(
  v.looseObject({ ...vJwtVcJsonLdCredentialIssuerMetadata.entries }),
  v.transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    ...credentialDefinition,
    types: type,
  })),
  vJwtVcJsonLdCredentialIssuerMetadataDraft11
)

export const vJwtVcJsonLdCredentialRequestFormat = v.object({
  format: vJwtVcJsonLdFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
})

export const vJwtVcJsonLdCredentialRequestDraft11 = v.looseObject({
  format: vJwtVcJsonLdFormatIdentifier,
  credential_definition: v.looseObject({
    '@context': v.array(v.string()),
    // credential_definition was using types instead of type in v11
    types: v.array(v.string()),
    credentialSubject: v.optional(vW3cVcCredentialSubject),
  }),
})

export const vJwtVcJsonLdCredentialRequestDraft11To14 = v.pipe(
  vJwtVcJsonLdCredentialRequestDraft11,
  v.transform(({ credential_definition: { types, ...restCredentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...restCredentialDefinition,
      type: types,
    },
  }))
)

export const vJwtVcJsonLdCredentialRequestDraft14To11 = v.pipe(
  v.looseObject({ ...vJwtVcJsonLdCredentialRequestFormat.entries }),
  v.transform(({ credential_definition: { type, ...restCredentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...restCredentialDefinition,
      types: type,
    },
  })),
  vJwtVcJsonLdCredentialRequestDraft11
)
