import * as v from 'valibot'
import { vW3cVcCredentialSubject, vW3cVcJsonLdCredentialDefinition } from './v-w3c-vc-common'

export const vLdpVcFormatIdentifier = v.literal('ldp_vc')
export type LdpVcFormatIdentifier = v.InferOutput<typeof vLdpVcFormatIdentifier>

export const vLdpVcCredentialIssuerMetadata = v.object({
  format: vLdpVcFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
  order: v.optional(v.array(v.string())),
})

export const vLdpVcCredentialIssuerMetadataDraft11 = v.looseObject({
  order: v.optional(v.array(v.string())),
  format: vLdpVcFormatIdentifier,
  // Credential definition was spread on top level instead of a separatey property in v11
  // As well as using types instead of type
  '@context': v.array(v.string()),
  types: v.array(v.string()),
  credentialSubject: v.optional(vW3cVcCredentialSubject),
})

export const vLdpVcCredentialIssuerMetadataDraft11To14 = v.pipe(
  vLdpVcCredentialIssuerMetadataDraft11,
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

export const vLdpVcCredentialIssuerMetadataDraft14To11 = v.pipe(
  v.looseObject({ ...vLdpVcCredentialIssuerMetadata.entries }),
  v.transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    ...credentialDefinition,
    types: type,
  })),
  vLdpVcCredentialIssuerMetadataDraft11
)

export const vLdpVcCredentialRequestFormat = v.object({
  format: vLdpVcFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
})

const vLdpVcCredentialRequestDraft11 = v.looseObject({
  format: vLdpVcFormatIdentifier,
  credential_definition: v.object({
    '@context': v.array(v.string()),
    // credential_definition was using types instead of type in v11
    types: v.array(v.string()),
    credentialSubject: v.optional(vW3cVcCredentialSubject),
  }),
})

export const vLdpVcCredentialRequestDraft11To14 = v.pipe(
  vLdpVcCredentialRequestDraft11,
  v.transform(({ credential_definition: { types, ...restCredentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...restCredentialDefinition,
      type: types,
    },
  }))
)

export const vLdpVcCredentialRequestDraft14To11 = v.pipe(
  v.looseObject({ ...vLdpVcCredentialRequestFormat.entries }),
  v.transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...credentialDefinition,
      types: type,
    },
  })),
  vLdpVcCredentialRequestDraft11
)
