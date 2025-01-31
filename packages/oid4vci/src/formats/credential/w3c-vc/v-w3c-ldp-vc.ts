import z from 'zod'
import { vW3cVcCredentialSubject, vW3cVcJsonLdCredentialDefinition } from './v-w3c-vc-common'

export const vLdpVcFormatIdentifier = z.literal('ldp_vc')
export type LdpVcFormatIdentifier = z.infer<typeof vLdpVcFormatIdentifier>

export const vLdpVcCredentialIssuerMetadata = z.object({
  format: vLdpVcFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
  order: z.array(z.string()).optional(),
})

export const vLdpVcCredentialIssuerMetadataDraft11 = z
  .object({
    order: z.array(z.string()).optional(),
    format: vLdpVcFormatIdentifier,
    // Credential definition was spread on top level instead of a separatey property in v11
    // As well as using types instead of type
    '@context': z.array(z.string()),
    types: z.array(z.string()),
    credentialSubject: vW3cVcCredentialSubject.optional(),
  })
  .passthrough()

export const vLdpVcCredentialIssuerMetadataDraft11To14 = vLdpVcCredentialIssuerMetadataDraft11.transform(
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

export const vLdpVcCredentialIssuerMetadataDraft14To11 = vLdpVcCredentialIssuerMetadata
  .passthrough()
  .transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    ...credentialDefinition,
    types: type,
  }))
  .and(vLdpVcCredentialIssuerMetadataDraft11)

export const vLdpVcCredentialRequestFormat = z.object({
  format: vLdpVcFormatIdentifier,
  credential_definition: vW3cVcJsonLdCredentialDefinition,
})

const vLdpVcCredentialRequestDraft11 = z
  .object({
    format: vLdpVcFormatIdentifier,
    credential_definition: z.object({
      '@context': z.array(z.string()),
      // credential_definition was using types instead of type in v11
      types: z.array(z.string()),
      credentialSubject: vW3cVcCredentialSubject.optional(),
    }),
  })
  .passthrough()

export const vLdpVcCredentialRequestDraft11To14 = vLdpVcCredentialRequestDraft11.transform(
  ({ credential_definition: { types, ...restCredentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...restCredentialDefinition,
      type: types,
    },
  })
)

export const vLdpVcCredentialRequestDraft14To11 = vLdpVcCredentialRequestFormat
  .passthrough()
  .transform(({ credential_definition: { type, ...restCredentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...restCredentialDefinition,
      types: type,
    },
  }))
  .and(vLdpVcCredentialRequestDraft11)
