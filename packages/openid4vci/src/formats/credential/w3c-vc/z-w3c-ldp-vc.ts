import z from 'zod'
import { zIssuerMetadataClaimsDescription } from '../../../metadata/credential-issuer/z-claims-description'
import {
  zW3cVcCredentialSubjectDraft14,
  zW3cVcJsonLdCredentialDefinition,
  zW3cVcJsonLdCredentialDefinitionDraft14,
} from './z-w3c-vc-common'

export const zLdpVcFormatIdentifier = z.literal('ldp_vc')
export type LdpVcFormatIdentifier = z.infer<typeof zLdpVcFormatIdentifier>

export const zLdpVcCredentialIssuerMetadata = z.object({
  format: zLdpVcFormatIdentifier,
  credential_definition: zW3cVcJsonLdCredentialDefinition,
  claims: zIssuerMetadataClaimsDescription.optional(),
})
export const zLdpVcCredentialIssuerMetadataDraft14 = z.object({
  format: zLdpVcFormatIdentifier,
  credential_definition: zW3cVcJsonLdCredentialDefinitionDraft14,
  order: z.array(z.string()).optional(),
})

export const zLdpVcCredentialIssuerMetadataDraft11 = z
  .object({
    order: z.array(z.string()).optional(),
    format: zLdpVcFormatIdentifier,
    // Credential definition was spread on top level instead of a separatey property in v11
    // As well as using types instead of type
    '@context': z.array(z.string()),
    types: z.array(z.string()),
    credentialSubject: zW3cVcCredentialSubjectDraft14.optional(),
  })
  .passthrough()

export const zLdpVcCredentialIssuerMetadataDraft11To14 = zLdpVcCredentialIssuerMetadataDraft11.transform(
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

export const zLdpVcCredentialIssuerMetadataDraft14To11 = zLdpVcCredentialIssuerMetadataDraft14
  .passthrough()
  .transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    ...credentialDefinition,
    types: type,
  }))
  .and(zLdpVcCredentialIssuerMetadataDraft11)

export const zLdpVcCredentialRequestFormatDraft14 = z.object({
  format: zLdpVcFormatIdentifier,
  credential_definition: zW3cVcJsonLdCredentialDefinitionDraft14,
})

const zLdpVcCredentialRequestDraft11 = z
  .object({
    format: zLdpVcFormatIdentifier,
    credential_definition: z.object({
      '@context': z.array(z.string()),
      // credential_definition was using types instead of type in v11
      types: z.array(z.string()),
      credentialSubject: zW3cVcCredentialSubjectDraft14.optional(),
    }),
  })
  .passthrough()

export const zLdpVcCredentialRequestDraft11To14 = zLdpVcCredentialRequestDraft11.transform(
  ({ credential_definition: { types, ...restCredentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...restCredentialDefinition,
      type: types,
    },
  })
)

export const zLdpVcCredentialRequestDraft14To11 = zLdpVcCredentialRequestFormatDraft14
  .passthrough()
  .transform(({ credential_definition: { type, ...restCredentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...restCredentialDefinition,
      types: type,
    },
  }))
  .and(zLdpVcCredentialRequestDraft11)
