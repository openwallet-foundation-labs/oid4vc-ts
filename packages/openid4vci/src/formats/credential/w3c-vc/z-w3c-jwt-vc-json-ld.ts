import z from 'zod'
import { zIssuerMetadataClaimsDescription } from '../../../metadata/credential-issuer/z-claims-description'
import {
  zCredentialConfigurationSupportedCommon,
  zCredentialConfigurationSupportedCommonCredentialMetadata,
  zCredentialConfigurationSupportedCommonDraft15,
} from '../../../metadata/credential-issuer/z-credential-configuration-supported-common'
import {
  zW3cVcCredentialSubjectDraft14,
  zW3cVcJsonLdCredentialDefinition,
  zW3cVcJsonLdCredentialDefinitionDraft14,
} from './z-w3c-vc-common'

export const zJwtVcJsonLdFormatIdentifier = z.literal('jwt_vc_json-ld')
export type JwtVcJsonLdFormatIdentifier = z.infer<typeof zJwtVcJsonLdFormatIdentifier>

export const zJwtVcJsonLdCredentialIssuerMetadata = zCredentialConfigurationSupportedCommon.extend({
  format: zJwtVcJsonLdFormatIdentifier,
  credential_definition: zW3cVcJsonLdCredentialDefinition,
  credential_metadata: zCredentialConfigurationSupportedCommonCredentialMetadata
    .extend({
      claims: zIssuerMetadataClaimsDescription.optional(),
    })
    .optional(),
})

export const zJwtVcJsonLdCredentialIssuerMetadataDraft15 = zCredentialConfigurationSupportedCommonDraft15.extend({
  format: zJwtVcJsonLdFormatIdentifier,
  credential_definition: zW3cVcJsonLdCredentialDefinition,
  claims: zIssuerMetadataClaimsDescription.optional(),
})

export const zJwtVcJsonLdCredentialIssuerMetadataDraft14 = zCredentialConfigurationSupportedCommonDraft15.extend({
  format: zJwtVcJsonLdFormatIdentifier,
  credential_definition: zW3cVcJsonLdCredentialDefinitionDraft14,
  order: z.optional(z.array(z.string())),
})

export const zJwtVcJsonLdCredentialIssuerMetadataDraft11 = z
  .object({
    order: z.array(z.string()).optional(),
    format: zJwtVcJsonLdFormatIdentifier,
    // Credential definition was spread on top level instead of a separatey property in v11
    // As well as using types instead of type
    '@context': z.array(z.string()),
    types: z.array(z.string()),
    credentialSubject: zW3cVcCredentialSubjectDraft14.optional(),
  })
  .passthrough()

export const zJwtVcJsonLdCredentialIssuerMetadataDraft11To14 = zJwtVcJsonLdCredentialIssuerMetadataDraft11.transform(
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

export const zJwtVcJsonLdCredentialIssuerMetadataDraft14To11 = zJwtVcJsonLdCredentialIssuerMetadataDraft14
  .passthrough()
  .transform(({ credential_definition: { type, ...credentialDefinition }, ...rest }) => ({
    ...rest,
    ...credentialDefinition,
    types: type,
  }))
  .pipe(zJwtVcJsonLdCredentialIssuerMetadataDraft11)

export const zJwtVcJsonLdCredentialRequestFormatDraft14 = z.object({
  format: zJwtVcJsonLdFormatIdentifier,
  credential_definition: zW3cVcJsonLdCredentialDefinition,
})

export const zJwtVcJsonLdCredentialRequestDraft11 = z
  .object({
    format: zJwtVcJsonLdFormatIdentifier,
    credential_definition: z
      .object({
        '@context': z.array(z.string()),
        // credential_definition was using types instead of type in v11
        types: z.array(z.string()),
        credentialSubject: z.optional(zW3cVcCredentialSubjectDraft14),
      })
      .passthrough(),
  })
  .passthrough()

export const zJwtVcJsonLdCredentialRequestDraft11To14 = zJwtVcJsonLdCredentialRequestDraft11.transform(
  ({ credential_definition: { types, ...restCredentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...restCredentialDefinition,
      type: types,
    },
  })
)

export const zJwtVcJsonLdCredentialRequestDraft14To11 = zJwtVcJsonLdCredentialRequestFormatDraft14
  .passthrough()
  .transform(({ credential_definition: { type, ...restCredentialDefinition }, ...rest }) => ({
    ...rest,
    credential_definition: {
      ...restCredentialDefinition,
      types: type,
    },
  }))
  .pipe(zJwtVcJsonLdCredentialRequestDraft11)
